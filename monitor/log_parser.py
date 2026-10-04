"""Parse nftables kernel log lines into structured events.

What the kernel actually emits
------------------------------
SentinelFW rules log with a fixed prefix, e.g. an nft rule containing::

    log prefix "SENTINELFW-DROP " level info

produces a kernel message that looks like one of these, depending on how the
host is configured:

.. code-block:: text

    # journald, short-iso
    2026-10-03T10:30:22+0000 kali kernel: SENTINELFW-DROP SRC=45.33.22.1 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=22 LEN=40

    # classic syslog (/var/log/kern.log)
    Oct  3 10:30:22 kali kernel: [482913.114] SENTINELFW-DROP SRC=45.33.22.1 DPT=22

    # dmesg
    [ 482913.114] SENTINELFW-DROP SRC=45.33.22.1 DPT=22

This module normalises all of them, plus bare ``SRC=``/``DPT=`` lines from
rules the operator wrote themselves.

The parser is deliberately strict: a line it cannot confidently interpret
returns ``None`` and is counted as skipped rather than being guessed at.
Bad data in an audit log is worse than missing data.
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Sequence

from exceptions import LogSourceError, RootRequiredError
from logsetup import get_logger
from monitor.database import FirewallEvent, Severity
from monitor.explain import classify_event
from utils import epoch_of, now_utc, parse_iso

log = get_logger("monitor.parser")

__all__ = [
    "NFLogParser",
    "LogSource",
    "JournalLogSource",
    "FileLogSource",
    "DemoLogSource",
    "StdinLogSource",
    "CommandLogSource",
    "build_source",
    "ParseStats",
]


# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------
#: Our marker plus optional verdict, e.g. "SENTINELFW-DROP", "SENTINELFW-SYN".
PREFIX_RE = re.compile(r"\bSENTINELFW(?:-([A-Za-z]+))?\b")

#: nftables' own connection-tuple keywords.
KV_RE = re.compile(
    r"\b(?P<key>[A-Z][A-Z0-9]{1,20})=(?P<value>\"[^\"]*\"|\S+)"
)

#: Trailing verdict word when there is no SENTINELFW prefix, e.g. "... DROP".
VERDICT_RE = re.compile(r"\b(DROP|ACCEPT|REJECT|LOG)\b")

#: journald --output=short-iso prefix.
ISO_TS_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2}|Z))\s+"
    r"(?P<host>\S+)\s+(?P<unit>[^:\s]+)(?:\[\d+\])?:\s(?P<msg>.*)$"
)

#: classic syslog prefix: "Oct  3 10:30:22 host unit: [123.456] msg"
SYSLOG_TS_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<unit>[a-zA-Z0-9_.-]+)(?:\[\d+\])?:\s(?P<msg>.*)$"
)

#: dmesg style: "[ 1234.567890] msg"
DMESG_RE = re.compile(r"^\[\s*(?P<uptime>[\d.]+)\]\s(?P<msg>.*)$")

#: ISO-8601 anywhere near the start (journald variants).
ISO_ANYWHERE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2}|Z))"
)

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

#: TCP flags as emitted by nftables, mapped to letters for readability.
_FLAG_MAP = {
    "fin": "F", "syn": "S", "rst": "R", "psh": "P", "ack": "A",
    "urg": "U", "ecn": "E", "cwr": "C",
}


@dataclass
class ParseStats:
    """Counters shown by ``monitor status`` after a run."""

    lines_seen: int = 0
    lines_matched: int = 0
    lines_skipped: int = 0
    events_parsed: int = 0
    started_at: str = field(default_factory=lambda: now_utc().isoformat())
    last_event_at: str | None = None

    def as_dict(self) -> dict[str, Any]:
        match_rate = (
            self.lines_matched / self.lines_seen * 100 if self.lines_seen else 0.0
        )
        return {
            "lines_seen": self.lines_seen,
            "lines_matched": self.lines_matched,
            "lines_skipped": self.lines_skipped,
            "events_parsed": self.events_parsed,
            "match_rate_pct": round(match_rate, 1),
            "started_at": self.started_at,
            "last_event_at": self.last_event_at,
        }


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
class NFLogParser:
    """Turn raw kernel log lines into :class:`FirewallEvent` objects."""

    def __init__(self, *, watch_ports: Sequence[int] = (), log_prefix: str = "SENTINELFW",
                 assign_severity: bool = True) -> None:
        self.watch_ports = tuple(int(p) for p in watch_ports)
        self.log_prefix = log_prefix
        self.assign_severity = assign_severity
        self.stats = ParseStats()
        # Compile the prefix search with the configured marker, escaping it in
        # case an operator picks something regex-significant.
        self._prefix_re = re.compile(
            rf"\b{re.escape(log_prefix)}(?:-([A-Za-z]+))?\b"
        )

    # -- public API --------------------------------------------------------
    def parse_line(self, line: str, *, now: datetime | None = None) -> FirewallEvent | None:
        """Parse one log line, or return ``None`` if it is not ours."""
        self.stats.lines_seen += 1
        if not line or not line.strip():
            self.stats.lines_skipped += 1
            return None

        message, timestamp = self._split_timestamp(line)
        prefix_match = self._prefix_re.search(message)

        fields = {m.group("key"): m.group("value").strip('"')
                  for m in KV_RE.finditer(message)}

        if prefix_match is None and not fields:
            self.stats.lines_skipped += 1
            return None

        if prefix_match is not None:
            self.stats.lines_matched += 1
        else:
            # A bare SRC=/DPT= line from someone else's rule is still useful.
            self.stats.lines_matched += 1
            log.debug("Parsing non-SentinelFW nftables line: %.100s", message)

        event = self._build_event(
            message=message,
            fields=fields,
            action=self._action_from(message, prefix_match, fields),
            timestamp=timestamp,
            now=now,
        )
        self.stats.events_parsed += 1
        self.stats.last_event_at = event.timestamp
        return event

    def parse_lines(self, lines: Iterable[str], *, now: datetime | None = None
                    ) -> Iterator[FirewallEvent]:
        """Parse an iterable of lines, yielding the events found."""
        for line in lines:
            event = self.parse_line(line, now=now)
            if event is not None:
                yield event

    def parse_file(self, path: str | Path, *, now: datetime | None = None,
                   limit: int | None = None) -> Iterator[FirewallEvent]:
        """Parse a log file from the beginning (used by ``monitor ingest``)."""
        target = Path(path).expanduser()
        if not target.is_file():
            raise LogSourceError(
                f"Log file not found: {target}",
                hint="Check monitoring.log_files in config.yaml.",
            )
        try:
            handle = target.open("r", encoding="utf-8", errors="replace")
        except OSError as exc:
            raise LogSourceError(f"Cannot read {target}: {exc}") from exc
        count = 0
        with handle:
            for line in handle:
                if limit is not None and count >= limit:
                    return
                event = self.parse_line(line.rstrip("\n"), now=now)
                if event is not None:
                    count += 1
                    yield event

    # -- internals ---------------------------------------------------------
    def _split_timestamp(self, line: str) -> tuple[str, datetime | None]:
        """Peel a timestamp off the front of a line, returning (message, time).

        Failing to find one is normal (``dmesg`` only has an uptime counter), so
        the caller substitutes "now" rather than dropping the event.
        """
        match = ISO_TS_RE.match(line)
        if match:
            parsed = parse_iso(match.group("ts"))
            if parsed:
                return match.group("msg"), parsed

        match = SYSLOG_TS_RE.match(line)
        if match:
            return match.group("msg"), self._syslog_time(match)

        match = DMESG_RE.match(line)
        if match:
            return match.group("msg"), None

        match = ISO_ANYWHERE_RE.search(line[:64])
        if match:
            parsed = parse_iso(match.group(1))
            if parsed:
                return line, parsed

        return line, None

    def _syslog_time(self, match: re.Match[str]) -> datetime | None:
        """Classic syslog has no year, so infer it.

        Rule: if the month/day is in the future relative to now, the line must
        be from last year (logs at 00:30 on 1 January otherwise look like they
        are from the future).
        """
        month = _MONTHS.get(match.group("mon").lower())
        if not month:
            return None
        day = int(match.group("day"))
        try:
            hms = time.strptime(match.group("hms"), "%H:%M:%S")
        except ValueError:
            return None
        now = now_utc()
        year = now.year
        try:
            candidate = datetime(year, month, day, hms.tm_hour, hms.tm_min,
                                 hms.tm_sec, tzinfo=timezone.utc)
        except ValueError:
            return None
        if (candidate - now).days > 1:
            candidate = candidate.replace(year=year - 1)
        return candidate

    def _action_from(self, message: str, prefix_match: re.Match[str] | None,
                     fields: dict[str, str]) -> str:
        """Decide DROP / ACCEPT / REJECT / LOG for a line."""
        if prefix_match and prefix_match.group(1):
            token = prefix_match.group(1).upper()
            if token in {"DROP", "ACCEPT", "REJECT", "LOG", "SYN"}:
                # "SYN" is a visibility marker, not a verdict.
                return "LOG" if token == "SYN" else token
        verdict = VERDICT_RE.search(message)
        if verdict:
            return verdict.group(1)
        # No verdict anywhere: the packet was only logged.
        return "LOG"

    def _build_event(self, *, message: str, fields: dict[str, str], action: str,
                     timestamp: datetime | None, now: datetime | None) -> FirewallEvent:
        def pick(*names: str) -> str | None:
            for name in names:
                if fields.get(name):
                    return fields[name]
            return None

        def as_int(value: str | None) -> int | None:
            if value is None:
                return None
            try:
                return int(value)
            except (TypeError, ValueError):
                return None

        protocol = (pick("PROTO", "PROTOCOL") or "").lower() or None
        dest_port = as_int(pick("DPT", "DST_PORT"))
        source_port = as_int(pick("SPT", "SRC_PORT"))

        # A bare port with no protocol keyword is almost always TCP in nft output.
        if protocol is None and (dest_port or source_port):
            protocol = "tcp"

        event = FirewallEvent(
            source_ip=pick("SRC", "SADDR", "SOURCE_IP"),
            dest_ip=pick("DST", "DADDR", "DEST_IP"),
            protocol=protocol,
            source_port=source_port,
            dest_port=dest_port,
            action=action,
            prefix=self.log_prefix,
            timestamp=(timestamp or now or now_utc()).isoformat(),
            epoch=epoch_of(timestamp or now or now_utc()),
            packet_length=as_int(pick("LEN", "LENGTH")),
            tcp_flags=self._flags(fields),
            description=message.strip()[:500],
            raw=message.strip(),
        )
        if self.assign_severity:
            severity, description = classify_event(event, watch_ports=self.watch_ports)
            event.severity = severity
            event.description = description
        return event

    @staticmethod
    def _flags(fields: dict[str, str]) -> str | None:
        """Render nftables' ``tcp flags syn,ack`` as ``SA``."""
        raw = fields.get("TCP_FLAGS") or fields.get("FLAGS")
        if not raw:
            return None
        letters = [_FLAG_MAP.get(flag.strip().lower(), "?")
                   for flag in raw.split(",") if flag.strip()]
        return "".join(letters) or None


# ---------------------------------------------------------------------------
# Log sources
# ---------------------------------------------------------------------------
class LogSource(ABC):
    """A stream of raw log lines.

    Implementations must be safe to :meth:`close` from another thread.
    """

    name = "source"

    def __init__(self) -> None:
        self._stop = threading.Event()

    @abstractmethod
    def stream(self) -> Iterator[str]:
        """Yield raw lines until :meth:`close` is called."""

    @abstractmethod
    def describe(self) -> str:
        """One-line human description for the UI and logs."""

    def stop(self) -> None:
        self._stop.set()

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def __iter__(self) -> Iterator[str]:
        return self.stream()


class JournalLogSource(LogSource):
    """Read the kernel ring buffer via ``journalctl -kf`` (systemd hosts).

    Requires membership in ``systemd-journal`` or root. That is the recommended
    source on Kali because journald keeps a structured, rotating record.
    """

    name = "journal"

    def __init__(self, *, identifier: str = "kernel", since_minutes: int = 5,
                 binary: str = "journalctl") -> None:
        super().__init__()
        self.identifier = identifier
        self.since_minutes = since_minutes
        self.binary = binary
        self._process: subprocess.Popen[str] | None = None

    def _argv(self) -> list[str]:
        return [
            self.binary,
            "--follow",
            "--no-pager",
            "--output", "short-iso",
            f"--identifier={self.identifier}",
            f"--since={self.since_minutes} minutes ago",
        ]

    def stream(self) -> Iterator[str]:
        import shutil

        if shutil.which(self.binary) is None:
            raise LogSourceError(
                f"'{self.binary}' is not available.",
                hint="Use monitoring.source: file, or read the kernel buffer with dmesg.",
            )
        if os.geteuid() != 0:
            # journalctl may still work for a user in systemd-journal; try it
            # and report the real failure instead of refusing up front.
            log.info("Not root: attempting journalctl as uid %d", os.geteuid())

        try:
            self._process = subprocess.Popen(  # noqa: S603 - fixed argv
                self._argv(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env={**os.environ, "SYSTEMD_COLORS": "0"},
            )
        except OSError as exc:
            raise LogSourceError(f"Cannot start {self.binary}: {exc}") from exc

        log.info("Reading kernel journal (since -%d minutes)", self.since_minutes)
        assert self._process.stdout is not None
        try:
            for line in self._process.stdout:
                if self._stop.is_set():
                    break
                yield line.rstrip("\n")
        finally:
            self.close()

    def close(self) -> None:
        self._stop.set()
        process = self._process
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:  # pragma: no cover - rare
                process.kill()

    def describe(self) -> str:
        return f"journalctl -kf --identifier={self.identifier}"


class FileLogSource(LogSource):
    """Tail a log file, surviving truncation and rotation.

    Rotation matters on a long-running monitor: after ``logrotate`` renames the
    file, blindly continuing to read would leave the monitor staring at a dead
    inode forever.
    """

    name = "file"

    def __init__(self, path: str | Path, *, poll_interval: float = 1.0,
                 follow: bool = True, from_start: bool = False) -> None:
        super().__init__()
        self.path = Path(path).expanduser()
        self.poll_interval = max(0.1, float(poll_interval))
        self.follow = follow
        self.from_start = from_start

    def stream(self) -> Iterator[str]:
        if not self.path.is_file():
            if self.follow:
                log.info("Waiting for log file %s to appear", self.path)
                while not self._stop.is_set():
                    if self.path.is_file():
                        break
                    time.sleep(self.poll_interval)
                if self._stop.is_set():
                    return
            else:
                raise LogSourceError(
                    f"Log file not found: {self.path}",
                    hint="Set monitoring.source to journal, or fix monitoring.log_files.",
                )

        handle = self.path.open("r", encoding="utf-8", errors="replace")
        try:
            if not self.from_start:
                handle.seek(0, os.SEEK_END)
            inode = self._inode()
            while not self._stop.is_set():
                line = handle.readline()
                if line:
                    yield line.rstrip("\n")
                    continue
                if not self.follow:
                    break
                time.sleep(self.poll_interval)
                current = self._inode()
                if inode is not None and current is not None and current != inode:
                    log.info("Log file %s was rotated; reopening", self.path)
                    handle.close()
                    handle = self.path.open("r", encoding="utf-8", errors="replace")
                    inode = current
                    continue
                try:
                    size = self.path.stat().st_size
                except OSError:
                    continue
                if handle.tell() > size:
                    log.info("Log file %s truncated; reopening", self.path)
                    handle.close()
                    handle = self.path.open("r", encoding="utf-8", errors="replace")
                    inode = self._inode()
        finally:
            handle.close()

    def _inode(self) -> int | None:
        try:
            return self.path.stat().st_ino
        except OSError:
            return None

    def close(self) -> None:
        self._stop.set()

    def describe(self) -> str:
        mode = "following" if self.follow else "reading"
        return f"{mode} {self.path}"


class StdinLogSource(LogSource):
    """Read piped input, e.g. ``nft monitor trace | sentinelfw monitor start -``."""

    name = "stdin"

    def stream(self) -> Iterator[str]:
        import sys

        for line in sys.stdin:
            if self._stop.is_set():
                break
            yield line.rstrip("\n")

    def describe(self) -> str:
        return "reading from standard input"


class CommandLogSource(LogSource):
    """Run a command and treat its stdout as a log stream (advanced use)."""

    name = "command"

    def __init__(self, argv: Sequence[str], *, poll_interval: float = 1.0) -> None:
        super().__init__()
        self.argv = [str(a) for a in argv]
        self.poll_interval = poll_interval
        self._process: subprocess.Popen[str] | None = None

    def stream(self) -> Iterator[str]:
        try:
            self._process = subprocess.Popen(  # noqa: S603 - operator supplied argv
                self.argv, stdout=subprocess.PIPE, stderr=None, text=True, bufsize=1
            )
        except OSError as exc:
            raise LogSourceError(f"Cannot run {' '.join(self.argv)}: {exc}") from exc
        assert self._process.stdout is not None
        try:
            for line in self._process.stdout:
                if self._stop.is_set():
                    break
                yield line.rstrip("\n")
        finally:
            self.close()

    def close(self) -> None:
        self._stop.set()
        process = self._process
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:  # pragma: no cover
                process.kill()

    def describe(self) -> str:
        return "running: " + " ".join(self.argv)


class DemoLogSource(LogSource):
    """Generate realistic synthetic kernel log lines.

    This exists for two honest reasons: it lets a student learn the tool on a
    laptop without root or a real attacker, and it makes the test suite and the
    dashboard demonstrable offline. It is clearly labelled ``demo`` everywhere
    it appears so nobody mistakes it for real evidence.
    """

    name = "demo"

    SCENARIOS: tuple[dict[str, Any], ...] = (
        {
            "name": "port scan",
            "ip": "45.33.22.1",
            "ports": (22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432,
                      5900, 6379, 8080, 8443, 9200, 27017, 21, 69, 139, 135, 111),
            "protocol": "tcp",
            "action": "DROP",
            "rate": 0.04,
        },
        {
            "name": "ssh brute force",
            "ip": "103.21.244.7",
            "ports": (22,),
            "protocol": "tcp",
            "action": "DROP",
            "rate": 0.012,
        },
        {
            "name": "background noise",
            "ip": None,
            "ports": (80, 443, 53, 22),
            "protocol": "tcp",
            "action": "DROP",
            "rate": 1.4,
        },
    )

    def __init__(self, *, log_prefix: str = "SENTINELFW", speed: float = 1.0,
                 seed: int | None = 7, dest_ip: str = "10.0.0.5") -> None:
        super().__init__()
        self.log_prefix = log_prefix
        self.speed = max(0.05, float(speed))
        self.dest_ip = dest_ip
        self._random = __import__("random").Random(seed)
        self._scenario_index = 0
        self._remaining = 0
        self._current = self.SCENARIOS[0]

    def stream(self) -> Iterator[str]:
        counter = 0
        while not self._stop.is_set():
            scenario = self._pick_scenario()
            counter += 1
            counter = counter % 65536
            source_port = self._random.randint(1024, 65535)
            port = self._random.choice(scenario["ports"])
            action = scenario["action"]
            protocol = scenario["protocol"]
            source = scenario["ip"] or self._random.choice(
                ["185.220.101.4", "91.243.44.12", "66.240.192.10", "198.51.100.7"]
            )
            stamp = now_utc().strftime("%Y-%m-%dT%H:%M:%S+0000")
            line = (
                f"{stamp} kali kernel: {self.log_prefix}-{action} "
                f"SRC={source} DST={self.dest_ip} PROTO={protocol.upper()} "
                f"SPT={source_port} DPT={port} LEN={self._random.choice((40, 60, 74, 102))}"
            )
            yield line
            time.sleep(scenario["rate"] / self.speed)

    def _pick_scenario(self) -> dict[str, Any]:
        """Round-robin through scenarios so every detector gets exercised."""
        if self._remaining <= 0:
            self._current = self.SCENARIOS[self._scenario_index % len(self.SCENARIOS)]
            self._scenario_index += 1
            # Longer runs for the noisy scenarios, single bursts for attacks.
            self._remaining = (
                self._random.randint(30, 60)
                if self._current["name"] == "background noise"
                else self._random.randint(25, 40)
            )
        self._remaining -= 1
        return self._current

    def close(self) -> None:
        self._stop.set()

    def describe(self) -> str:
        return ("synthetic demo traffic (no root, no real attacker) - "
                "not real evidence")


def build_source(kind: str, config: Any, *, log_prefix: str | None = None,
                 command: Sequence[str] | None = None) -> LogSource:
    """Factory mapping ``monitoring.source`` to a concrete log source."""
    monitoring = config.monitoring
    prefix = log_prefix or config.log_prefix

    if kind == "demo":
        return DemoLogSource(log_prefix=prefix)
    if kind == "journal":
        return JournalLogSource(
            identifier=monitoring.journal_identifier,
            since_minutes=monitoring.read_since_minutes,
        )
    if kind == "file":
        candidates = [Path(p) for p in monitoring.log_files]
        existing = next((p for p in candidates if p.is_file()), None)
        if existing is None:
            raise LogSourceError(
                "None of the configured log files exist: "
                + ", ".join(str(p) for p in candidates),
                hint="On a journald system use monitoring.source: journal instead.",
            )
        return FileLogSource(existing, poll_interval=monitoring.poll_interval,
                             follow=monitoring.follow)
    if kind == "stdin":
        return StdinLogSource()
    if kind == "command":
        if not command:
            raise LogSourceError("No command given for the 'command' log source.")
        return CommandLogSource(command)
    raise LogSourceError(
        f"Unknown log source {kind!r}.",
        hint="Valid sources: journal, file, demo, stdin, command.",
    )