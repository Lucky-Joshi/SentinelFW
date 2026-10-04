"""Small, dependency-light helpers shared by every SentinelFW module.

This module is intentionally boring: atomic file writes, timestamp helpers,
and a single audited ``run_command`` wrapper. Keeping the subprocess wrapper
in one place means there is exactly one code path that executes an external
program, which makes dry-run and audit logging reliable.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from exceptions import SentinelFWError

__all__ = [
    "CommandResult",
    "run_command",
    "atomic_write_text",
    "atomic_write_bytes",
    "ensure_dir",
    "secure_path",
    "human_int",
    "human_duration",
    "now_iso",
    "now_utc",
    "to_iso",
    "parse_iso",
    "epoch_of",
    "iso_from_epoch",
    "period_start",
    "mask_ip",
    "truncate",
    "table_to_list",
]


# ---------------------------------------------------------------------------
# External command execution
# ---------------------------------------------------------------------------
@dataclass
class CommandResult:
    """Outcome of an external command.

    Attributes
    ----------
    args:
        The argv list that was (or would have been) executed.
    returncode:
        Exit status. ``0`` for a successful dry run.
    stdout / stderr:
        Captured text. Empty in dry-run mode.
    dry_run:
        ``True`` when the command was *not* actually executed.
    timed_out:
        ``True`` when the command exceeded its timeout and was killed.
    """

    args: list[str]
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    dry_run: bool = False
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def command_line(self) -> str:
        """The command as a copy-pasteable shell string."""
        return " ".join(shlex.quote(a) for a in self.args)

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        state = "would run" if self.dry_run else f"rc={self.returncode}"
        return f"{self.command_line}  ({state})"


def run_command(
    args: Sequence[str],
    *,
    dry_run: bool = False,
    timeout: float | None = 30.0,
    input_text: str | None = None,
    env: Mapping[str, str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
    logger: Any | None = None,
    log_prefix: str = "exec",
) -> CommandResult:
    """Execute an external command with audit logging and dry-run support.

    The function never raises on a non-zero exit status; inspect
    :attr:`CommandResult.ok` instead. It only raises :class:`OSError` if the
    binary cannot be spawned at all, which callers translate into a
    domain-specific dependency error.

    Parameters
    ----------
    args:
        argv list. Never a shell string, so no shell metacharacters can be
        injected by user input.
    dry_run:
        Log the command and return a successful "would run" result without
        touching the system.
    timeout:
        Seconds before the child is killed (``None`` disables).
    input_text:
        Data piped to the child's stdin. Used to feed whole ruleset scripts to
        ``nft -f -`` in a single atomic transaction.
    logger:
        Optional logger receiving the audit line.
    log_prefix:
        Short label included in the log line, e.g. ``"nft"`` or ``"journalctl"``.
    """
    argv = [str(a) for a in args]
    log = logger
    line = " ".join(shlex.quote(a) for a in argv)

    if log is not None:
        if dry_run:
            log.info("[DRY-RUN %s] would execute: %s", log_prefix, line)
        else:
            log.info("[%s] executing: %s", log_prefix, line)
            if input_text:
                log.debug("[%s] stdin:\n%s", log_prefix, input_text.rstrip())

    if dry_run:
        return CommandResult(args=argv, returncode=0, dry_run=True)

    merged_env = None
    if env is not None:
        merged_env = {**os.environ, **dict(env)}

    try:
        completed = subprocess.run(  # noqa: S603 - argv list, never shell=True
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            env=merged_env,
            cwd=str(cwd) if cwd else None,
            check=False,
        )
    except FileNotFoundError as exc:
        if log is not None:
            log.error("[%s] binary not found: %s", log_prefix, argv[0])
        raise SentinelFWError(
            f"Command not found: {argv[0]}",
            hint="Install it, e.g. 'sudo apt install nftables'.",
        ) from exc
    except subprocess.TimeoutExpired:
        if log is not None:
            log.error("[%s] timed out after %ss: %s", log_prefix, timeout, line)
        return CommandResult(args=argv, returncode=124, timed_out=True,
                             stderr=f"timed out after {timeout}s")

    result = CommandResult(
        args=argv,
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )
    if log is not None:
        if result.ok:
            log.debug("[%s] ok (rc=0)", log_prefix)
        else:
            log.error("[%s] failed rc=%s: %s", log_prefix, result.returncode,
                      result.stderr.strip() or "<no stderr>")
    return result


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------
def ensure_dir(path: str | os.PathLike[str], mode: int = 0o750) -> Path:
    """Create ``path`` (and parents) if needed and return it."""
    p = Path(path).expanduser()
    p.mkdir(parents=True, exist_ok=True)
    try:
        p.chmod(mode)
    except OSError:
        pass
    return p


def secure_path(path: str | os.PathLike[str], mode: int = 0o600) -> Path:
    """Create the parent directory of ``path`` and chmod the file to ``mode``."""
    p = Path(path).expanduser()
    ensure_dir(p.parent)
    if p.exists():
        try:
            p.chmod(mode)
        except OSError:
            pass
    return p


def atomic_write_text(
    path: str | os.PathLike[str],
    content: str,
    *,
    mode: int = 0o600,
    encoding: str = "utf-8",
) -> Path:
    """Write ``content`` to ``path`` atomically with restrictive permissions.

    The write goes to a temporary file in the *same* directory, is flushed and
    ``fsync``-ed, then renamed over the target. ``os.replace`` is atomic on the
    same filesystem, so a crash or Ctrl-C can never leave a half-written
    config or rules file behind.
    """
    target = Path(path).expanduser()
    ensure_dir(target.parent)

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent)
    )
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding=encoding) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, target)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    # Make sure the mode is correct even if the target pre-existed.
    try:
        target.chmod(mode)
    except OSError:
        pass
    return target


def atomic_write_bytes(path: str | os.PathLike[str], data: bytes, *, mode: int = 0o600) -> Path:
    """Binary counterpart of :func:`atomic_write_text`."""
    target = Path(path).expanduser()
    ensure_dir(target.parent)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent)
    )
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, target)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    try:
        target.chmod(mode)
    except OSError:
        pass
    return target


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def human_int(value: int | None) -> str:
    """``1234`` -> ``1.2K`` for compact dashboard tiles."""
    if value is None:
        return "-"
    value = int(value)
    if abs(value) < 1000:
        return str(value)
    if abs(value) < 1_000_000:
        return f"{value / 1000:.1f}K"
    return f"{value / 1_000_000:.1f}M"


def human_duration(seconds: float | int | None) -> str:
    """Render a duration compactly, e.g. ``2d 4h`` or ``37s``."""
    if seconds is None:
        return "-"
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes and not days:
        parts.append(f"{minutes}m")
    if not parts:
        parts.append(f"{secs}s")
    return " ".join(parts)


def truncate(text: str, width: int, ellipsis: str = "…") -> str:
    """Truncate ``text`` to ``width`` characters, appending an ellipsis."""
    text = text or ""
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= len(ellipsis):
        return text[:width]
    return text[: width - len(ellipsis)] + ellipsis


def mask_ip(ip: str, keep_octets: int = 2) -> str:
    """Partially mask an address for privacy, e.g. ``103.21.xx.xx``.

    Private addresses are returned unchanged - they contain no information
    worth hiding and masking them makes troubleshooting harder.
    """
    if not ip or ":" in ip:
        return ip or "-"
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    if parts[0] in {"10", "127"} or (parts[0] == "192" and parts[1] == "168"):
        return ip
    keep = max(1, min(3, keep_octets))
    return ".".join(parts[:keep] + ["xx"] * (4 - keep))


def table_to_list(rows: Sequence[Mapping[str, Any]], limit: int | None = None) -> str:
    """Render rows as a minimal aligned text table (fallback renderer)."""
    if not rows:
        return "(no records)"
    keys = list(rows[0].keys())
    data = [tuple("" if r.get(k) is None else str(r.get(k)) for k in keys)
            for r in (rows[:limit] if limit else rows)]
    widths = [
        max(len(str(k)), *(len(row[i]) for row in data)) if data else len(str(k))
        for i, k in enumerate(keys)
    ]
    header = "  ".join(str(k).ljust(widths[i]) for i, k in enumerate(keys))
    sep = "  ".join("-" * w for w in widths)
    body = [
        "  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row))
        for row in data
    ]
    return "\n".join([header, sep, *body])


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------
def now_utc() -> datetime:
    """Timezone-aware "now" in UTC."""
    return datetime.now(timezone.utc)


def now_iso() -> str:
    """Current UTC time as an ISO-8601 string with a ``Z`` suffix."""
    return to_iso(now_utc())


def to_iso(moment: datetime) -> str:
    """Serialise a datetime to a sortable ISO-8601 UTC string."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_iso(value: str) -> datetime | None:
    """Parse an ISO-8601 string into an aware datetime, or ``None``.

    The kernel and journald emit several slightly different ISO shapes
    (``2026-10-03T10:30:22+0000``, ``...Z``, with or without microseconds), so
    this is deliberately forgiving.
    """
    if not value:
        return None
    raw = value.strip().replace("Z", "+00:00")
    # ``+0000`` (no colon) -> ``+00:00``
    if len(raw) > 5 and (raw[-5] in "+-") and ":" not in raw[-5:]:
        raw = f"{raw[:-2]}:{raw[-2:]}"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                parsed = datetime.strptime(value.strip(), fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def epoch_of(moment: datetime) -> float:
    """POSIX timestamp, used as the fast numeric column in SQLite."""
    return moment.timestamp()


def iso_from_epoch(epoch: float) -> str:
    """Inverse of :func:`epoch_of`."""
    return to_iso(datetime.fromtimestamp(float(epoch), tz=timezone.utc))


def period_start(period: str, *, now: datetime | None = None) -> tuple[datetime, str]:
    """Translate a human period such as ``24h``/``7d``/``today`` into a range.

    Returns ``(start_datetime, canonical_label)``.
    """
    now = now or now_utc()
    key = (period or "24h").strip().lower()
    mapping = {
        "15m": timedelta(minutes=15),
        "1h": timedelta(hours=1),
        "6h": timedelta(hours=6),
        "12h": timedelta(hours=12),
        "24h": timedelta(hours=24),
        "1d": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    if key in ("today", "day"):
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return start, "today"
    if key in ("week",):
        return now - timedelta(days=7), "7d"
    if key in mapping:
        return now - mapping[key], key
    # Accept a raw "<n><unit>" form such as 45m, 3h, 2d.
    if len(key) >= 2 and key[:-1].isdigit() and key[-1] in {"m", "h", "d"}:
        amount = int(key[:-1])
        unit = {"m": timedelta(minutes=amount),
                "h": timedelta(hours=amount),
                "d": timedelta(days=amount)}[key[-1]]
        return now - amount * unit, key
    raise SentinelFWError(
        f"Unknown time period: {period!r}",
        hint="Use one of: 15m, 1h, 6h, 12h, 24h, 7d, 30d, today.",
    )