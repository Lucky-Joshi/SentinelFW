"""The monitoring pipeline: log source -> parser -> database -> detector.

This is the only long-running component. It is designed so that stopping it is
always safe:

* the log source is a plain iterator that can be closed from another thread,
* database writes are batched inside a transaction, so a Ctrl-C cannot leave a
  half-written batch,
* the detection cycle runs on a timer in the same loop, so there is exactly one
  thread touching SQLite.

Nothing here modifies the firewall. Monitoring is strictly read-only with
respect to the kernel; blocking an attacker is always an explicit operator
action.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from config import AppConfig
from exceptions import SentinelFWError
from logsetup import get_logger
from monitor.database import Database, FirewallEvent
from monitor.detector import DetectionEngine, DetectionResult
from monitor.log_parser import (
    CommandLogSource,
    DemoLogSource,
    FileLogSource,
    JournalLogSource,
    LogSource,
    NFLogParser,
    StdinLogSource,
    build_source,
)
from utils import now_iso

log = get_logger("monitor.collector")

__all__ = ["LogCollector", "CollectorStats", "build_log_parser"]

def build_log_parser(config: AppConfig) -> NFLogParser:
    """Create a parser configured from ``config.yaml``."""
    return NFLogParser(
        watch_ports=config.detection.watch_ports,
        log_prefix=config.log_prefix,
    )


@dataclass
class CollectorStats:
    """Live counters for the CLI progress line and the dashboard."""

    started_at: str = field(default_factory=now_iso)
    lines_seen: int = 0
    events_ingested: int = 0
    events_pending: int = 0
    batches_written: int = 0
    db_errors: int = 0
    detection_cycles: int = 0
    last_detection: dict[str, Any] | None = None
    last_event_at: str | None = None
    last_error: str | None = None
    running: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "lines_seen": self.lines_seen,
            "events_ingested": self.events_ingested,
            "events_pending": self.events_pending,
            "batches_written": self.batches_written,
            "db_errors": self.db_errors,
            "detection_cycles": self.detection_cycles,
            "last_detection": self.last_detection,
            "last_event_at": self.last_event_at,
            "last_error": self.last_error,
            "running": self.running,
            "uptime_seconds": round(
                time.time() - _epoch_of_iso(self.started_at), 1
            ),
        }


def _epoch_of_iso(value: str) -> float:
    from utils import epoch_of, parse_iso

    parsed = parse_iso(value)
    return epoch_of(parsed) if parsed else time.time()


class LogCollector:
    """Pulls lines from a :class:`LogSource`, stores events, runs detection."""

    def __init__(
        self,
        config: AppConfig,
        db: Database,
        source: LogSource,
        *,
        parser: NFLogParser | None = None,
        batch_size: int | None = None,
        detect_interval: float = 15.0,
        on_alert: Callable[[Any], None] | None = None,
        on_event: Callable[[FirewallEvent], None] | None = None,
        detection: bool = True,
    ) -> None:
        self.config = config
        self.db = db
        self.source = source
        self.parser = parser or build_log_parser(config)
        self.batch_size = int(batch_size or config.monitoring.batch_size or 200)
        self.detect_interval = max(1.0, float(detect_interval))
        self.engine = DetectionEngine(config, db) if detection else None
        self.on_alert = on_alert
        self.on_event = on_event
        self.stats = CollectorStats()
        self._buffer: list[FirewallEvent] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    def start(self) -> threading.Thread:
        """Run the collector in a background thread and return it."""
        if self._thread and self._thread.is_alive():
            raise SentinelFWError("Collector is already running.")
        self.stats = CollectorStats(running=True)
        self._thread = threading.Thread(
            target=self._run, name="sentinelfw-collector", daemon=True
        )
        self._thread.start()
        log.info("Collector started (source: %s)", self.source.describe())
        return self._thread

    def stop(self, timeout: float = 5.0) -> None:
        """Ask the collector to finish and flush its buffer."""
        self._stop.set()
        self.source.stop()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=timeout)
        self.stats.running = False
        log.info("Collector stopped: %s", self.stats.as_dict())

    def run_forever(self, *, max_events: int | None = None,
                    max_seconds: float | None = None) -> CollectorStats:
        """Blocking mode used by ``monitor start`` (runs in the foreground)."""
        self.stats.running = True
        deadline = (time.time() + max_seconds) if max_seconds else None
        try:
            self._loop(max_events=max_events, deadline=deadline)
        finally:
            self.stats.running = False
            self._flush()
            self.source.stop()
        return self.stats

    def run_once(self, max_events: int | None = None) -> DetectionResult | None:
        """Read whatever is currently buffered from the source, then stop.

        Used by ``monitor poll``: one pass, no following.
        """
        self.stats.running = True
        deadline = time.time() + 2.0
        try:
            self._loop(max_events=max_events, deadline=deadline, follow=False,
                       idle_timeout=1.5)
        finally:
            self.stats.running = False
            self._flush()
            self.source.stop()
        if self.engine:
            return self.engine.run()
        return None

    # ------------------------------------------------------------------
    def _run(self) -> None:  # pragma: no cover - exercised via start()
        self.stats.running = True
        try:
            self._loop()
        except Exception as exc:
            self.stats.last_error = str(exc)
            log.error("Collector stopped with an error: %s", exc, exc_info=True)
        finally:
            self.stats.running = False
            self._flush()
            self.source.stop()

    def _loop(self, *, max_events: int | None = None,
              deadline: float | None = None, follow: bool = True,
              idle_timeout: float | None = None) -> None:
        """Read -> buffer -> flush -> detect, until told to stop."""
        ingested = 0
        last_detect = time.time()
        last_line = time.time()
        log.info("Reading from %s", self.source.describe())

        for line in self.source.stream():
            if self._stop.is_set():
                break
            last_line = time.time()
            self.stats.lines_seen += 1

            try:
                event = self.parser.parse_line(line)
            except Exception as exc:  # a malformed line must not stop the feed
                self.stats.last_error = f"parse error: {exc}"
                log.warning("Could not parse a log line: %s", exc)
                continue

            if event is None:
                continue

            self._buffer.append(event)
            self.stats.events_pending = len(self._buffer)
            self.stats.events_ingested += 1
            self.stats.last_event_at = event.timestamp
            ingested += 1

            if self.on_event:
                try:
                    self.on_event(event)
                except Exception:
                    log.debug("on_event callback failed", exc_info=True)

            if len(self._buffer) >= self.batch_size:
                self._flush()

            if max_events is not None and ingested >= max_events:
                break

            if deadline and time.time() >= deadline:
                break

            if self.engine and (time.time() - last_detect) >= self.detect_interval:
                self._flush()
                self._run_detection()
                last_detect = time.time()

            if idle_timeout is not None and (time.time() - last_line) > idle_timeout:
                log.debug("Idle timeout reached; ending this poll cycle")
                break

        self._flush()
        if self.engine and (follow or max_events is None):
            self._run_detection()

    # ------------------------------------------------------------------
    def _flush(self) -> None:
        """Write buffered events to SQLite in one transaction."""
        if not self._buffer:
            return
        batch, self._buffer = self._buffer, []
        self.stats.events_pending = 0
        try:
            self.db.insert_events(batch)
        except SentinelFWError as exc:
            self.stats.db_errors += 1
            self.stats.last_error = str(exc)
            log.error("Dropped %d event(s): %s", len(batch), exc)
            return
        self.stats.batches_written += 1
        log.debug("Stored %d event(s)", len(batch))

    def _run_detection(self) -> DetectionResult | None:
        if not self.engine:
            return None
        result = self.engine.run()
        self.stats.detection_cycles += 1
        self.stats.last_detection = result.as_dict()
        if result.new_alerts and self.on_alert:
            for alert in result.new_alerts:
                try:
                    self.on_alert(alert)
                except Exception:
                    log.debug("on_alert callback failed", exc_info=True)
        return result

    # ------------------------------------------------------------------
    def ingest_file(self, path: str, *, limit: int | None = None) -> int:
        """One-shot import of a log file (no following, then one detection run)."""
        events: list[FirewallEvent] = []
        for event in self.parser.parse_file(path, limit=limit):
            events.append(event)
            if len(events) >= self.batch_size:
                self.db.insert_events(events)
                events = []
        if events:
            self.db.insert_events(events)
        self.stats.events_ingested += self.parser.stats.events_parsed
        self.stats.last_event_at = now_iso()
        if self.engine:
            self._run_detection()
        return self.parser.stats.events_parsed

    def ingest_demo(self, *, seconds: float = 20.0, max_events: int | None = None,
                    speed: float = 1.0) -> int:
        """Run the synthetic source for a bounded time, then stop."""
        demo = DemoLogSource(log_prefix=self.config.log_prefix, speed=speed)
        self.source = demo
        self.run_forever(max_events=max_events, max_seconds=seconds)
        return self.stats.events_ingested


def make_collector(
    config: AppConfig,
    db: Database,
    *,
    source_kind: str | None = None,
    command: Sequence[str] | None = None,
    follow: bool | None = None,
    detection: bool = True,
    on_alert: Callable[[Any], None] | None = None,
    on_event: Callable[[FirewallEvent], None] | None = None,
) -> LogCollector:
    """Convenience constructor wiring config -> source -> collector."""
    kind = source_kind or config.monitoring.source
    source = build_source(kind, config, log_prefix=config.log_prefix, command=command)
    if isinstance(source, FileLogSource) and follow is not None:
        source.follow = follow
    return LogCollector(
        config, db, source,
        on_alert=on_alert,
        on_event=on_event,
        detection=detection,
    )