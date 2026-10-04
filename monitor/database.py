"""SQLite storage for firewall events and alerts.

Design notes
------------
* **WAL journal.** Readers (dashboard, reports) never block the writer
  (the monitor). Essential when the dashboard is open while events stream in.
* **Two clocks.** ``timestamp`` is ISO-8601 text for humans; ``epoch`` is a
  REAL for fast, correct range queries and window functions. Storing both
  avoids string-comparing timestamps and makes "last 15 minutes" a plain
  numeric ``WHERE epoch > ?``.
* **Batched inserts.** A busy port scan can emit thousands of events a second.
  :meth:`Database.insert_events` wraps a batch in one transaction.
* **Alert de-duplication.** Each alert carries a ``fingerprint``; the UNIQUE
  index means the same finding is not stored twice, which keeps the alert
  table meaningful instead of a wall of duplicates.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Sequence

from exceptions import DatabaseError
from logsetup import get_logger
from utils import ensure_dir, epoch_of, iso_from_epoch, now_iso, now_utc, parse_iso
from version import SCHEMA_VERSION

log = get_logger("monitor.db")

__all__ = ["Database", "FirewallEvent", "Alert", "Severity", "SEVERITY_ORDER"]

#: Ordered from least to most serious (used for sorting and threshold logic).
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


class Severity:
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    ALL = SEVERITY_ORDER


def severity_rank(value: str | None) -> int:
    """Numeric rank for a severity label (unknown -> 0)."""
    try:
        return SEVERITY_ORDER.index((value or "").lower())
    except ValueError:
        return 0


# ---------------------------------------------------------------------------
# Row models
# ---------------------------------------------------------------------------
@dataclass
class FirewallEvent:
    """One parsed firewall log line.

    ``id`` is the SQLite primary key once the event has been stored; it stays
    ``None`` for events that have only been parsed, which is why
    ``sentinelfw explain event --last`` can display it.
    """

    id: int | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    protocol: str | None = None
    source_port: int | None = None
    dest_port: int | None = None
    action: str = "DROP"
    prefix: str = ""
    timestamp: str = field(default_factory=now_iso)
    epoch: float = 0.0
    rule_id: int | None = None
    severity: str = Severity.INFO
    description: str = ""
    raw: str = ""
    packet_length: int | None = None
    tcp_flags: str | None = None

    def __post_init__(self) -> None:
        self.action = (self.action or "UNKNOWN").upper()
        if not self.epoch:
            parsed = parse_iso(self.timestamp)
            self.epoch = epoch_of(parsed) if parsed else epoch_of(now_utc())
        if not self.timestamp:
            self.timestamp = iso_from_epoch(self.epoch)

    @property
    def blocked(self) -> bool:
        return self.action in ("DROP", "REJECT")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "epoch": self.epoch,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "protocol": self.protocol,
            "source_port": self.source_port,
            "dest_port": self.dest_port,
            "action": self.action,
            "prefix": self.prefix,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "description": self.description,
            "packet_length": self.packet_length,
            "tcp_flags": self.tcp_flags,
        }

    @classmethod
    def from_row(cls, row: sqlite3.Row | dict[str, Any]) -> "FirewallEvent":
        keys = row.keys() if isinstance(row, sqlite3.Row) else row.keys()
        return cls(**{k: row[k] for k in keys if k in cls.__dataclass_fields__})  # type: ignore[attr-defined]


@dataclass
class Alert:
    """A detection finding."""

    kind: str
    severity: str
    title: str
    description: str = ""
    source_ip: str | None = None
    dest_port: int | None = None
    fingerprint: str = ""
    first_seen: str = field(default_factory=now_iso)
    last_seen: str = field(default_factory=now_iso)
    first_epoch: float = 0.0
    last_epoch: float = 0.0
    event_count: int = 0
    ports: list[int] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    acknowledged: bool = False

    def __post_init__(self) -> None:
        self.severity = (self.severity or Severity.MEDIUM).lower()
        if not self.first_epoch:
            parsed = parse_iso(self.first_seen)
            self.first_epoch = epoch_of(parsed) if parsed else 0.0
        if not self.last_epoch:
            self.last_epoch = self.first_epoch

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "dest_port": self.dest_port,
            "fingerprint": self.fingerprint,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "first_epoch": self.first_epoch,
            "last_epoch": self.last_epoch,
            "event_count": self.event_count,
            "ports": self.ports,
            "evidence": self.evidence,
            "acknowledged": self.acknowledged,
        }


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT    NOT NULL,
    epoch          REAL    NOT NULL,
    source_ip      TEXT,
    dest_ip        TEXT,
    protocol       TEXT,
    source_port    INTEGER,
    dest_port      INTEGER,
    action         TEXT    NOT NULL,
    prefix         TEXT,
    rule_id        INTEGER,
    severity       TEXT    NOT NULL DEFAULT 'info',
    description    TEXT,
    packet_length  INTEGER,
    tcp_flags      TEXT,
    raw            TEXT,
    ingested_at    TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_epoch      ON events(epoch);
CREATE INDEX IF NOT EXISTS idx_events_source     ON events(source_ip, epoch);
CREATE INDEX IF NOT EXISTS idx_events_port       ON events(dest_port, epoch);
CREATE INDEX IF NOT EXISTS idx_events_action     ON events(action, epoch);
CREATE INDEX IF NOT EXISTS idx_events_severity   ON events(severity, epoch);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint  TEXT    NOT NULL UNIQUE,
    kind         TEXT    NOT NULL,
    severity     TEXT    NOT NULL,
    title        TEXT    NOT NULL,
    description  TEXT,
    source_ip    TEXT,
    dest_port    INTEGER,
    first_seen   TEXT    NOT NULL,
    last_seen    TEXT    NOT NULL,
    first_epoch  REAL    NOT NULL,
    last_epoch   REAL    NOT NULL,
    event_count  INTEGER NOT NULL DEFAULT 0,
    ports        TEXT    NOT NULL DEFAULT '[]',
    evidence     TEXT    NOT NULL DEFAULT '{}',
    acknowledged INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_epoch    ON alerts(last_epoch);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity, last_epoch);
CREATE INDEX IF NOT EXISTS idx_alerts_kind     ON alerts(kind, last_epoch);

CREATE TABLE IF NOT EXISTS rule_hits (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id    INTEGER NOT NULL,
    epoch      REAL    NOT NULL,
    timestamp  TEXT    NOT NULL,
    hits       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_rule_hits ON rule_hits(rule_id, epoch);
-- bmp_rule_hits relies on this to fold repeated updates into one row per
-- (rule, second-window) bucket.
CREATE UNIQUE INDEX IF NOT EXISTS idx_rule_hits_unique
    ON rule_hits(rule_id, epoch);
"""


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
class Database:
    """Thread-safe SQLite wrapper (one connection guarded by a lock)."""

    def __init__(self, path: str | os.PathLike[str], *, busy_timeout_ms: int = 5000,
                 create: bool = True) -> None:
        self.path = Path(path)
        self.busy_timeout_ms = busy_timeout_ms
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        if create:
            self._ensure_parent()
        elif not self.path.exists():
            raise DatabaseError(
                f"Database {self.path} does not exist.",
                hint="Create it with: sentinelfw monitor ingest --demo",
            )

    # -- connection --------------------------------------------------------
    def _ensure_parent(self) -> None:
        try:
            ensure_dir(self.path.parent)
        except OSError as exc:
            raise DatabaseError(f"Cannot create {self.path.parent}: {exc}") from exc

    @property
    def conn(self) -> sqlite3.Connection:
        """Lazily opened connection in autocommit-friendly mode."""
        if self._conn is None:
            try:
                conn = sqlite3.connect(
                    str(self.path),
                    timeout=self.busy_timeout_ms / 1000.0,
                    isolation_level=None,       # explicit transactions
                    check_same_thread=False,
                )
            except sqlite3.Error as exc:
                raise DatabaseError(f"Cannot open {self.path}: {exc}") from exc
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
                conn.execute("PRAGMA foreign_keys=ON")
            except sqlite3.Error as exc:  # pragma: no cover - exotic filesystems
                log.warning("Could not apply all SQLite pragmas: %s", exc)
            self._conn = conn
            self._migrate(conn)
        return self._conn

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """Create tables and record the schema version."""
        try:
            conn.executescript(_SCHEMA)
        except sqlite3.Error as exc:
            raise DatabaseError(
                f"Cannot initialise schema in {self.path}: {exc}",
                hint="Check free disk space and directory permissions.",
            ) from exc
        current = self.get_meta("schema_version")
        if current is None:
            self.set_meta("schema_version", str(SCHEMA_VERSION))
            self.set_meta("created_at", now_iso())
        elif int(current) < SCHEMA_VERSION:
            log.info("Migrating database schema v%s -> v%s", current, SCHEMA_VERSION)
            # Future migrations are appended here, one version at a time.
            self.set_meta("schema_version", str(SCHEMA_VERSION))

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Explicit ``BEGIN``/``COMMIT`` with rollback on error."""
        conn = self.conn
        with self._lock:
            try:
                conn.execute("BEGIN")
            except sqlite3.OperationalError:
                # Already inside a transaction (nested use): just yield.
                yield conn
                return
            try:
                yield conn
            except Exception:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                finally:
                    self._conn = None

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- meta --------------------------------------------------------------
    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )

    # -- writes ------------------------------------------------------------
    def insert_event(self, event: FirewallEvent) -> int:
        """Insert a single event, returning its row id."""
        return self.insert_events([event])

    def insert_events(self, events: Sequence[FirewallEvent]) -> int:
        """Insert a batch of events in one transaction. Returns the count."""
        if not events:
            return 0
        rows = [
            (
                event.timestamp, event.epoch, event.source_ip, event.dest_ip,
                event.protocol, event.source_port, event.dest_port, event.action,
                event.prefix, event.rule_id, event.severity, event.description,
                event.packet_length, event.tcp_flags, event.raw, now_iso(),
            )
            for event in events
        ]
        sql = """
            INSERT INTO events (
                timestamp, epoch, source_ip, dest_ip, protocol, source_port,
                dest_port, action, prefix, rule_id, severity, description,
                packet_length, tcp_flags, raw, ingested_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """
        try:
            with self.transaction() as conn:
                conn.executemany(sql, rows)
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to store events: {exc}") from exc
        return len(rows)

    def record_alert(self, alert: Alert) -> tuple[int, bool]:
        """Insert or update an alert by fingerprint.

        Returns ``(alert_id, created)`` where ``created`` is ``False`` when an
        existing alert was updated (the alert table stays de-duplicated).
        """
        payload = (
            alert.kind, alert.severity, alert.title, alert.description,
            alert.source_ip, alert.dest_port, alert.fingerprint,
            alert.first_seen, alert.last_seen, alert.first_epoch, alert.last_epoch,
            alert.event_count, json.dumps(sorted(alert.ports)),
            json.dumps(alert.evidence, default=str), int(alert.acknowledged),
        )
        try:
            with self.transaction() as conn:
                existing = conn.execute(
                    "SELECT id, first_epoch, event_count FROM alerts WHERE fingerprint = ?",
                    (alert.fingerprint,),
                ).fetchone()
                if existing is None:
                    cursor = conn.execute(
                        """
                        INSERT INTO alerts (
                            kind, severity, title, description, source_ip, dest_port,
                            fingerprint, first_seen, last_seen, first_epoch,
                            last_epoch, event_count, ports, evidence, acknowledged,
                            created_at
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        (*payload, now_iso()),
                    )
                    return int(cursor.lastrowid or 0), True
                alert_id = int(existing["id"])
                first_epoch = min(float(existing["first_epoch"] or 0.0), alert.first_epoch)
                total = int(existing["event_count"] or 0) + max(1, alert.event_count)
                conn.execute(
                    """
                    UPDATE alerts
                       SET last_seen = ?, last_epoch = ?, first_epoch = ?,
                           severity = ?, title = ?, description = ?, event_count = ?,
                           ports = ?, evidence = ?
                     WHERE id = ?
                    """,
                    (
                        alert.last_seen, max(alert.last_epoch, float(existing["first_epoch"])),
                        first_epoch, alert.severity, alert.title, alert.description,
                        total, json.dumps(sorted(alert.ports)),
                        json.dumps(alert.evidence, default=str), alert_id,
                    ),
                )
                return alert_id, False
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to store alert: {exc}") from exc

    def bump_rule_hits(self, rule_id: int, hits: int = 1) -> None:
        """Accumulate per-rule hit counters for the ``firewall why`` view.

        The epoch is truncated to whole seconds on purpose: the unique index is
        on ``(rule_id, epoch)``, so a sub-second float would never collide and
        every call would insert a fresh row instead of incrementing.
        """
        try:
            with self.transaction() as conn:
                conn.execute(
                    """
                    INSERT INTO rule_hits(rule_id, epoch, timestamp, hits)
                    VALUES (?,?,?,?)
                    ON CONFLICT(rule_id, epoch)
                    DO UPDATE SET hits = hits + excluded.hits
                    """,
                    (rule_id, int(epoch_of(now_utc())), now_iso(), hits),
                )
        except sqlite3.Error:
            log.debug("Could not update rule hit counters", exc_info=True)

    # -- reads -------------------------------------------------------------
    def _query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        try:
            return self.conn.execute(sql, tuple(params)).fetchall()
        except sqlite3.Error as exc:
            raise DatabaseError(f"Query failed: {exc}") from exc

    def count_events(self, *, since_epoch: float | None = None,
                     until_epoch: float | None = None) -> int:
        where, params = self._range_clause(since_epoch, until_epoch)
        row = self._query(f"SELECT COUNT(*) AS c FROM events{where}", params)
        return int(row[0]["c"]) if row else 0

    def recent_events(self, limit: int = 50, *, since_epoch: float | None = None,
                      until_epoch: float | None = None,
                      action: str | None = None,
                      source_ip: str | None = None) -> list[FirewallEvent]:
        conditions, params = self._conditions(since_epoch, until_epoch)
        extra: list[str] = []
        if action:
            extra.append("action = ?")
            params.append(action.upper())
        if source_ip:
            extra.append("source_ip = ?")
            params.append(source_ip)
        conditions = [c for c in [*conditions, *extra] if c]
        clause = " AND ".join(conditions)
        sql = ("SELECT * FROM events"
               + (f" WHERE {clause}" if clause else "")
               + " ORDER BY epoch DESC, id DESC LIMIT ?")
        return [FirewallEvent.from_row(r) for r in self._query(sql, [*params, limit])]

    def iter_events(self, *, since_epoch: float | None = None,
                    until_epoch: float | None = None, batch: int = 1000
                    ) -> Iterator[FirewallEvent]:
        """Stream events oldest-first without loading everything into memory."""
        where, params = self._range_clause(since_epoch, until_epoch)
        sql = f"SELECT * FROM events{where} ORDER BY epoch ASC, id ASC LIMIT ?"
        cursor = self.conn.execute(sql, (*params, batch))
        while True:
            rows = cursor.fetchmany(batch)
            if not rows:
                return
            for row in rows:
                yield FirewallEvent.from_row(row)

    def top_sources(self, since_epoch: float, limit: int = 10,
                    *, blocked_only: bool = True) -> list[dict[str, Any]]:
        where = "epoch >= ?"
        params: list[Any] = [since_epoch]
        if blocked_only:
            where += " AND action IN ('DROP','REJECT')"
        sql = f"""
            SELECT source_ip,
                   COUNT(*)                AS attempts,
                   COUNT(DISTINCT dest_port) AS ports,
                   MIN(epoch)              AS first_epoch,
                   MAX(epoch)              AS last_epoch,
                   MAX(severity)           AS worst_severity
              FROM events
             WHERE {where} AND source_ip IS NOT NULL
          GROUP BY source_ip
          ORDER BY attempts DESC, last_epoch DESC
             LIMIT ?
        """
        return [dict(r) for r in self._query(sql, (*params, limit))]

    def top_ports(self, since_epoch: float, limit: int = 10,
                  *, blocked_only: bool = True) -> list[dict[str, Any]]:
        where = "epoch >= ?"
        params: list[Any] = [since_epoch]
        if blocked_only:
            where += " AND action IN ('DROP','REJECT')"
        sql = f"""
            SELECT dest_port, protocol, COUNT(*) AS attempts,
                   COUNT(DISTINCT source_ip) AS sources
              FROM events
             WHERE {where} AND dest_port IS NOT NULL
          GROUP BY dest_port, protocol
          ORDER BY attempts DESC
             LIMIT ?
        """
        return [dict(r) for r in self._query(sql, (*params, limit))]

    def hourly_histogram(self, since_epoch: float) -> list[dict[str, Any]]:
        """Events per hour bucket, for the dashboard's activity sparkline."""
        sql = """
            SELECT CAST((epoch - ?) / 3600 AS INTEGER) AS bucket,
                   COUNT(*) AS total,
                   SUM(CASE WHEN action IN ('DROP','REJECT') THEN 1 ELSE 0 END) AS blocked
              FROM events
             WHERE epoch >= ?
          GROUP BY bucket
          ORDER BY bucket ASC
        """
        rows = [dict(r) for r in self._query(sql, (since_epoch, since_epoch))]
        if not rows:
            return []
        # Fill empty buckets so the chart has a continuous x-axis.
        start = int(rows[0]["bucket"])
        end = int(rows[-1]["bucket"])
        by_bucket = {int(r["bucket"]): r for r in rows}
        return [
            {
                "bucket": b,
                "hour": iso_from_epoch(since_epoch + b * 3600),
                "total": int(by_bucket.get(b, {}).get("total", 0)),
                "blocked": int(by_bucket.get(b, {}).get("blocked", 0)),
            }
            for b in range(start, end + 1)
        ]

    def alerts(self, *, since_epoch: float | None = None,
               limit: int = 50, min_severity: str | None = None,
               kind: str | None = None, include_acked: bool = False) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if since_epoch is not None:
            clauses.append("last_epoch >= ?")
            params.append(since_epoch)
        if min_severity:
            allowed = SEVERITY_ORDER[severity_rank(min_severity):]
            placeholders = ",".join("?" for _ in allowed)
            clauses.append(f"severity IN ({placeholders})")
            params.extend(allowed)
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if not include_acked:
            clauses.append("acknowledged = 0")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (f"SELECT * FROM alerts{where} ORDER BY last_epoch DESC LIMIT ?")
        out: list[dict[str, Any]] = []
        for row in self._query(sql, (*params, limit)):
            item = dict(row)
            for key in ("ports", "evidence"):
                try:
                    item[key] = json.loads(item.get(key) or ("[]" if key == "ports" else "{}"))
                except json.JSONDecodeError:
                    item[key] = [] if key == "ports" else {}
            item["acknowledged"] = bool(item.get("acknowledged"))
            out.append(item)
        return out

    def alert_counts_by_severity(self, since_epoch: float) -> dict[str, int]:
        rows = self._query(
            "SELECT severity, COUNT(*) AS c FROM alerts WHERE last_epoch >= ? GROUP BY severity",
            (since_epoch,),
        )
        counts = {s: 0 for s in SEVERITY_ORDER}
        for row in rows:
            counts[str(row["severity"])] = int(row["c"])
        return counts

    def top_alert_kinds(self, since_epoch: float, limit: int = 5) -> list[dict[str, Any]]:
        rows = self._query(
            """
            SELECT kind, severity, COUNT(*) AS c
              FROM alerts WHERE last_epoch >= ?
          GROUP BY kind, severity ORDER BY c DESC LIMIT ?
            """,
            (since_epoch, limit),
        )
        return [dict(r) for r in rows]

    def acknowledge_alert(self, alert_id: int, acknowledged: bool = True) -> bool:
        try:
            with self.transaction() as conn:
                cursor = conn.execute(
                    "UPDATE alerts SET acknowledged = ? WHERE id = ?",
                    (int(acknowledged), alert_id),
                )
                return cursor.rowcount > 0
        except sqlite3.Error as exc:
            raise DatabaseError(f"Could not update alert: {exc}") from exc

    def rule_hit_totals(self, since_epoch: float) -> dict[int, int]:
        rows = self._query(
            "SELECT rule_id, SUM(hits) AS total FROM rule_hits WHERE epoch >= ? GROUP BY rule_id",
            (since_epoch,),
        )
        return {int(r["rule_id"]): int(r["total"] or 0) for r in rows}

    def stats(self, since_epoch: float) -> dict[str, Any]:
        """Everything the dashboard needs, in one round of cheap queries."""
        row = self._query(
            """
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN action IN ('DROP','REJECT') THEN 1 ELSE 0 END) AS blocked,
                   SUM(CASE WHEN action = 'ACCEPT' THEN 1 ELSE 0 END) AS accepted,
                   COUNT(DISTINCT source_ip) AS unique_sources,
                   COUNT(DISTINCT dest_port) AS unique_ports,
                   MIN(epoch) AS first_epoch,
                   MAX(epoch) AS last_epoch
              FROM events WHERE epoch >= ?
            """,
            (since_epoch,),
        )
        base = dict(row[0]) if row else {}
        result = {
            "total_events": int(base.get("total") or 0),
            "blocked_events": int(base.get("blocked") or 0),
            "accepted_events": int(base.get("accepted") or 0),
            "unique_sources": int(base.get("unique_sources") or 0),
            "unique_ports": int(base.get("unique_ports") or 0),
            "first_epoch": base.get("first_epoch"),
            "last_epoch": base.get("last_epoch"),
        }
        result["alerts_by_severity"] = self.alert_counts_by_severity(since_epoch)
        result["alert_total"] = sum(result["alerts_by_severity"].values())
        return result

    # -- maintenance -------------------------------------------------------
    def prune(self, *, older_than_epoch: float | None = None) -> dict[str, int]:
        """Delete old events, alerts and counters.

        With ``older_than_epoch`` only rows older than that timestamp go; with
        ``None`` the events table is emptied (a full reset of history, keeping
        the schema and the ``meta`` table intact).
        """
        removed = {"events": 0, "alerts": 0, "rule_hits": 0}
        try:
            with self.transaction() as conn:
                if older_than_epoch is None:
                    cursor = conn.execute("DELETE FROM events")
                else:
                    cursor = conn.execute("DELETE FROM events WHERE epoch < ?",
                                          (older_than_epoch,))
                removed["events"] = cursor.rowcount or 0
                if older_than_epoch is None:
                    conn.execute("DELETE FROM alerts")
                    conn.execute("DELETE FROM rule_hits")
                else:
                    removed["alerts"] = (conn.execute(
                        "DELETE FROM alerts WHERE last_epoch < ?",
                        (older_than_epoch,)).rowcount or 0)
                    removed["rule_hits"] = (conn.execute(
                        "DELETE FROM rule_hits WHERE epoch < ?",
                        (older_than_epoch,)).rowcount or 0)
        except sqlite3.Error as exc:
            raise DatabaseError(f"Prune failed: {exc}") from exc
        log.info("Pruned %s", removed)
        return removed

    def vacuum(self) -> None:
        try:
            self.conn.execute("VACUUM")
        except sqlite3.Error as exc:
            raise DatabaseError(f"VACUUM failed: {exc}") from exc

    def file_size(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError:
            return 0

    def reset(self, *, confirm_required: bool = True) -> None:
        """Delete all rows but keep the schema. Used by ``monitor reset``."""
        try:
            with self.transaction() as conn:
                conn.execute("DELETE FROM events")
                conn.execute("DELETE FROM alerts")
                conn.execute("DELETE FROM rule_hits")
        except sqlite3.Error as exc:
            raise DatabaseError(f"Reset failed: {exc}") from exc
        log.warning("Event database %s cleared", self.path)

    def export_rows(self, since_epoch: float | None = None,
                    limit: int | None = None) -> list[dict[str, Any]]:
        where, params = self._range_clause(since_epoch, None)
        sql = f"SELECT * FROM events{where} ORDER BY epoch ASC"
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        return [dict(r) for r in self._query(sql, params)]

    # -- internals ---------------------------------------------------------
    @staticmethod
    def _conditions(since_epoch: float | None,
                    until_epoch: float | None) -> tuple[list[str], list[Any]]:
        """Build ``(conditions, params)`` for an epoch range."""
        conditions: list[str] = []
        params: list[Any] = []
        if since_epoch is not None:
            conditions.append("epoch >= ?")
            params.append(float(since_epoch))
        if until_epoch is not None:
            conditions.append("epoch <= ?")
            params.append(float(until_epoch))
        return conditions, params

    @classmethod
    def _range_clause(cls, since_epoch: float | None,
                      until_epoch: float | None) -> tuple[str, list[Any]]:
        conditions, params = cls._conditions(since_epoch, until_epoch)
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        return where, params

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Database {self.path}>"