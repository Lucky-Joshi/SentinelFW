"""Anomaly detection over stored firewall events.

Method
------
Every detector answers one question over a time window using SQL, so the cost
scales with the window rather than with the size of the history. That matters:
a month of events should not be slower to analyse than a day.

The detectors are deliberately *threshold and window* based rather than
statistical. On a Kali workstation the interesting events are rare and
conspicuous (300 attempts against port 22), and a threshold that an operator
can read, tune and reason about is more trustworthy than an opaque score. The
thresholds live in ``config.yaml`` under ``detection:``.

Every alert carries a fingerprint so the same finding is updated rather than
duplicated on each poll.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Sequence

from config import AppConfig
from logsetup import get_logger
from monitor.database import Alert, Database, Severity, severity_rank
from monitor.explain import attack_info, recommendations_for
from utils import epoch_of, iso_from_epoch, now_iso, now_utc

log = get_logger("monitor.detector")

__all__ = [
    "Detector",
    "PortScanDetector",
    "BruteForceDetector",
    "ConnectionSpikeDetector",
    "RepeatedBlockDetector",
    "SensitivePortDetector",
    "DetectionEngine",
    "DetectionResult",
]


def _fingerprint(*parts: Any) -> str:
    """Stable short identifier for de-duplication."""
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]  # noqa: S324 - not security


@dataclass
class DetectionResult:
    """Outcome of one polling cycle."""

    scanned_events: int = 0
    alerts: list[Alert] = field(default_factory=list)
    new_alerts: list[Alert] = field(default_factory=list)
    updated_alerts: list[Alert] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def alert_count(self) -> int:
        return len(self.alerts)

    def as_dict(self) -> dict[str, Any]:
        return {
            "scanned_events": self.scanned_events,
            "alerts": len(self.alerts),
            "new_alerts": len(self.new_alerts),
            "updated_alerts": len(self.updated_alerts),
            "duration_seconds": round(self.duration_seconds, 3),
            "kinds": sorted({a.kind for a in self.alerts}),
        }


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------
class Detector:
    """Base class: a named check over an event window."""

    kind = "base"
    default_severity = Severity.MEDIUM

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.log = log

    # -- helpers -----------------------------------------------------------
    @property
    def window_seconds(self) -> int:
        """Subclasses override; default is one hour."""
        return 3600

    @property
    def cooldown_seconds(self) -> int:
        return self.config.detection.alert_cooldown_seconds

    def _recent_alert_exists(self, db: Database, fingerprint: str) -> bool:
        """Respect the cooldown so a sustained attack is not re-announced."""
        rows = db.conn.execute(
            "SELECT last_epoch FROM alerts WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        if rows is None:
            return False
        return (epoch_of(now_utc()) - float(rows["last_epoch"])) < self.cooldown_seconds

    def detect(self, db: Database, now: float | None = None) -> list[Alert]:
        """Return alerts for the current window. Subclasses implement."""
        raise NotImplementedError

    def _alert(self, **kwargs: Any) -> Alert:
        kwargs.setdefault("severity", self.default_severity)
        return Alert(kind=self.kind, **kwargs)


# ---------------------------------------------------------------------------
# Concrete detectors
# ---------------------------------------------------------------------------
class PortScanDetector(Detector):
    """One source touching many distinct ports in a short window.

    Query shape: ``COUNT(DISTINCT dest_port)`` grouped by source, filtered to a
    sliding window. This is the classic reconnaissance signature and is the
    most reliable of the four detectors.
    """

    kind = "port_scan"

    def __init__(self, config: AppConfig) -> None:
        super().__init__(config)
        self.threshold = max(2, config.detection.port_scan_threshold)
        self.window = max(5, config.detection.port_scan_window_seconds)

    @property
    def window_seconds(self) -> int:
        return self.window

    def detect(self, db: Database, now: float | None = None) -> list[Alert]:
        now = now or time.time()
        rows = db.conn.execute(
            """
            SELECT source_ip,
                   COUNT(DISTINCT dest_port)      AS ports,
                   COUNT(*)                       AS packets,
                   MIN(epoch)                     AS first_epoch,
                   MAX(epoch)                     AS last_epoch
              FROM events
             WHERE epoch >= ? AND source_ip IS NOT NULL AND dest_port IS NOT NULL
          GROUP BY source_ip
            HAVING ports >= ?
             ORDER BY ports DESC
             LIMIT 50
            """,
            (now - self.window, self.threshold),
        ).fetchall()

        alerts: list[Alert] = []
        for row in rows:
            fingerprint = _fingerprint(self.kind, row["source_ip"], self.window)
            if self._recent_alert_exists(db, fingerprint):
                continue
            ports = [
                int(r["dest_port"])
                for r in db.conn.execute(
                    """
                    SELECT DISTINCT dest_port FROM events
                     WHERE source_ip = ? AND epoch >= ? AND dest_port IS NOT NULL
                  ORDER BY dest_port
                    """,
                    (row["source_ip"], now - self.window),
                ).fetchall()
            ]
            count = int(row["ports"])
            # Severity scales with breadth: a 20-port sweep is suspicious, a
            # 2000-port sweep is a full port scan.
            severity = Severity.CRITICAL if count >= self.threshold * 10 else Severity.HIGH
            title = f"Possible port scan ({count} distinct ports)"
            description = (
                f"{row['source_ip']} contacted {count} distinct ports and sent "
                f"{int(row['packets'])} packets within {self.window}s."
            )
            alerts.append(
                self._alert(
                    severity=severity,
                    title=title,
                    description=description,
                    source_ip=str(row["source_ip"]),
                    fingerprint=fingerprint,
                    first_seen=iso_from_epoch(row["first_epoch"]),
                    last_seen=iso_from_epoch(row["last_epoch"]),
                    first_epoch=float(row["first_epoch"]),
                    last_epoch=float(row["last_epoch"]),
                    event_count=int(row["packets"]),
                    ports=ports[:64],
                    evidence={
                        "distinct_ports": count,
                        "packets": int(row["packets"]),
                        "window_seconds": self.window,
                        "threshold": self.threshold,
                        "ports_sample": ports[:32],
                    },
                )
            )
        return alerts


class BruteForceDetector(Detector):
    """Many blocked packets to the same source/port pair.

    Restricted to blocked events: a *successful* login is a different (and much
    more serious) problem, and this tool has no way to distinguish it from
    ordinary traffic. Flagging volume is what log data alone can support.
    """

    kind = "brute_force"

    def __init__(self, config: AppConfig) -> None:
        super().__init__(config)
        self.threshold = max(2, config.detection.brute_force_threshold)
        self.window = max(5, config.detection.brute_force_window_seconds)

    @property
    def window_seconds(self) -> int:
        return self.window

    def detect(self, db: Database, now: float | None = None) -> list[Alert]:
        now = now or time.time()
        rows = db.conn.execute(
            """
            SELECT source_ip, dest_port, protocol,
                   COUNT(*)      AS attempts,
                   MIN(epoch)    AS first_epoch,
                   MAX(epoch)    AS last_epoch
              FROM events
             WHERE epoch >= ? AND source_ip IS NOT NULL
                   AND action IN ('DROP','REJECT')
             GROUP BY source_ip, dest_port
            HAVING attempts >= ?
          ORDER BY attempts DESC
             LIMIT 50
            """,
            (now - self.window, self.threshold),
        ).fetchall()

        from firewall.rules import port_service_name

        alerts: list[Alert] = []
        for row in rows:
            port = row["dest_port"]
            fingerprint = _fingerprint(self.kind, row["source_ip"], port)
            if self._recent_alert_exists(db, fingerprint):
                continue
            service = port_service_name(int(port)) if port else "unknown"
            attempts = int(row["attempts"])
            alerts.append(
                self._alert(
                    severity=Severity.CRITICAL,
                    title=f"Possible {service} brute force ({attempts} attempts)",
                    description=(
                        f"{row['source_ip']} generated {attempts} blocked connections "
                        f"to {row['protocol'] or 'tcp'}/{port} ({service}) in "
                        f"{self.window}s. This is the signature of automated password "
                        f"guessing against a login service."
                    ),
                    source_ip=str(row["source_ip"]),
                    dest_port=int(port) if port is not None else None,
                    fingerprint=fingerprint,
                    first_seen=iso_from_epoch(row["first_epoch"]),
                    last_seen=iso_from_epoch(row["last_epoch"]),
                    first_epoch=float(row["first_epoch"]),
                    last_epoch=float(row["last_epoch"]),
                    event_count=attempts,
                    ports=[int(port)] if port is not None else [],
                    evidence={
                        "attempts": attempts,
                        "window_seconds": self.window,
                        "threshold": self.threshold,
                        "service": service,
                        "protocol": row["protocol"],
                    },
                )
            )
        return alerts


class ConnectionSpikeDetector(Detector):
    """Total blocked volume far above the configured baseline.

    A blunt instrument by design: this fires on volume, not on malice, so the
    severity is capped at ``medium`` and the explanation says so.
    """

    kind = "connection_spike"

    def __init__(self, config: AppConfig) -> None:
        super().__init__(config)
        self.threshold = max(2, config.detection.spike_threshold)
        self.window = max(5, config.detection.spike_window_seconds)

    @property
    def window_seconds(self) -> int:
        return self.window

    def detect(self, db: Database, now: float | None = None) -> list[Alert]:
        now = now or time.time()
        row = db.conn.execute(
            """
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN action IN ('DROP','REJECT') THEN 1 ELSE 0 END) AS blocked,
                   COUNT(DISTINCT source_ip) AS sources,
                   MIN(epoch) AS first_epoch, MAX(epoch) AS last_epoch
              FROM events WHERE epoch >= ?
            """,
            (now - self.window,),
        ).fetchone()
        blocked = int((row["blocked"] if row else 0) or 0)
        if blocked < self.threshold:
            return []

        fingerprint = _fingerprint(self.kind, int(self.window // 60), blocked // 100)
        if self._recent_alert_exists(db, fingerprint):
            return []

        sources = int((row["sources"] if row else 0) or 0)
        many_sources = sources >= 20
        return [
            self._alert(
                severity=Severity.MEDIUM,
                title=(f"Connection spike: {blocked} blocked packets in {self.window}s"),
                description=(
                    f"{blocked} packets were logged in the last {self.window}s from "
                    f"{sources} distinct source address(es). This may be an attack "
                    f"(flood or scan storm) or a legitimate burst of activity such "
                    f"as a backup. Check the source list before acting."
                ),
                fingerprint=fingerprint,
                first_seen=iso_from_epoch(row["first_epoch"]) if row["first_epoch"] else now_iso(),
                last_seen=iso_from_epoch(row["last_epoch"]) if row["last_epoch"] else now_iso(),
                first_epoch=float(row["first_epoch"]) if row["first_epoch"] else now - self.window,
                last_epoch=float(row["last_epoch"]) if row["last_epoch"] else now,
                event_count=blocked,
                evidence={
                    "blocked": blocked,
                    "sources": sources,
                    "window_seconds": self.window,
                    "threshold": self.threshold,
                    "pattern": "many sources" if many_sources else "few sources, high rate",
                },
            )
        ]


class RepeatedBlockDetector(Detector):
    """The same source repeatedly tripping the same rule.

    The "same rule" signal comes from matching the blocked port against
    SentinelFW's own rules - it tells the operator *which* rule is doing the
    work, which is the useful part.
    """

    kind = "repeated_block"

    def __init__(self, config: AppConfig) -> None:
        super().__init__(config)
        self.threshold = max(2, config.detection.repeated_block_threshold)
        self.window = max(5, config.detection.repeated_block_window_seconds)

    @property
    def window_seconds(self) -> int:
        return self.window

    def detect(self, db: Database, now: float | None = None) -> list[Alert]:
        now = now or time.time()
        rows = db.conn.execute(
            """
            SELECT source_ip, dest_port,
                   COUNT(*)   AS hits,
                   MIN(epoch) AS first_epoch,
                   MAX(epoch) AS last_epoch
              FROM events
             WHERE epoch >= ? AND source_ip IS NOT NULL
                   AND action IN ('DROP','REJECT')
          GROUP BY source_ip, dest_port
            HAVING hits >= ?
          ORDER BY hits DESC
             LIMIT 25
            """,
            (now - self.window, self.threshold),
        ).fetchall()

        alerts: list[Alert] = []
        for row in rows:
            if int(row["hits"]) < self.threshold:
                continue
            fingerprint = _fingerprint(self.kind, row["source_ip"], row["dest_port"])
            if self._recent_alert_exists(db, fingerprint):
                continue
            port = row["dest_port"]
            # Same rule repeated, but not at a volume that reads as brute force.
            if int(row["hits"]) >= self.config.detection.brute_force_threshold:
                continue
            from firewall.rules import port_service_name

            service = port_service_name(int(port)) if port else "unknown"
            alerts.append(
                self._alert(
                    severity=Severity.MEDIUM,
                    title=f"Repeated blocks on port {port} ({int(row['hits'])} times)",
                    description=(
                        f"{row['source_ip']} hit the same blocked port {int(row['hits'])} "
                        f"times in {self.window}s. Automated tooling usually gives up "
                        f"after a few attempts; this one did not."
                    ),
                    source_ip=str(row["source_ip"]),
                    dest_port=int(port) if port is not None else None,
                    fingerprint=fingerprint,
                    first_seen=iso_from_epoch(row["first_epoch"]),
                    last_seen=iso_from_epoch(row["last_epoch"]),
                    first_epoch=float(row["first_epoch"]),
                    last_epoch=float(row["last_epoch"]),
                    event_count=int(row["hits"]),
                    ports=[int(port)] if port is not None else [],
                    evidence={
                        "hits": int(row["hits"]),
                        "window_seconds": self.window,
                        "threshold": self.threshold,
                    },
                )
            )
        return alerts


class SensitivePortDetector(Detector):
    """Blocked traffic toward services that should never be exposed.

    Aggregated **per source address**, not per (source, port) pair. A single
    port scan touching 12 watched services is one finding, not twelve; emitting
    an alert per pair would bury the real signal in noise.
    """

    kind = "sensitive_port"

    #: A single hit is not a finding: services get probed constantly. Require a
    #: small repeat count before escalating, so this complements (rather than
    #: duplicates) the volume-based detectors.
    min_hits = 3

    def __init__(self, config: AppConfig) -> None:
        super().__init__(config)
        self.watch_ports = {int(p) for p in config.detection.watch_ports}

    @property
    def window_seconds(self) -> int:
        return 3600

    def detect(self, db: Database, now: float | None = None) -> list[Alert]:
        if not self.watch_ports:
            return []
        now = now or time.time()
        placeholders = ",".join("?" for _ in self.watch_ports)
        rows = db.conn.execute(
            f"""
            SELECT source_ip,
                   COUNT(*)          AS hits,
                   COUNT(DISTINCT dest_port) AS ports_hit,
                   GROUP_CONCAT(DISTINCT dest_port) AS port_list,
                   MIN(epoch)        AS first_epoch,
                   MAX(epoch)        AS last_epoch
              FROM events
             WHERE epoch >= ? AND action IN ('DROP','REJECT')
                   AND dest_port IN ({placeholders})
          GROUP BY source_ip
            HAVING hits >= ?
          ORDER BY hits DESC
             LIMIT 20
            """,
            (now - self.window_seconds, *sorted(self.watch_ports), self.min_hits),
        ).fetchall()

        from firewall.rules import local_addresses, port_service_name

        local = local_addresses()
        alerts: list[Alert] = []
        for row in rows:
            source = str(row["source_ip"])
            if source in local:
                continue  # our own host showing up is a logging artefact
            fingerprint = _fingerprint(self.kind, source)
            if self._recent_alert_exists(db, fingerprint):
                continue

            ports = sorted(int(p) for p in str(row["port_list"] or "").split(",") if p)
            named = ", ".join(
                f"{port} ({port_service_name(port)})" for port in ports[:6]
            )
            if len(ports) > 6:
                named += f" and {len(ports) - 6} more"
            hits = int(row["hits"])
            alerts.append(
                self._alert(
                    severity=Severity.HIGH,
                    title=(f"Probed {len(ports)} sensitive service(s) "
                           f"({hits} blocked attempts)"),
                    description=(
                        f"{source} was blocked {hits} time(s) while targeting "
                        f"{len(ports)} service(s) that should not be reachable from "
                        f"an untrusted network: {named}."
                    ),
                    source_ip=source,
                    dest_port=ports[0] if ports else None,
                    fingerprint=fingerprint,
                    first_seen=iso_from_epoch(row["first_epoch"]),
                    last_seen=iso_from_epoch(row["last_epoch"]),
                    first_epoch=float(row["first_epoch"]),
                    last_epoch=float(row["last_epoch"]),
                    event_count=hits,
                    ports=ports[:64],
                    evidence={
                        "hits": hits,
                        "ports": ports,
                        "services": [port_service_name(p) for p in ports],
                        "window_seconds": self.window_seconds,
                    },
                )
            )
        return alerts


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class DetectionEngine:
    """Runs every detector over a window and persists new alerts."""

    def __init__(self, config: AppConfig, db: Database,
                 detectors: Sequence[Detector] | None = None) -> None:
        self.config = config
        self.db = db
        self.detectors: list[Detector] = list(detectors) if detectors else [
            BruteForceDetector(config),
            PortScanDetector(config),
            RepeatedBlockDetector(config),
            ConnectionSpikeDetector(config),
            SensitivePortDetector(config),
        ]
        self.log = log

    @property
    def longest_window(self) -> int:
        return max((d.window_seconds for d in self.detectors), default=3600)

    def run(self, *, now: float | None = None, persist: bool = True) -> DetectionResult:
        """Analyse the configured windows and (optionally) store findings."""
        started = time.perf_counter()
        now = now or time.time()
        result = DetectionResult(scanned_events=self.db.count_events(
            since_epoch=now - self.longest_window
        ))

        seen_fingerprints: set[str] = set()
        for detector in self.detectors:
            try:
                alerts = detector.detect(self.db, now=now)
            except Exception as exc:  # never let one detector kill the loop
                self.log.error("Detector %s failed: %s", detector.kind, exc,
                               exc_info=self.config is not None)
                continue
            for alert in alerts:
                if alert.fingerprint in seen_fingerprints:
                    continue
                seen_fingerprints.add(alert.fingerprint)
                result.alerts.append(alert)

        # Highest severity first, then most recent.
        result.alerts.sort(
            key=lambda a: (-severity_rank(a.severity), -a.last_epoch)
        )

        if persist:
            for alert in result.alerts:
                try:
                    _, created = self.db.record_alert(alert)
                except Exception as exc:
                    self.log.error("Could not store alert %s: %s", alert.fingerprint, exc)
                    continue
                (result.new_alerts if created else result.updated_alerts).append(alert)

        result.duration_seconds = time.perf_counter() - started
        if result.alerts:
            self.log.info(
                "Detection cycle: %d event(s) scanned, %d finding(s) (%d new)",
                result.scanned_events, len(result.alerts), len(result.new_alerts),
            )
        else:
            self.log.debug("Detection cycle: %d event(s) scanned, no findings",
                           result.scanned_events)
        return result

    # -- presentation helpers ---------------------------------------------
    @staticmethod
    def describe_alert(alert: Alert | dict[str, Any]) -> dict[str, Any]:
        """Attach the knowledge-base explanation to a finding."""
        data = alert.to_dict() if isinstance(alert, Alert) else dict(alert)
        info = attack_info(data.get("kind", ""))
        data["explanation"] = {
            "what": info.what if info else "",
            "why": info.why if info else "",
            "indicators": info.indicators if info else [],
        }
        data["recommendations"] = recommendations_for(
            data.get("kind", ""),
            source_ip=data.get("source_ip"),
            dest_port=data.get("dest_port"),
        )
        return data

    def known_kinds(self) -> list[str]:
        return [d.kind for d in self.detectors]