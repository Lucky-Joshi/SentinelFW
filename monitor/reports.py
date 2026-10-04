"""Security report generation.

Three output formats:

* ``text`` - human readable, rendered with Rich tables for the terminal and
  written to a plain ``.txt`` file.
* ``markdown`` - same content, for pasting into notes or a lab report.
* ``json`` - machine readable, for scripting or archiving.

The report is deliberately *evidence plus interpretation*: numbers first, then
what they most likely mean, then concrete next commands. A report that only
lists counters teaches nothing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from config import AppConfig
from exceptions import ReportError
from logsetup import get_logger
from monitor.database import Database, SEVERITY_ORDER
from monitor.detector import DetectionEngine
from monitor.explain import attack_info, port_info, recommendations_for
from utils import (
    human_duration,
    human_int,
    iso_from_epoch,
    mask_ip,
    now_iso,
    now_utc,
    period_start,
    truncate,
)

log = get_logger("monitor.report")

__all__ = ["ReportGenerator", "SecurityReport"]


@dataclass
class SecurityReport:
    """Structured report, renderable to text, markdown or JSON."""

    period_label: str
    generated_at: str
    start_epoch: float
    end_epoch: float
    stats: dict[str, Any] = field(default_factory=dict)
    top_sources: list[dict[str, Any]] = field(default_factory=list)
    top_ports: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    alert_kinds: list[dict[str, Any]] = field(default_factory=list)
    hourly: list[dict[str, Any]] = field(default_factory=list)
    firewall_rules: list[str] = field(default_factory=list)
    firewall_status: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    # -- serialisation -----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "period": self.period_label,
            "generated_at": self.generated_at,
            "window": {
                "start": iso_from_epoch(self.start_epoch),
                "end": iso_from_epoch(self.end_epoch),
                "seconds": int(self.end_epoch - self.start_epoch),
            },
            "summary": self.stats,
            "top_sources": self.top_sources,
            "top_ports": self.top_ports,
            "alerts": self.alerts,
            "alert_kinds": self.alert_kinds,
            "activity_by_hour": self.hourly,
            "firewall": {
                "status": self.firewall_status,
                "rules": self.firewall_rules,
            },
            "recommendations": self.recommendations,
            "notes": self.notes,
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    # -- rendering ---------------------------------------------------------
    def to_markdown(self) -> str:
        """Markdown rendering (also used as the basis for the text report)."""
        lines: list[str] = []
        add = lines.append

        add(f"# SentinelFW Security Report")
        add("")
        add(f"- **Generated**: {self.generated_at}")
        add(f"- **Period**: last {self.period_label} "
            f"(from {iso_from_epoch(self.start_epoch)} to {iso_from_epoch(self.end_epoch)})")
        add(f"- **Database**: {self.firewall_status.get('database', 'unknown')}")
        add("")

        add("## Summary")
        add("")
        add("| Metric | Value |")
        add("| --- | --- |")
        add(f"| Events recorded | {human_int(self.stats.get('total_events'))} |")
        add(f"| Blocked / rejected | {human_int(self.stats.get('blocked_events'))} |")
        add(f"| Accepted | {human_int(self.stats.get('accepted_events'))} |")
        add(f"| Unique source addresses | {human_int(self.stats.get('unique_sources'))} |")
        add(f"| Unique destination ports | {human_int(self.stats.get('unique_ports'))} |")
        alerts_by_sev = self.stats.get("alerts_by_severity", {})
        for sev in reversed(SEVERITY_ORDER):
            count = alerts_by_sev.get(sev, 0)
            if count:
                add(f"| Alerts ({sev}) | {count} |")
        add("")

        add("## Top attack sources")
        add("")
        if self.top_sources:
            add("| Source | Blocked attempts | Distinct ports | Last seen |")
            add("| --- | ---: | ---: | --- |")
            for row in self.top_sources[:10]:
                add(f"| `{row['source_ip']}` | {row['attempts']} | {row['ports']} | "
                    f"{iso_from_epoch(row['last_epoch'])} |")
        else:
            add("_No blocked connections recorded in this period._")
        add("")

        add("## Most targeted ports")
        add("")
        if self.top_ports:
            add("| Port | Service | Protocol | Attempts | Sources |")
            add("| ---: | --- | --- | ---: | ---: |")
            for row in self.top_ports[:10]:
                info = port_info(row.get("dest_port"))
                add(f"| {row['dest_port']} | {info.service} | "
                    f"{row.get('protocol') or '-'} | {row['attempts']} | {row['sources']} |")
        else:
            add("_No targeted ports recorded._")
        add("")

        add("## Threats detected")
        add("")
        if self.alerts:
            for alert in self.alerts[:15]:
                add(f"### [{alert['severity'].upper()}] {alert['title']}")
                add("")
                add(f"- **First seen**: {alert['first_seen']}")
                add(f"- **Last seen**: {alert['last_seen']}")
                if alert.get("source_ip"):
                    add(f"- **Source**: `{alert['source_ip']}`")
                if alert.get("dest_port"):
                    add(f"- **Target port**: {alert['dest_port']}")
                add(f"- **Events**: {alert.get('event_count', 0)}")
                if alert.get("description"):
                    add("")
                    add(alert["description"])
                info = attack_info(alert["kind"])
                if info and info.why:
                    add("")
                    add(f"**Why this matters**: {info.why}")
                add("")
        else:
            add("_No threats detected in this period._")
            add("")

        add("## Firewall state")
        add("")
        status = self.firewall_status
        add(f"- Backend: {status.get('nft_version') or 'unknown'}")
        add(f"- Table: `{status.get('table', '-')}` "
            f"({'present' if status.get('table_exists') else 'not installed'})")
        add(f"- Active rules tracked by SentinelFW: {len(self.firewall_rules)}")
        if self.firewall_rules:
            add("")
            for rule in self.firewall_rules[:25]:
                add(f"  - {rule}")
        add("")

        add("## Recommendations")
        add("")
        if self.recommendations:
            for item in self.recommendations:
                add(f"1. {item}")
        else:
            add("_No action required based on the collected evidence._")
        add("")

        if self.notes:
            add("## Notes and caveats")
            add("")
            for note in self.notes:
                add(f"- {note}")
            add("")

        return "\n".join(lines)

    def to_text(self) -> str:
        """Plain-text report for the terminal."""
        lines: list[str] = []
        add = lines.append
        rule = "=" * 68

        add(rule)
        add("SentinelFW Security Report".center(68))
        add(rule)
        add(f"Generated : {self.generated_at}")
        add(f"Period    : last {self.period_label}")
        add(f"Window    : {iso_from_epoch(self.start_epoch)} -> "
            f"{iso_from_epoch(self.end_epoch)}")
        add("")

        add("-- Summary " + "-" * 56)
        add(f"  Events recorded      : {self.stats.get('total_events', 0)}")
        add(f"  Blocked / rejected   : {self.stats.get('blocked_events', 0)}")
        add(f"  Accepted             : {self.stats.get('accepted_events', 0)}")
        add(f"  Unique sources       : {self.stats.get('unique_sources', 0)}")
        add(f"  Unique ports targeted: {self.stats.get('unique_ports', 0)}")
        alerts_by_sev = self.stats.get("alerts_by_severity", {})
        total_alerts = sum(alerts_by_sev.values()) if alerts_by_sev else 0
        add(f"  Alerts raised        : {total_alerts}")
        for sev in reversed(SEVERITY_ORDER):
            if alerts_by_sev.get(sev):
                add(f"      - {sev:<9}: {alerts_by_sev[sev]}")
        add("")

        add("-- Top attack sources " + "-" * 47)
        if self.top_sources:
            add(f"  {'Source':<40} {'Attempts':>9} {'Ports':>6}")
            for row in self.top_sources[:10]:
                add(f"  {row['source_ip']:<40} {row['attempts']:>9} {row['ports']:>6}")
        else:
            add("  (nothing recorded)")
        add("")

        add("-- Most targeted ports " + "-" * 48)
        if self.top_ports:
            add(f"  {'Port':<8} {'Service':<16} {'Proto':<6} {'Attempts':>9}")
            for row in self.top_ports[:10]:
                info = port_info(row.get("dest_port"))
                add(f"  {str(row['dest_port']):<8} {info.service:<16} "
                    f"{str(row.get('protocol') or '-'):<6} {row['attempts']:>9}")
        else:
            add("  (nothing recorded)")
        add("")

        add("-- Threats detected " + "-" * 50)
        if self.alerts:
            for alert in self.alerts[:10]:
                add(f"  [{alert['severity'].upper():<8}] {alert['title']}")
                if alert.get("description"):
                    add(f"             {truncate(alert['description'], 58)}")
        else:
            add("  (no threats detected in this period)")
        add("")

        add("-- Firewall state " + "-" * 52)
        status = self.firewall_status
        add(f"  Backend     : {status.get('nft_version') or 'unavailable'}")
        add(f"  Table       : {status.get('table', '-')} "
            f"({'installed' if status.get('table_exists') else 'not installed'})")
        add(f"  Rules       : {len(self.firewall_rules)} tracked")
        for rule_line in self.firewall_rules[:10]:
            add(f"      {rule_line}")
        add("")

        add("-- Recommendations " + "-" * 50)
        if self.recommendations:
            for index, item in enumerate(self.recommendations[:12], start=1):
                add(f"  {index}. {item}")
        else:
            add("  No action required based on the collected evidence.")
        add("")

        if self.notes:
            add("-- Notes " + "-" * 61)
            for note in self.notes:
                add(f"  - {note}")
            add("")

        add(rule)
        add("Report generated locally by SentinelFW. No data left this machine.")
        add(rule)
        return "\n".join(lines)


class ReportGenerator:
    """Builds :class:`SecurityReport` objects from the event database."""

    def __init__(self, config: AppConfig, db: Database) -> None:
        self.config = config
        self.db = db
        self.log = log

    def generate(self, *, period: str | None = None, limit: int | None = None,
                 include_firewall: bool = True) -> SecurityReport:
        """Assemble a report for ``period`` (e.g. ``24h``, ``7d``, ``today``)."""
        # period_start returns (start_datetime, canonical_label).
        start_dt, canonical_label = period_start(
            period or self.config.report.default_period
        )
        now_dt = now_utc()
        now_epoch = now_dt.timestamp()
        start_epoch = start_dt.timestamp()
        top_n = limit or self.config.report.top_n

        stats = self.db.stats(start_epoch)
        sources = self.db.top_sources(start_epoch, top_n)
        ports = self.db.top_ports(start_epoch, top_n)
        alerts = self.db.alerts(since_epoch=start_epoch, limit=50)
        kinds = self.db.top_alert_kinds(start_epoch, limit=10)
        hourly = self.db.hourly_histogram(start_epoch)

        firewall_status: dict[str, Any] = {"database": str(self.db.path)}
        rule_lines: list[str] = []
        if include_firewall:
            firewall_status, rule_lines = self._firewall_snapshot()

        report = SecurityReport(
            period_label=canonical_label,
            generated_at=now_iso(),
            start_epoch=start_epoch,
            end_epoch=now_epoch,
            stats=stats,
            top_sources=sources,
            top_ports=ports,
            alerts=alerts,
            alert_kinds=kinds,
            hourly=hourly,
            firewall_status=firewall_status,
            firewall_rules=rule_lines,
        )
        report.recommendations = self._recommendations(report)
        report.notes = self._notes(report)
        return report

    # ------------------------------------------------------------------
    def _firewall_snapshot(self) -> tuple[dict[str, Any], list[str]]:
        """Read live firewall state, degrading gracefully without root."""
        status: dict[str, Any] = {"database": str(self.db.path)}
        lines: list[str] = []
        try:
            from firewall import NFTManager, RuleStore, is_root

            manager = NFTManager(self.config)
            snapshot = manager.status(require_root=is_root())
            status.update(
                {
                    "nft_version": snapshot.version or "unavailable",
                    "available": snapshot.available,
                    "table": f"{self.config.firewall.family} {self.config.firewall.table}",
                    "table_exists": snapshot.table_exists,
                    "live_rules": snapshot.rule_count,
                    "detail": snapshot.detail,
                }
            )
            store = RuleStore(self.config.state_file).load()
            lines = [f"#{r.id} {r.describe()}" for r in store.sorted_rules()]
            status["stored_rules"] = len(store)
        except Exception as exc:  # a report must never fail on firewall state
            self.log.warning("Could not read firewall state for the report: %s", exc)
            status["error"] = str(exc)
        return status, lines

    def _recommendations(self, report: SecurityReport) -> list[str]:
        """Turn findings into an ordered, de-duplicated action list."""
        items: list[str] = []

        def add(text: str) -> None:
            if text and text not in items:
                items.append(text)

        for alert in report.alerts[:8]:
            kind = alert.get("kind", "")
            for step in recommendations_for(kind, source_ip=alert.get("source_ip"),
                                           dest_port=alert.get("dest_port")):
                add(step)
            info = attack_info(kind)
            if info:
                for step in info.response[:2]:
                    add(step)

        # Top source that is not already covered by an alert.
        covered = {a.get("source_ip") for a in report.alerts}
        for row in report.top_sources[:3]:
            ip = row.get("source_ip")
            if ip and ip not in covered and row.get("attempts", 0) >= 20:
                add(f"sentinelfw firewall block-ip {ip}   "
                    f"# then: sentinelfw firewall apply")

        # Services that should not be reachable at all.
        for row in report.top_ports[:5]:
            info = port_info(row.get("dest_port"))
            if info.risk in {"high", "critical"} and info.port:
                add(f"sentinelfw firewall block-port {info.port}   "
                    f"# then: sentinelfw firewall apply")

        if not report.stats.get("blocked_events"):
            add("No blocked traffic was recorded. Confirm that firewall logging is "
                "enabled (firewall.log_enabled) and that the monitor is running.")

        if not report.firewall_status.get("table_exists"):
            add("SentinelFW's nftables table is not installed. Apply your rules with: "
                "sentinelfw firewall apply")

        if not items:
            add("Nothing requires action. Keep the monitor running and review the "
                "dashboard daily.")
        return items

    def _notes(self, report: SecurityReport) -> list[str]:
        """Caveats the operator should not skip. Honesty is a feature."""
        notes = [
            "Severity is derived from event volume and pattern heuristics, not from "
            "packet inspection. Treat findings as leads to investigate, not proof of "
            "compromise.",
        ]
        if not report.top_sources:
            notes.append(
                "No events in this period. Either there was no blocked traffic, or "
                "logging is not reaching SentinelFW - check 'sentinelfw doctor'."
            )
        if report.stats.get("total_events", 0) < 10:
            notes.append(
                "Very few events were recorded; statistical conclusions are not "
                "meaningful at this volume."
            )
        db_size = self.db.file_size()
        notes.append(f"Database size: {db_size / 1024:.0f} KiB at {self.db.path}.")
        return notes

    # ------------------------------------------------------------------
    def save(self, report: SecurityReport, *, fmt: str = "text",
             directory: str | Path | None = None) -> Path:
        """Write a report to disk and return the path."""
        target_dir = Path(directory) if directory else self.config.report_dir
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        suffix = {"text": "txt", "markdown": "md", "json": "json"}.get(fmt, "txt")
        path = target_dir / f"security-report-{stamp}.{suffix}"

        renderers = {
            "text": report.to_text,
            "markdown": report.to_markdown,
            "json": report.to_json,
        }
        if fmt not in renderers:
            raise ReportError(
                f"Unknown report format {fmt!r}.",
                hint="Use text, markdown or json.",
            )
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            path.write_text(renderers[fmt](), encoding="utf-8")
            path.chmod(0o600)
        except OSError as exc:
            raise ReportError(f"Could not write report to {path}: {exc}") from exc
        self.log.info("Report written to %s", path)
        return path

    # ------------------------------------------------------------------
    def summary_line(self, report: SecurityReport) -> str:
        """One-line summary used by ``report generate --brief``."""
        duration = human_duration(report.end_epoch - report.start_epoch)
        return (
            f"{report.stats.get('blocked_events', 0)} blocked events, "
            f"{report.stats.get('unique_sources', 0)} sources, "
            f"{sum(report.stats.get('alerts_by_severity', {}).values())} alerts "
            f"over {duration}"
        )


def privacy_masked_sources(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return copies with public IPs partially masked (for shareable reports)."""
    return [{**row, "source_ip": mask_ip(str(row.get("source_ip", "")))}
            for row in sources]