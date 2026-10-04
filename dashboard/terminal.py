"""Terminal dashboard built with Rich.

Two rendering modes, because a dashboard that only works in a full-screen TTY
is useless when piped to a file or run over a narrow SSH window:

* :meth:`Dashboard.render` - a Rich renderable, used by ``Live`` for the
  auto-refreshing view (Ctrl-C exits cleanly).
* :meth:`Dashboard.render_static` - a single snapshot, printed once. Used when
  stdout is not a TTY, and it degrades to plain text if Rich is unavailable.

Nothing in here performs actions. The dashboard is a read-only window onto the
event database and the firewall state.
"""

from __future__ import annotations

import time
from typing import Any, Sequence

from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from config import AppConfig
from logsetup import get_logger
from monitor.database import Database
from monitor.detector import DetectionEngine
from monitor.explain import SEVERITY_COLORS, port_info
from utils import human_int, iso_from_epoch, mask_ip, period_start

log = get_logger("dashboard")

__all__ = ["Dashboard", "SEVERITY_BADGES"]

#: Short bracketed labels used in compact listings.
SEVERITY_BADGES = {
    "critical": "[bold red]CRITICAL[/]",
    "high": "[magenta]HIGH[/]",
    "medium": "[yellow]MEDIUM[/]",
    "low": "[green]LOW[/]",
    "info": "[cyan]INFO[/]",
}

_BLOCKS = "▁▂▃▄▅▆▇█"


class Dashboard:
    """Assembles the security overview from the database and firewall state."""

    def __init__(self, config: AppConfig, db: Database,
                 console: Console | None = None) -> None:
        self.config = config
        self.db = db
        self.console = console or Console()
        self.engine = DetectionEngine(config, db)

    # ------------------------------------------------------------------
    def snapshot(self, range_label: str | None = None) -> dict[str, Any]:
        """Collect every value the dashboard displays in one place.

        Separated from rendering so the same data can feed a report, a JSON
        dump (``--json``) or the TUI.
        """
        label = range_label or self.config.dashboard.default_range
        start_dt, _ = period_start(label)
        start_epoch = start_dt.timestamp()
        top_n = self.config.dashboard.top_n

        data: dict[str, Any] = {
            "range": label,
            "generated_at": time.time(),
            "stats": self.db.stats(start_epoch),
            "top_sources": self.db.top_sources(start_epoch, top_n),
            "top_ports": self.db.top_ports(start_epoch, top_n),
            "alerts": self.db.alerts(since_epoch=start_epoch, limit=10),
            "hourly": self.db.hourly_histogram(start_epoch),
            "recent_events": self.db.recent_events(
                self.config.dashboard.max_events, since_epoch=start_epoch
            ),
            "firewall": {},
            "rules": [],
        }

        try:
            from firewall import NFTManager, RuleStore, is_root

            manager = NFTManager(self.config)
            status = manager.status(require_root=is_root())
            store = RuleStore(self.config.state_file).load()
            data["firewall"] = {
                "available": status.available,
                "version": status.version,
                "table_exists": status.table_exists,
                "live_rules": status.rule_count,
                "hook": status.hook,
                "priority": status.priority,
                "policy": status.policy,
                "detail": status.detail,
                "log_enabled": status.log_enabled,
            }
            data["rules"] = [r.describe() for r in store.sorted_rules()]
            data["rule_count"] = len(store)
        except Exception as exc:  # the dashboard must render regardless
            log.debug("Firewall state unavailable for dashboard: %s", exc)
            data["firewall"] = {"available": False, "detail": str(exc)}
            data["rule_count"] = len(data["rules"])

        data["alerts_by_severity"] = data["stats"].get("alerts_by_severity", {})
        data["alert_total"] = sum(data["alerts_by_severity"].values()) if data["alerts_by_severity"] else 0
        return data

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------
    def render(self, data: dict[str, Any] | None = None) -> RenderableType:
        """Build the full dashboard as a Rich renderable."""
        data = data or self.snapshot()
        pieces: list[RenderableType] = [
            self._header(data),
            self._status_row(data),
            self._activity_panel(data),
            self._sources_and_ports(data),
            self._alerts_panel(data),
        ]
        recent = self._recent_table(data)
        if recent is not None:
            pieces.append(recent)
        return Group(*pieces)

    def _header(self, data: dict[str, Any]) -> RenderableType:
        from version import APP_NAME, __version__

        subtitle = (
            f"last {data['range']}  |  generated {iso_from_epoch(data['generated_at'])}"
        )
        title = Text()
        title.append(f"{APP_NAME} ", style="bold cyan")
        title.append(f"v{__version__}", style="dim")
        title.append("  local firewall security assistant", style="bold white")
        return Panel(title, subtitle=subtitle, border_style="cyan", padding=(0, 1))

    def _status_row(self, data: dict[str, Any]) -> RenderableType:
        stats = data["stats"]
        fw = data.get("firewall", {})
        sev = data.get("alerts_by_severity", {})

        grid = Table.grid(expand=True)
        grid.add_column(justify="center")
        grid.add_column(justify="center")
        grid.add_column(justify="center")
        grid.add_column(justify="center")
        grid.add_column(justify="center")

        if fw.get("available") and fw.get("table_exists"):
            fw_text = "[bold green]ACTIVE[/]\n[dim]table installed[/]"
        elif fw.get("available"):
            fw_text = "[yellow]NOT APPLIED[/]\n[dim]run: firewall apply[/]"
        else:
            fw_text = "[bold red]UNAVAILABLE[/]\n[dim]nft not found[/]"

        critical = sev.get("critical", 0)
        high = sev.get("high", 0)
        alert_cell = Text()
        alert_cell.append(str(data.get("alert_total", 0)), style="bold")
        if critical:
            alert_cell.append(f" ({critical} critical)", style="bold red")
        elif high:
            alert_cell.append(f" ({high} high)", style="magenta")

        grid.add_row(
            self._tile("Firewall", fw_text),
            self._tile("Rules", f"[bold]{data.get('rule_count', 0)}[/]\n[dim]tracked[/]"),
            self._tile(
                "Blocked",
                f"[bold]{human_int(stats.get('blocked_events', 0))}[/]\n"
                f"[dim]last {data['range']}[/dim]",
            ),
            self._tile("Alerts", f"{alert_cell}\n[dim]open[/dim]"),
            self._tile(
                "Sources",
                f"[bold]{human_int(stats.get('unique_sources', 0))}[/]\n"
                f"[dim]unique IPs[/dim]",
            ),
        )
        return grid

    @staticmethod
    def _tile(title: str, body: str) -> RenderableType:
        text = Text()
        text.append(title.upper(), style="dim bold")
        text.append("\n")
        return Panel(text.from_markup(body), title=None, border_style="grey37",
                     padding=(0, 1))

    def _activity_panel(self, data: dict[str, Any]) -> RenderableType:
        """Hourly activity as a text bar chart (no external plotting needed)."""
        hourly: Sequence[dict[str, Any]] = data.get("hourly") or []
        if not hourly:
            body = Text("No activity recorded in this window.", style="dim")
            return Panel(body, title="Activity (last 24h)", border_style="grey37")

        peak = max((int(h["total"]) for h in hourly), default=1) or 1
        rows: list[Text] = []
        for bucket in hourly[-24:]:
            total = int(bucket["total"])
            blocked = int(bucket["blocked"])
            height = _BLOCKS[min(len(_BLOCKS) - 1, int(total / peak * (len(_BLOCKS) - 1)))]
            colour = "red" if blocked == total and blocked else "yellow" if blocked else "cyan"
            line = Text()
            line.append(f"{bucket['hour'][11:16]}  ", style="dim")
            line.append(height * 2, style=f"bold {colour}")
            line.append(f"  {total:>6}", style="white" if blocked else "dim")
            line.append(f"  ({blocked} blocked)" if blocked else "", style="dim")
            rows.append(line)

        return Panel(Group(*rows), title="Activity (per hour)", border_style="grey37")

    def _sources_and_ports(self, data: dict[str, Any]) -> RenderableType:
        sources = Table(
            title="Top blocked sources", title_style="bold", title_justify="left",
            header_style="bold dim", expand=True, border_style="grey37",
            show_edge=False,
        )
        sources.add_column("Source", overflow="ellipsis")
        sources.add_column("Attempts", justify="right")
        sources.add_column("Ports", justify="right")
        sources.add_column("Last seen", justify="right")
        rows = data.get("top_sources") or []
        if not rows:
            sources.add_row("[dim]none recorded[/dim]", "", "", "")
        for row in rows:
            sources.add_row(
                str(row["source_ip"]),
                f"[bold]{row['attempts']}[/]",
                str(row["ports"]),
                f"[dim]{iso_from_epoch(row['last_epoch'])[11:19]}[/dim]",
            )

        ports = Table(
            title="Most targeted ports", title_style="bold", title_justify="left",
            header_style="bold dim", expand=True, border_style="grey37",
            show_edge=False,
        )
        ports.add_column("Port", justify="right")
        ports.add_column("Service")
        ports.add_column("Attempts", justify="right")
        port_rows = data.get("top_ports") or []
        if not port_rows:
            ports.add_row("", "[dim]none recorded[/dim]", "")
        for row in port_rows:
            info = port_info(row.get("dest_port"))
            colour = {"critical": "red", "high": "magenta",
                      "medium": "yellow"}.get(info.risk, "dim")
            ports.add_row(
                str(row["dest_port"]),
                f"[{colour}]{info.service}[/]",
                f"[bold]{row['attempts']}[/]",
            )
        grid = Table.grid(expand=True)
        grid.add_row(sources, ports)
        return grid

    def _alerts_panel(self, data: dict[str, Any]) -> RenderableType:
        alerts = data.get("alerts") or []
        body_items: list[RenderableType] = []
        if not alerts:
            body_items.append(Text(
                "No alerts in this window. Nothing crossed a detection threshold.",
                style="dim",
            ))
        for alert in alerts[:8]:
            # overflow="fold" so long descriptions wrap instead of being cut
            # off at the panel edge.
            line = Text(overflow="fold")
            line.append(f"{alert['severity'].upper():<8}", style=SEVERITY_COLORS.get(
                alert["severity"], "white"))
            line.append(f"  {alert['title']}\n", style="bold")
            line.append(f"           {alert['description']}\n", style="dim")
            if alert.get("source_ip"):
                line.append(f"           source: {alert['source_ip']}", style="cyan")
                if alert.get("dest_port"):
                    line.append(f"  port: {alert['dest_port']}", style="cyan")
                line.append(f"  last: {alert['last_seen']}\n", style="dim")
            body_items.append(line)
        return Panel(
            Group(*body_items), title="Recent alerts", border_style="grey37"
        )

    def _recent_table(self, data: dict[str, Any]) -> RenderableType | None:
        events = data.get("recent_events") or []
        if not events:
            return None

        # Rich cannot fit seven columns on a narrow terminal: it shrinks them to
        # one character each. Drop the optional columns instead of showing
        # unreadable stubs.
        width = self.console.width if self.console is not None else 100
        compact = width < 110
        roomy = width >= 150

        table = Table(
            title="Latest events", title_style="bold", title_justify="left",
            header_style="bold dim", border_style="grey37",
            show_edge=False, row_styles=["", "on grey11"],
        )
        table.add_column("Time", no_wrap=True)
        table.add_column("Action", no_wrap=True)
        if not compact:
            table.add_column("Severity", no_wrap=True)
        table.add_column("Source", overflow="ellipsis", no_wrap=True, max_width=16)
        table.add_column("Port", justify="right", no_wrap=True)
        if roomy:
            table.add_column("Description", overflow="ellipsis", no_wrap=True)

        for event in events:
            cells = [
                event.timestamp[11:19],
                f"[{'red' if event.blocked else 'green'}]{event.action}[/]",
            ]
            if not compact:
                cells.append(f"[{SEVERITY_COLORS.get(event.severity, 'white')}]"
                             f"{event.severity}[/]")
            cells.append(mask_ip(str(event.source_ip or "-")))
            cells.append(str(event.dest_port or "-"))
            if roomy:
                cells.append(f"[dim]{event.description[:70]}[/dim]")
            table.add_row(*cells)
        return table

    # ------------------------------------------------------------------
    # Output modes
    # ------------------------------------------------------------------
    def render_static(self, data: dict[str, Any] | None = None,
                      *, as_json: bool = False, console: Console | None = None) -> None:
        """Print one snapshot (no live refresh)."""
        import json

        console = console or self.console
        data = data or self.snapshot()
        if as_json:
            console.print_json(json.dumps(_jsonable(data), default=str))
            return
        console.print(self.render(data))

    def run_live(self, *, interval: float | None = None, iterations: int | None = None,
                 range_label: str | None = None, console: Console | None = None
                 ) -> None:
        """Auto-refreshing view until Ctrl-C.

        Ctrl-C is the expected exit path, so it is caught and turned into a
        clean shutdown rather than a traceback.
        """
        from rich.live import Live

        console = console or self.console
        refresh = max(1.0, float(interval or self.config.dashboard.refresh_seconds))
        count = 0
        try:
            with Live(
                self.render(self.snapshot(range_label)),
                console=console,
                refresh_per_second=max(1, int(1 / min(refresh, 1.0))),
                screen=False,
                transient=False,
            ) as live:
                while True:
                    time.sleep(refresh)
                    live.update(self.render(self.snapshot(range_label)))
                    count += 1
                    if iterations is not None and count >= iterations:
                        break
        except KeyboardInterrupt:
            console.print("\n[dim]Dashboard stopped.[/dim]")


def _jsonable(value: Any) -> Any:
    """Coerce event objects and datetimes into JSON-safe values."""
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (int, float, str, bool)) or value is None:
        return value
    if hasattr(value, "to_dict"):
        return _jsonable(value.to_dict())
    return str(value)