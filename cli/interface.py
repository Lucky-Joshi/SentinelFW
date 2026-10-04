"""Command-line interface.

Interaction contract (the important part)
-----------------------------------------
No mutating command ever touches the kernel as a side effect of *recording* a
change. ``block-ip`` writes the rule to ``rules.yaml`` and tells you the exact
command to activate it. ``firewall apply`` is the only command that sends
anything to nftables, and it always:

1. requires root,
2. prints the full nft script it will run,
3. takes a backup of the live ruleset,
4. asks for confirmation unless ``--yes``,
5. verifies the result afterwards.

That split means a typo cannot reach the kernel, and a pasted command can be
read before it runs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cli.console import (
    confirm,
    error,
    make_console,
    print_alert_table,
    print_kv,
    print_rule_table,
    show_change_preview,
    success,
    warn,
)
from config import AppConfig, load_config, save_config, write_template
from dashboard.terminal import Dashboard
from exceptions import (
    ExitCode,
    SentinelFWError,
    UserAbortError,
)
from firewall import BackupManager, NFTManager, Rule, RuleStore, is_root
from firewall.rules import RuleAction, RuleKind, local_addresses
from logsetup import get_logger, setup_logging
from monitor.database import Database, FirewallEvent
from monitor.detector import DetectionEngine
from monitor.explain import explain_attack, explain_event, explain_port
from monitor.log_parser import FileLogSource, build_source
from monitor.monitor import LogCollector, make_collector
from monitor.reports import ReportGenerator
from utils import human_int, mask_ip, now_iso, period_start, truncate
from version import APP_NAME, SCHEMA_VERSION, __version__

log = get_logger("cli")

__all__ = ["main", "build_parser"]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
#: Global flags, mirrored onto every leaf subcommand so that they may be given
#: either before or after the command (``--json firewall list`` and
#: ``firewall list --json`` both work, which is what people actually type).
_GLOBAL_FLAGS: tuple[tuple[str, dict[str, Any]], ...] = (
    ("--config", {"metavar": "PATH", "default": argparse.SUPPRESS,
                  "help": "use an alternative config.yaml"}),
    ("--dry-run", {"action": "store_true", "default": argparse.SUPPRESS,
                   "help": "print what would happen; execute nothing"}),
    ("-y", {"dest": "yes", "action": "store_true", "default": argparse.SUPPRESS,
            "help": "skip confirmation prompts (scripting)"}),
    ("--yes", {"action": "store_true", "default": argparse.SUPPRESS,
               "help": "alias of -y"}),
    ("--no-color", {"action": "store_true", "default": argparse.SUPPRESS,
                    "help": "disable colour"}),
    ("--json", {"action": "store_true", "default": argparse.SUPPRESS,
                "help": "machine readable output where supported"}),
    ("-v", {"dest": "verbose", "action": "store_true", "default": argparse.SUPPRESS,
            "help": "log INFO to stderr"}),
    ("--verbose", {"action": "store_true", "default": argparse.SUPPRESS,
                   "help": "alias of -v"}),
    ("--debug", {"action": "store_true", "default": argparse.SUPPRESS,
                 "help": "log DEBUG to stderr, including every command"}),
)


def _mirror_global_flags(parser: argparse.ArgumentParser) -> None:
    """Recursively add :data:`_GLOBAL_FLAGS` to every subcommand.

    Both intermediate groups (``firewall``) and leaves get the flags, so
    ``firewall --dry-run block-ip 1.2.3.4`` and
    ``firewall block-ip 1.2.3.4 --dry-run`` both work, as does the leading
    ``--dry-run firewall ...`` form. ``argparse.SUPPRESS`` defaults are
    essential: without them the subparser would overwrite whatever the parent
    already parsed with its own default, silently discarding an earlier flag.
    """
    existing = parser._option_string_actions  # noqa: SLF001
    group = None
    for flag, kwargs in _GLOBAL_FLAGS:
        names = (flag,) if flag in ("-y", "-v") else (flag, flag.lstrip("-"))
        if any(name in existing for name in names):
            continue
        if group is None:
            group = parser.add_argument_group(
                "global options (also accepted before the command)")
        group.add_argument(flag, **{**kwargs, "help": kwargs.get("help", "")})

    for action in parser._actions:  # noqa: SLF001
        if isinstance(action, argparse._SubParsersAction):
            for child in action.choices.values():
                _mirror_global_flags(child)


def build_parser() -> argparse.ArgumentParser:
    """Construct the full argument parser (also used to render help)."""
    parser = argparse.ArgumentParser(
        prog="sentinelfw",
        description=(
            f"{APP_NAME} - local nftables firewall manager and security monitor.\n"
            "Every firewall change is previewed, backed up and confirmed."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Typical first session:\n"
            "  sentinelfw doctor                    check this machine\n"
            "  sentinelfw firewall block-ip 1.2.3.4  record a block rule\n"
            "  sentinelfw firewall preview           see the exact nft script\n"
            "  sudo sentinelfw firewall apply        install it into the kernel\n"
            "  sentinelfw monitor start --demo       watch synthetic traffic\n"
            "  sentinelfw dashboard                  watch it live\n"
        ),
    )
    parser.add_argument("--version", action="version",
                        version=f"{APP_NAME} {__version__} "
                                f"(db schema v{SCHEMA_VERSION})")
    parser.add_argument("--config", metavar="PATH",
                        help="use an alternative config.yaml")
    parser.add_argument("--dry-run", action="store_true",
                        help="print what would happen; execute nothing")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="skip confirmation prompts (scripting)")
    parser.add_argument("--no-color", action="store_true", help="disable colour")
    parser.add_argument("--json", action="store_true",
                        help="machine readable output where supported")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="log INFO to stderr")
    parser.add_argument("--debug", action="store_true",
                        help="log DEBUG to stderr, including every command")

    sub = parser.add_subparsers(dest="group", metavar="<group>")

    # ---------------- firewall ----------------
    fw = sub.add_parser("firewall", help="manage nftables rules",
                        description="Manage the nftables ruleset SentinelFW owns.")
    fw_sub = fw.add_subparsers(dest="command", metavar="<action>")

    p = fw_sub.add_parser("list", help="show configured rules")
    p.add_argument("--live", action="store_true",
                   help="also read the rules currently loaded in the kernel")
    p.add_argument("--ids", action="store_true", help="show only ids")

    p = fw_sub.add_parser("status", help="backend availability and rule sync")
    p.add_argument("--json", action="store_true", help="machine readable output")

    p = fw_sub.add_parser("block-ip", help="block an IP address or network")
    p.add_argument("address", help="e.g. 45.33.22.1 or 10.0.0.0/24")
    p.add_argument("-r", "--reason", default="", help="why (stored as the comment)")
    p.add_argument("--apply", action="store_true",
                   help="also install the ruleset now (asks to confirm)")

    p = fw_sub.add_parser("allow-ip", help="allow an IP address or network")
    p.add_argument("address")
    p.add_argument("-r", "--reason", default="")
    p.add_argument("--apply", action="store_true")

    p = fw_sub.add_parser("block-port", help="block a TCP/UDP port")
    p.add_argument("port", type=str)
    p.add_argument("-p", "--protocol", default="any", choices=["tcp", "udp", "any", "icmp"])
    p.add_argument("-r", "--reason", default="")
    p.add_argument("--apply", action="store_true")

    p = fw_sub.add_parser("allow-port", help="allow a TCP/UDP port")
    p.add_argument("port", type=str)
    p.add_argument("-p", "--protocol", default="any", choices=["tcp", "udp", "any", "icmp"])
    p.add_argument("-r", "--reason", default="")
    p.add_argument("--apply", action="store_true")

    p = fw_sub.add_parser("remove", help="delete a rule by id")
    p.add_argument("id", type=int)
    p.add_argument("--apply", action="store_true")

    p = fw_sub.add_parser("enable", help="enable a disabled rule")
    p.add_argument("id", type=int)

    p = fw_sub.add_parser("disable", help="disable a rule without deleting it")
    p.add_argument("id", type=int)
    p.add_argument("--apply", action="store_true")

    p = fw_sub.add_parser("preview", help="print the nft script without running it")
    p.add_argument("--no-logging", action="store_true",
                   help="show what it looks like with logging disabled")

    fw_sub.add_parser("validate", help="ask nft to check the script (needs root)")

    p = fw_sub.add_parser("apply", help="install rules into the kernel (needs root)")
    p.add_argument("--no-backup", action="store_true",
                   help="skip the pre-apply ruleset backup (not recommended)")

    p = fw_sub.add_parser("flush", help="delete all SentinelFW rules")
    p.add_argument("--apply", action="store_true")

    fw_sub.add_parser("backup", help="snapshot the live ruleset (needs root)")

    p = fw_sub.add_parser("backups", help="list available backups")
    p.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"),
                   help="diff two snapshots instead of listing")

    p = fw_sub.add_parser("restore", help="restore a snapshot (needs root)")
    p.add_argument("name", help="backup file name, or its timestamp")

    p = fw_sub.add_parser("enable-logging", help="log every incoming SYN (noisy)")
    p.add_argument("--off", action="store_true", help="remove the SYN logging rule")

    # ---------------- monitor ----------------
    mon = sub.add_parser("monitor", help="collect and analyse firewall logs",
                         description="Collect kernel log events into SQLite.")
    mon_sub = mon.add_subparsers(dest="command", metavar="<action>")

    p = mon_sub.add_parser("start", help="follow logs and detect anomalies")
    p.add_argument("--source", choices=["journal", "file", "demo", "stdin"],
                   help="override monitoring.source")
    p.add_argument("--file", action="append", default=[],
                   help="log file to follow (repeatable)")
    p.add_argument("--demo", action="store_true",
                   help="generate synthetic traffic (no root, no real attacker)")
    p.add_argument("--seconds", type=float, default=None,
                   help="stop after this many seconds")
    p.add_argument("--events", type=int, default=None,
                   help="stop after this many events")
    p.add_argument("--speed", type=float, default=1.0,
                   help="demo speed multiplier")
    p.add_argument("--no-detect", action="store_true", help="store events only")

    p = mon_sub.add_parser("poll", help="one pass over buffered logs, then exit")
    p.add_argument("--source", choices=["journal", "file", "stdin"])
    p.add_argument("--file", default=None)

    p = mon_sub.add_parser("ingest", help="import an existing log file")
    p.add_argument("path")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--from-start", action="store_true",
                   help="read the whole file instead of only new lines")

    p = mon_sub.add_parser("demo", help="run synthetic traffic for N seconds")
    p.add_argument("--seconds", type=float, default=30.0)
    p.add_argument("--events", type=int, default=None)
    p.add_argument("--speed", type=float, default=1.0)

    mon_sub.add_parser("status", help="database and parser statistics")
    p = mon_sub.add_parser("detect", help="run one detection cycle now")
    p.add_argument("--dry-run", action="store_true",
                   help="analyse but do not store alerts")

    p = mon_sub.add_parser("prune", help="delete events older than a period")
    p.add_argument("--period", default=None, help="e.g. 30d (default: retention_days)")
    p.add_argument("--all", action="store_true", help="delete every event")

    mon_sub.add_parser("vacuum", help="compact the database file")

    p = mon_sub.add_parser("reset", help="delete all events and alerts")
    p.add_argument("--yes", action="store_true", help="skip confirmation")

    # ---------------- alerts ----------------
    al = sub.add_parser("alerts", help="inspect detected threats")
    al_sub = al.add_subparsers(dest="command", metavar="<action>")

    p = al_sub.add_parser("list", help="list alerts")
    p.add_argument("--period", default=None, help="time range (default 24h)")
    p.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"],
                   help="minimum severity")
    p.add_argument("--kind", help="filter by detector kind")
    p.add_argument("--explain", action="store_true",
                   help="show the full explanation and recommended actions")
    p.add_argument("--all", action="store_true", help="include acknowledged")
    p.add_argument("--json", action="store_true")

    p = al_sub.add_parser("show", help="explain one alert in full")
    p.add_argument("id", type=int)

    p = al_sub.add_parser("ack", help="acknowledge an alert")
    p.add_argument("id", type=int)

    # ---------------- report ----------------
    rep = sub.add_parser("report", help="generate security reports")
    rep_sub = rep.add_subparsers(dest="command", metavar="<action>")

    p = rep_sub.add_parser("generate", help="build a report for a time window")
    p.add_argument("--period", default=None, help="15m, 1h, 6h, 12h, 24h, 7d, 30d, today")
    p.add_argument("--format", dest="fmt", default="text",
                   choices=["text", "markdown", "json"])
    p.add_argument("--save", action="store_true", help="also write to reports/")
    p.add_argument("--brief", action="store_true", help="one-line summary only")

    p = rep_sub.add_parser("list", help="list saved reports")
    p.add_argument("--limit", type=int, default=20)

    # ---------------- dashboard ----------------
    dash = sub.add_parser("dashboard", help="live terminal dashboard")
    dash.add_argument("--range", dest="range_label", default=None,
                      help="time range (default from config)")
    dash.add_argument("--once", action="store_true", help="print once, do not refresh")
    dash.add_argument("--json", action="store_true", help="dump the snapshot as JSON")
    dash.add_argument("--iterations", type=int, default=None,
                      help="stop after N refreshes (testing)")

    # ---------------- explain ----------------
    exp = sub.add_parser("explain", help="explain ports, attacks or stored events")
    exp_sub = exp.add_subparsers(dest="command", metavar="<subject>")

    p = exp_sub.add_parser("port", help="what is this port and is it risky?")
    p.add_argument("port", type=int)

    p = exp_sub.add_parser("attack", help="what does this detection mean?")
    p.add_argument("kind", nargs="?", default=None,
                   help="port_scan, brute_force, connection_spike, "
                        "repeated_block, sensitive_port")
    p.add_argument("--list", action="store_true", help="list all known kinds")

    p = exp_sub.add_parser("event", help="explain a stored event")
    p.add_argument("id", type=int, nargs="?", default=None,
                   help="event id (see 'monitor status')")
    p.add_argument("--last", type=int, default=None, metavar="N",
                   help="explain the Nth most recent event instead of an id")

    # ---------------- database ----------------
    dbp = sub.add_parser("db", help="database maintenance")
    db_sub = dbp.add_subparsers(dest="command", metavar="<action>")

    p = db_sub.add_parser("stats", help="table sizes and totals")
    p.add_argument("--period", default=None)

    p = db_sub.add_parser("export", help="export events as JSON or CSV")
    p.add_argument("--format", dest="fmt", default="json", choices=["json", "csv"])
    p.add_argument("--period", default=None)
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--output", default=None, help="write to a file")

    # ---------------- config ----------------
    cfgp = sub.add_parser("config", help="configuration management")
    cfg_sub = cfgp.add_subparsers(dest="command", metavar="<action>")

    p = cfg_sub.add_parser("init", help="create config.yaml")
    p.add_argument("--force", action="store_true", help="overwrite an existing file")

    cfg_sub.add_parser("show", help="print the effective configuration")
    cfg_sub.add_parser("path", help="print config and state file locations")

    cfg_sub.add_parser("check", help="validate the configuration")
    p = cfg_sub.add_parser("harden", help="set 0600 on config and rules files")
    p.add_argument("--apply", action="store_true")

    sub.add_parser("doctor", help="check this machine for problems")

    _mirror_global_flags(parser)
    return parser


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
class SentinelCLI:
    """Executes parsed arguments against the firewall and monitoring planes."""

    def __init__(self, argv: Sequence[str] | None = None) -> None:
        self.argv = list(argv) if argv is not None else sys.argv[1:]
        self.parser = build_parser()
        self.args = self.parser.parse_args(self.argv)
        self.console = make_console(
            no_color=self.args.no_color or bool(os.environ.get("NO_COLOR")),
            json_mode=self.args.json,
        )
        self.config: AppConfig | None = None
        self._manager: NFTManager | None = None
        self._store: RuleStore | None = None
        self._db: Database | None = None

    # -- lazily built components -----------------------------------------
    @property
    def cfg(self) -> AppConfig:
        if self.config is None:
            self.config = load_config(self.args.config)
        return self.config

    @property
    def manager(self) -> NFTManager:
        if self._manager is None:
            self._manager = NFTManager(self.cfg, dry_run=self.args.dry_run)
        return self._manager

    @property
    def store(self) -> RuleStore:
        if self._store is None:
            self._store = RuleStore(self.cfg.state_file).load()
        return self._store

    @property
    def db(self) -> Database:
        if self._db is None:
            self._db = Database(self.cfg.database_path,
                                busy_timeout_ms=self.cfg.database.busy_timeout_ms)
        return self._db

    @property
    def dry_run(self) -> bool:
        return bool(self.args.dry_run)

    # -- output helpers ---------------------------------------------------
    def emit(self, payload: dict[str, Any], renderer: Any = None) -> None:
        """Print JSON when ``--json`` is set, otherwise call the renderer."""
        if self.args.json:
            self.console.print_json(json.dumps(payload, default=str))
        elif renderer is not None:
            renderer(payload)

    # ------------------------------------------------------------------
    def run(self) -> int:
        """Dispatch to the requested subcommand."""
        group = getattr(self.args, "group", None)
        command = getattr(self.args, "command", None)

        # Logging must be configured first so every later step is auditable.
        setup_logging(
            self.cfg.log_file,
            level=self.cfg.logging.level,
            verbose=self.args.verbose,
            debug=self.args.debug,
        )
        log.info("%s %s starting: %s", APP_NAME, __version__, " ".join(self.argv) or "(no args)")

        if group is None:
            self.parser.print_help()
            return ExitCode.OK

        handlers = {
            "firewall": self._firewall,
            "monitor": self._monitor,
            "alerts": self._alerts,
            "report": self._report,
            "dashboard": self._dashboard,
            "explain": self._explain,
            "db": self._db_maintenance,
            "config": self._config,
            "doctor": self._doctor,
        }
        handler = handlers.get(group)
        if handler is None:  # pragma: no cover - argparse rejects these first
            error(self.console, f"Unknown command group: {group}")
            return ExitCode.USAGE

        # Groups that take arguments directly instead of a sub-command.
        leaf_groups = {"doctor", "dashboard"}
        if command is None and group not in leaf_groups:
            # Print the sub-parser help rather than doing nothing.
            subparser = {
                "firewall": "firewall", "monitor": "monitor", "alerts": "alerts",
                "report": "report", "explain": "explain", "db": "db",
                "config": "config",
            }.get(group)
            self._print_group_help(subparser)
            return ExitCode.OK

        try:
            return int(handler() or ExitCode.OK)
        except UserAbortError:
            self.console.print("[yellow]Aborted - nothing was changed.[/yellow]")
            return ExitCode.ABORTED
        except SentinelFWError as exc:
            error(self.console, exc.message, exc.hint)
            log.debug("Handled error: %s", exc)
            return exc.exit_code
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Interrupted.[/yellow]")
            return ExitCode.ABORTED
        except BrokenPipeError:  # e.g. `sentinelfw dashboard | head`
            return ExitCode.OK

    def _print_group_help(self, name: str | None) -> None:
        if not name:  # pragma: no cover
            self.parser.print_help()
            return
        for action in self.parser._subparsers._group_actions:  # noqa: SLF001
            choices = action.choices
            if name in choices:
                choices[name].print_help()
                return

    # ==================================================================
    # firewall
    # ==================================================================
    def _firewall(self) -> int:
        command = self.args.command
        handlers = {
            "list": self._fw_list,
            "status": self._fw_status,
            "block-ip": lambda: self._fw_add_ip(block=True),
            "allow-ip": lambda: self._fw_add_ip(block=False),
            "block-port": lambda: self._fw_add_port(block=True),
            "allow-port": lambda: self._fw_add_port(block=False),
            "remove": self._fw_remove,
            "enable": lambda: self._fw_toggle(enable=True),
            "disable": lambda: self._fw_toggle(enable=False),
            "preview": self._fw_preview,
            "validate": self._fw_validate,
            "apply": self._fw_apply,
            "flush": self._fw_flush,
            "backup": self._fw_backup,
            "backups": self._fw_backups,
            "restore": self._fw_restore,
            "enable-logging": self._fw_syn_logging,
        }
        handler = handlers.get(command)
        if handler is None:
            error(self.console, f"Unknown firewall action: {command}")
            return ExitCode.USAGE
        return handler()

    # -- listing ----------------------------------------------------------
    def _fw_list(self) -> int:
        rules = self.store.sorted_rules()
        if self.args.ids:
            for rule in rules:
                self.console.print(f"{rule.id}\t{rule.describe()}")
            return ExitCode.OK

        print_rule_table(self.console, rules,
                         title=f"SentinelFW rules ({len(rules)}) "
                               f"[{self.cfg.chain_ref}]")

        if self.args.live:
            try:
                live = self.manager.list_managed_rules(require_root=True)
                table = Table(title=f"Live in kernel ({len(live)} rules)",
                              title_style="bold", border_style="grey37")
                table.add_column("Handle", justify="right")
                table.add_column("Expression", overflow="ellipsis")
                for item in live:
                    table.add_row(str(item.handle), item.text)
                self.console.print(table)
            except SentinelFWError as exc:
                warn(self.console, f"Could not read live rules: {exc.message}")
        else:
            self.console.print(
                "[dim]Use --live to compare against the rules loaded in the kernel.[/dim]"
            )

        if rules:
            self.console.print(
                f"[dim]These rules are stored in {self.cfg.state_file}.\n"
                f"They affect the kernel only after: sudo sentinelfw firewall apply[/dim]"
            )
        return ExitCode.OK

    def _fw_status(self) -> int:
        status = self.manager.status(require_root=is_root())
        diff = None
        try:
            diff = self.manager.diff_against_live(self.store.sorted_rules())
        except SentinelFWError as exc:
            log.debug("Diff unavailable: %s", exc)

        payload = {
            "nft_available": status.available,
            "nft_version": status.version,
            "table": f"{self.cfg.firewall.family} {self.cfg.firewall.table}",
            "table_installed": status.table_exists,
            "chain_hook": status.hook or self.cfg.firewall.hook,
            "chain_priority": status.priority if status.priority is not None
            else self.cfg.firewall.priority,
            "chain_policy": status.policy or self.cfg.firewall.policy,
            "logging": status.log_enabled,
            "live_rules": status.rule_count,
            "stored_rules": len(self.store),
            "in_sync": diff["in_sync"] if diff else None,
            "detail": status.detail,
            "running_as_root": is_root(),
            "config": str(self.cfg.config_path),
            "state_file": str(self.cfg.state_file),
            "database": str(self.cfg.database_path),
        }
        self.emit(payload, self._render_fw_status)

        if diff and not diff["in_sync"] and not status.table_exists:
            self.console.print(
                "\n[yellow]Stored rules are not installed in the kernel.[/yellow]\n"
                "Preview:  sentinelfw firewall preview\n"
                "Install:  sudo sentinelfw firewall apply"
            )
        elif diff and not diff["in_sync"]:
            self.console.print(
                "\n[yellow]Kernel and rules.yaml differ "
                f"({diff['live']} live vs {diff['desired']} desired).[/yellow]\n"
                "Re-apply with: sudo sentinelfw firewall apply"
            )
        return ExitCode.OK

    def _render_fw_status(self, payload: dict[str, Any]) -> None:
        def styled(text: str, style: str) -> Text:
            return Text(text, style=style)

        if payload["nft_available"]:
            backend = styled(str(payload["nft_version"]), "green")
        else:
            backend = Text("nft not found  (sudo apt install nftables)", style="red")
        installed = (styled("installed", "green") if payload["table_installed"]
                     else styled("not installed", "yellow"))
        sync = payload["in_sync"]
        sync_text = (styled("in sync", "green") if sync else
                     styled("out of sync", "yellow") if sync is not None
                     else styled("unknown (needs root)", "dim"))
        table_cell = Text()
        table_cell.append(str(payload["table"]))
        table_cell.append("  ")
        table_cell.append_text(installed)
        rules_cell = Text()
        rules_cell.append(f"{payload['stored_rules']} stored / "
                          f"{payload['live_rules']} live  (")
        rules_cell.append_text(sync_text)
        rules_cell.append(")")
        print_kv(
            self.console,
            [
                ("Backend", backend),
                ("Managed table", table_cell),
                ("Chain", f"hook {payload['chain_hook']} "
                          f"priority {payload['chain_priority']} "
                          f"policy {payload['chain_policy']}"),
                ("Logging", styled("enabled", "green") if payload["logging"]
                 else styled("disabled", "dim")),
                ("Rules", rules_cell),
                ("Privileges", styled("root", "green") if payload["running_as_root"]
                 else styled("unprivileged", "yellow")),
                ("Config", payload["config"]),
                ("State file", payload["state_file"]),
                ("Database", payload["database"]),
            ],
            title="Firewall status",
        )
        if payload.get("detail"):
            self.console.print(f"[dim]{payload['detail']}[/dim]")

    # -- adding rules -----------------------------------------------------
    def _local_address_warning(self, address: str) -> str | None:
        """Warn if the operator is about to block one of their own addresses."""
        try:
            if address in local_addresses():
                return (f"{address} is an address of THIS machine. Blocking it may "
                        f"cut off your own access.")
        except Exception:  # pragma: no cover - best effort
            return None
        return None

    def _fw_add_ip(self, *, block: bool) -> int:
        address = self.args.address
        kind = RuleKind.IP_BLOCK if block else RuleKind.IP_ALLOW
        action = RuleAction.DROP if block else RuleAction.ACCEPT
        # Validation happens in Rule(); an invalid address raises here.
        rule = Rule(kind=kind, action=action, value=address,
                    comment=self.args.reason or ("blocked by operator" if block
                                                 else "trusted by operator"))
        return self._record_and_maybe_apply(rule, address_display=rule.value or address)

    def _fw_add_port(self, *, block: bool) -> int:
        # Let Rule() own validation so bad input is a clean message, not a
        # ValueError traceback from int().
        raw = self.args.port
        rule = Rule(
            kind=RuleKind.PORT_BLOCK if block else RuleKind.PORT_ALLOW,
            action=action_of(block),
            value=str(raw),
            protocol=self.args.protocol,
            comment=self.args.reason or (f"port {raw} blocked" if block
                                         else f"port {raw} allowed"),
        )
        return self._record_and_maybe_apply(rule, address_display=rule.target)

    def _record_and_maybe_apply(self, rule: Rule, *, address_display: str) -> int:
        """Preview, confirm, store, and optionally install a new rule."""
        verb = "Block" if rule.action == RuleAction.DROP else "Allow"
        effect = (
            f"Inbound packets from {address_display} are dropped before they reach "
            f"any service."
            if rule.action == RuleAction.DROP
            else f"Inbound packets from {address_display} are accepted, and this "
                 f"rule takes priority over any SentinelFW block rule."
        )
        warnings: list[str] = []
        if rule.action == RuleAction.DROP:
            local_warning = self._local_address_warning(str(rule.value))
            if local_warning:
                warnings.append(local_warning)

        # Build the script that *would* result from this rule being added.
        preview_rules = sorted([*self.store.rules, rule], key=lambda r: r.sort_key)
        script = self.manager.build_rules_script(preview_rules)

        show_change_preview(
            self.console,
            action=f"{verb} {'IP address' if rule.is_ip_rule else 'port'}",
            target=address_display,
            effect=effect,
            commands=("stored in " + str(self.cfg.state_file) + "\n"
                      + "(not applied to the kernel yet)") + "\n\n"
                     + "[after 'firewall apply']\n" + script,
            reason=rule.comment or None,
            warnings=warnings,
            undo=f"sentinelfw firewall remove <id>   (after it is created)",
            dry_run=self.dry_run,
        )

        if self.dry_run:
            return ExitCode.OK

        if not confirm(self.console,
                       f"Record this {verb.lower()} rule in {self.cfg.state_file.name}?",
                       assume_yes=self.args.yes):
            raise UserAbortError("Declined by operator.")

        created = self.store.add(rule, allow_duplicate=self.args.yes,
                                 allow_contradiction=self.args.yes)
        success(self.console, f"Rule #{created.id} saved to {self.cfg.state_file}")
        self.console.print(
            f"[dim]Not active in the kernel yet. Install it with:[/dim]\n"
            f"[bold]sudo sentinelfw firewall apply[/bold]"
        )

        if self.args.apply:
            return self._apply(assume_yes=True)
        return ExitCode.OK

    # -- removing / toggling ----------------------------------------------
    def _fw_remove(self) -> int:
        rule = self.store.get(self.args.id)
        if rule is None:
            error(self.console, f"No rule with id {self.args.id}.",
                  "Run: sentinelfw firewall list")
            return ExitCode.VALIDATION

        show_change_preview(
            self.console,
            action="Remove rule",
            target=f"#{rule.id}  {rule.describe()}",
            effect="The rule is deleted from rules.yaml and stops being applied on "
                   "the next apply. It stays active in the kernel until then.",
            commands=f"edit {self.cfg.state_file}\n"
                     f"then: sudo sentinelfw firewall apply",
            warnings=[],
            undo="Restore it with: sentinelfw firewall backup restore, or re-add "
                 "the rule by hand.",
            dry_run=self.dry_run,
        )
        if self.dry_run:
            return ExitCode.OK
        if not confirm(self.console, f"Delete rule #{rule.id}?",
                       assume_yes=self.args.yes):
            raise UserAbortError("Declined by operator.")
        self.store.remove(self.args.id)
        success(self.console, f"Rule #{rule.id} deleted from {self.cfg.state_file}")
        if self.args.apply:
            return self._apply(assume_yes=True)
        return ExitCode.OK

    def _fw_toggle(self, *, enable: bool) -> int:
        rule = self.store.get(self.args.id)
        if rule is None:
            error(self.console, f"No rule with id {self.args.id}.")
            return ExitCode.VALIDATION
        self.store.set_enabled(self.args.id, enable)
        success(self.console,
                f"Rule #{rule.id} {'enabled' if enable else 'disabled'} "
                f"(change active after 'firewall apply')")
        if getattr(self.args, "apply", False):
            return self._apply(assume_yes=True)
        return ExitCode.OK

    def _fw_flush(self) -> int:
        rules = self.store.rules
        if not rules:
            success(self.console, "No SentinelFW rules to remove.")
            return ExitCode.OK

        show_change_preview(
            self.console,
            action="Remove every SentinelFW rule",
            target=f"{len(rules)} rule(s) from {self.cfg.state_file}",
            effect="SentinelFW stops managing all rules. Traffic previously blocked "
                   "by SentinelFW will be permitted again after the next apply. "
                   "Rules belonging to other tools are untouched.",
            commands=f"remove all rules from {self.cfg.state_file}\n"
                     f"then: sudo sentinelfw firewall apply",
            warnings=["Check that you are not relying on these blocks for "
                      "protection before continuing."],
            undo="Restore from a backup: sentinelfw firewall backups, then restore.",
            dry_run=self.dry_run,
        )
        if self.dry_run:
            return ExitCode.OK
        if not confirm(self.console, f"Delete all {len(rules)} rules?",
                       assume_yes=self.args.yes):
            raise UserAbortError("Declined by operator.")
        self.store.replace_all([])
        success(self.console, "All SentinelFW rules removed from rules.yaml.")
        if self.args.apply:
            return self._apply(assume_yes=True)
        return ExitCode.OK

    # -- preview / validate / apply ---------------------------------------
    def _fw_preview(self) -> int:
        rules = self.store.sorted_rules()
        if self.args.no_logging:
            # Temporarily render without the log prefix for comparison.
            original = self.cfg.firewall.log_enabled
            self.cfg.firewall.log_enabled = False
            script = self.manager.build_full_script(rules)
            self.cfg.firewall.log_enabled = original
        else:
            script = self.manager.build_full_script(rules)

        body = Text()
        body.append(f"Table    : {self.cfg.table_ref}\n", style="bold")
        body.append(f"Chain    : {self.cfg.chain_ref}\n", style="bold")
        body.append(f"Rules    : {len(rules)} stored, "
                    f"{len([r for r in rules if r.enabled])} enabled\n", style="bold")
        body.append("\nThis is the exact script that 'firewall apply' feeds to "
                    "'nft -f -' in a single atomic transaction:\n\n", style="dim")
        for line in script.splitlines():
            body.append(f"  {line}\n", style="yellow")
        self.console.print(Panel(body, title="nft script preview",
                                 title_align="left", border_style="yellow"))

        if self.args.json:
            self.console.print_json(json.dumps({"script": script,
                                                "rules": len(rules)}))
        else:
            self.console.print(
                "[dim]Nothing above has been executed. To install it:[/dim]\n"
                "[bold]sudo sentinelfw firewall apply[/bold]"
            )
        return ExitCode.OK

    def _fw_validate(self) -> int:
        rules = self.store.sorted_rules()
        result = self.manager.validate(rules)
        if result.get("dry_run"):
            self.console.print("[yellow]--dry-run: validation skipped.[/yellow]")
            return ExitCode.OK
        if result.get("valid"):
            success(self.console, "The kernel accepted the ruleset syntax (nft -c).")
            self.console.print("[dim]This checks syntax only, not that the rules "
                               "are the right ones for you.[/dim]")
            return ExitCode.OK
        error(self.console, "nftables rejected the ruleset.",
              result.get("error", "unknown error"))
        return ExitCode.VALIDATION

    def _fw_apply(self) -> int:
        rules = self.store.sorted_rules()
        script = self.manager.build_full_script(rules)

        body = Text()
        body.append(f"Table : {self.cfg.table_ref}\n", style="bold")
        body.append(f"Chain : hook {self.cfg.firewall.hook}, priority "
                    f"{self.cfg.firewall.priority}, policy {self.cfg.firewall.policy}\n",
                    style="bold")
        body.append(f"Rules : {len([r for r in rules if r.enabled])} to install\n\n",
                    style="bold")
        body.append("Backup : the current ruleset is snapshotted first "
                    f"(dir {self.cfg.backup_dir})\n\n", style="dim")
        body.append("Script that will be sent to 'nft -f -':\n", style="dim")
        for line in script.splitlines() or ["(flush only - no rules defined)"]:
            body.append(f"  {line}\n", style="yellow")

        self.console.print(Panel(body, title="APPLYING FIREWALL RULES",
                                 title_align="left", border_style="red"))
        if self.dry_run:
            self.console.print("[yellow]DRY RUN - nothing was applied.[/yellow]")
            return ExitCode.OK

        if not is_root():
            error(self.console, "Root privileges are required to modify nftables.",
                  "Re-run with sudo: sudo sentinelfw firewall apply")
            return ExitCode.PERMISSION

        if not confirm(self.console, "Send this ruleset to the kernel?",
                       assume_yes=self.args.yes):
            raise UserAbortError("Declined by operator.")

        report = self.manager.apply_rules(
            rules, backup=not self.args.no_backup, verify=True
        )
        if report.get("backup"):
            self.console.print(f"[dim]Backup: {report['backup']}[/dim]")
        success(self.console,
                f"Applied {report['rule_count']} rule(s) to {self.cfg.table_ref}.")
        if report.get("verified") is False:
            warn(self.console,
                 f"Post-apply check mismatch: {report.get('live_rules')} live rule(s), "
                 f"{report.get('expected_rules')} expected. "
                 f"Inspect with: sudo nft list table {self.cfg.table_ref}")
        elif report.get("verified"):
            self.console.print(f"[dim]Verified: {report.get('live_rules')} rule(s) "
                               f"present in the kernel.[/dim]")
        return ExitCode.OK

    def _apply(self, *, assume_yes: bool) -> int:
        """Shared apply path used by --apply on other commands."""
        self.args.dry_run = False
        self.args.yes = assume_yes
        return self._fw_apply()

    # -- backups ----------------------------------------------------------
    def _backup_manager(self) -> BackupManager:
        return BackupManager(self.cfg.backup_dir, keep=self.cfg.firewall.backup_keep,
                             config=self.cfg)

    def _fw_backup(self) -> int:
        backups = self._backup_manager()
        if self.dry_run:
            self.console.print("[yellow]DRY RUN - no snapshot taken.[/yellow]")
            return ExitCode.OK
        path = backups.create(note="manual")
        if path is None:
            error(self.console, "Could not create a backup.",
                  "Reading the live ruleset requires root.")
            return ExitCode.PERMISSION
        success(self.console, f"Ruleset snapshot: {path}")
        return ExitCode.OK

    def _fw_backups(self) -> int:
        backups = self._backup_manager()
        if self.args.diff:
            diff = backups.diff(self.args.diff[0], self.args.diff[1])
            self.console.print(diff if diff.strip() else "(no differences)")
            return ExitCode.OK

        entries = backups.list()
        table = Table(title=f"Ruleset backups ({len(entries)})", title_style="bold",
                      border_style="grey37")
        table.add_column("File", overflow="ellipsis")
        table.add_column("Reason")
        table.add_column("Size", justify="right")
        table.add_column("Modified")
        for entry in entries:
            table.add_row(entry.name, entry.tag, human_int(entry.size // 1024) + " KiB",
                          entry.modified)
        if not entries:
            table.add_row("[dim]none[/dim]", "", "", "")
        self.console.print(table)
        self.console.print(
            f"[dim]Total {backups.total_size() / 1024:.0f} KiB in {backups.dir}. "
            f"Retention keeps the newest {self.cfg.firewall.backup_keep}.[/dim]"
        )
        return ExitCode.OK

    def _fw_restore(self) -> int:
        backups = self._backup_manager()
        commands = backups.preview_restore(self.args.name)
        show_change_preview(
            self.console,
            action="Restore ruleset from backup",
            target=self.args.name,
            effect="The ENTIRE live ruleset is flushed and replaced with the "
                   "snapshot. This affects tables owned by other tools too, and "
                   "there is no undo other than restoring a newer backup.",
            commands=commands,
            warnings=[
                "Step 1 (flush ruleset) removes every nftables table, including "
                "docker/ufw/libvirt tables that SentinelFW does not manage.",
                "If you are connected over SSH, keep this session open until you "
                "have verified connectivity.",
            ],
            undo=f"Restore a different snapshot, e.g.: "
                 f"sentinelfw firewall restore <newer-backup>",
            dry_run=self.dry_run,
        )
        if self.dry_run:
            return ExitCode.OK
        if not confirm(self.console, "Flush and restore the full ruleset?",
                       assume_yes=self.args.yes):
            raise UserAbortError("Declined by operator.")
        info = backups.restore(self.args.name, dry_run=False)
        success(self.console, f"Ruleset restored from {info['path']}")
        self.console.print(
            f"[dim]Pre-restore snapshot: {info.get('pre_restore_backup')}[/dim]"
        )
        self.console.print(
            "[yellow]SentinelFW's rules.yaml may now disagree with the kernel. "
            "Re-apply if needed: sudo sentinelfw firewall apply[/yellow]"
        )
        return ExitCode.OK

    def _fw_syn_logging(self) -> int:
        enable = not self.args.off
        show_change_preview(
            self.console,
            action="Enable SYN logging" if enable else "Disable SYN logging",
            target=self.cfg.chain_ref,
            effect=("Every incoming TCP SYN is written to the kernel log. This is "
                    "the highest-volume data SentinelFW can collect and can fill "
                    "/var/log quickly."
                    if enable else
                    "The SYN logging rule is removed (this flushes the chain, so "
                    "re-apply your rules afterwards)."),
            commands=(f"nft -f -  <<< 'flush chain {self.cfg.chain_ref}\n"
                      f"add rule {self.cfg.chain_ref} meta l4proto tcp "
                      f'tcp flags & (syn | ack) == syn log prefix '
                      f'"{self.config.log_prefix}-SYN " level info' if enable
                      else f"nft -f -  <<< 'flush chain {self.cfg.chain_ref}'"),
            warnings=["Expect thousands of log lines per minute on a public host."]
            if enable else [],
            undo=f"sentinelfw firewall enable-logging --off",
            dry_run=self.dry_run,
        )
        if self.dry_run:
            return ExitCode.OK
        if not is_root():
            error(self.console, "Root privileges are required.",
                  "Re-run with sudo.")
            return ExitCode.PERMISSION
        if not confirm(self.console, "Continue?", assume_yes=self.args.yes):
            raise UserAbortError("Declined by operator.")
        self.manager.enable_syn_logging(enable)
        success(self.console,
                "SYN logging enabled." if enable else "SYN logging disabled.")
        if not enable:
            self.console.print(
                "[yellow]The chain was flushed - re-apply your rules:[/yellow]\n"
                "[bold]sudo sentinelfw firewall apply[/bold]"
            )
        return ExitCode.OK


# ==================================================================
    # monitor
    # ==================================================================
    def _monitor(self) -> int:
        command = self.args.command
        handlers = {
            "start": self._mon_start,
            "poll": self._mon_poll,
            "ingest": self._mon_ingest,
            "demo": self._mon_demo,
            "status": self._mon_status,
            "detect": self._mon_detect,
            "prune": self._mon_prune,
            "vacuum": self._mon_vacuum,
            "reset": self._mon_reset,
        }
        handler = handlers.get(command)
        if handler is None:
            error(self.console, f"Unknown monitor action: {command}")
            return ExitCode.USAGE
        return handler()

    def _resolve_source(self) -> str:
        """Work out which log source to use, with a clear error if ambiguous."""
        if getattr(self.args, "demo", False):
            return "demo"
        source = getattr(self.args, "source", None)
        if source:
            return source
        # A --file argument overrides the configured source.
        if getattr(self.args, "file", None):
            path = Path(self.args.file[-1])
            if not path.is_file():
                error(self.console, f"Log file not found: {path}")
                raise SystemExit(ExitCode.DEPENDENCY)
            return "file"
        return self.cfg.monitoring.source

    def _build_collector(self, source_kind: str, *, detection: bool = True,
                        file_override: str | Path | None = None) -> LogCollector:
        """Create a collector, honouring a one-off ``--file`` override."""
        if file_override:
            source = FileLogSource(Path(file_override),
                                   poll_interval=self.cfg.monitoring.poll_interval,
                                   follow=True, from_start=True)
            return LogCollector(self.cfg, self.db, source, detection=detection,
                                on_alert=self._announce_alert)
        collector = make_collector(self.cfg, self.db, source_kind=source_kind,
                                   detection=detection,
                                   on_alert=self._announce_alert)
        # --file on `monitor start` may repeat; use the last one.
        files = getattr(self.args, "file", None)
        if files and source_kind == "file":
            collector.source = FileLogSource(
                Path(files[-1]), poll_interval=self.cfg.monitoring.poll_interval,
                follow=self.cfg.monitoring.follow,
            )
        return collector

    def _announce_alert(self, alert: Any) -> None:
        """Print a finding the moment it is raised, with its explanation."""
        from monitor.explain import SEVERITY_COLORS

        severity = getattr(alert, "severity", "info")
        title = getattr(alert, "title", str(alert))
        colour = SEVERITY_COLORS.get(severity, "white")
        body = Text()
        # Text.append does not parse markup, so apply the style directly.
        body.append(f"{severity.upper()} ", style=f"bold {colour}")
        body.append(f"{title}\n", style="bold")
        source_ip = getattr(alert, "source_ip", None)
        if source_ip:
            body.append(f"     source {source_ip}\n", style="dim")
        description = getattr(alert, "description", "")
        if description:
            body.append(f"     {truncate(description, 100)}\n", style="dim")
        info = explain_attack(getattr(alert, "kind", ""))
        if info:
            body.append(f"     {truncate(info['why'], 100)}\n", style="dim")
        from monitor.detector import DetectionEngine

        for step in DetectionEngine.describe_alert(alert)["recommendations"][:2]:
            body.append(f"     -> {step}\n", style="green")
        self.console.print(Panel(body, title="ALERT", title_align="left",
                                 border_style=colour))

    # -- monitor commands -------------------------------------------------
    def _mon_start(self) -> int:
        source_kind = self._resolve_source()
        if source_kind == "demo":
            return self._run_demo(
                seconds=self.args.seconds or 60.0,
                events=self.args.events,
                speed=self.args.speed,
                detection=not self.args.no_detect,
            )

        collector = self._build_collector(source_kind,
                                          detection=not self.args.no_detect)
        self.console.print(Panel(
            Text.from_markup(
                f"Reading : [bold]{collector.source.describe()}[/]\n"
                f"Database: {self.cfg.database_path}\n"
                f"Events  : {self.cfg.monitoring.batch_size} per batch\n"
                f"Detect  : {'every 15s' if not self.args.no_detect else 'off'}\n\n"
                "[dim]Press Ctrl+C to stop. Events already stored are kept.[/dim]"
            ),
            title="Monitor starting", title_align="left", border_style="cyan",
        ))
        try:
            stats = collector.run_forever(max_events=self.args.events,
                                          max_seconds=self.args.seconds)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Stopping...[/yellow]")
            collector.stop()
            stats = collector.stats
        self._render_collector_stats(stats)
        return ExitCode.OK

    def _mon_poll(self) -> int:
        source_kind = self._resolve_source()
        collector = self._build_collector(source_kind)
        collector.run_once()
        self._render_collector_stats(collector.stats)
        return ExitCode.OK

    def _mon_ingest(self) -> int:
        # Point the collector at the given file: building it from the configured
        # source would fail on a machine whose configured log files are absent.
        collector = self._build_collector("file", file_override=self.args.path)
        count = collector.ingest_file(self.args.path, limit=self.args.limit)
        success(self.console, f"Imported {count} event(s) from {self.args.path}")
        result = collector.stats.last_detection
        if result:
            self.console.print(f"[dim]Detection cycle: {result}[/dim]")
        return ExitCode.OK

    def _mon_demo(self) -> int:
        return self._run_demo(seconds=self.args.seconds, events=self.args.events,
                              speed=self.args.speed, detection=True)

    def _run_demo(self, *, seconds: float, events: int | None,
                  speed: float, detection: bool) -> int:
        """Run the synthetic source - no root, no real attacker involved."""
        from monitor.log_parser import DemoLogSource

        source = DemoLogSource(log_prefix=self.cfg.log_prefix, speed=speed)
        collector = LogCollector(self.cfg, self.db, source, detection=detection,
                                 on_alert=self._announce_alert)
        self.console.print(Panel(
            Text.from_markup(
                "Source    : [bold]synthetic demo traffic[/bold]\n"
                f"Duration  : {seconds:g}s\n"
                f"Database  : {self.cfg.database_path}\n\n"
                "[yellow]Demo data is fabricated. It is written to the same "
                "database as real events and is labelled 'demo' in every "
                "explanation.[/yellow]\n"
                "[dim]Use 'monitor reset' to clear it afterwards.[/dim]"
            ),
            title="Demo mode", title_align="left", border_style="yellow",
        ))
        if not confirm(self.console, "Generate synthetic traffic?",
                       assume_yes=self.args.yes, default=True):
            raise UserAbortError("Declined by operator.")
        try:
            stats = collector.run_forever(max_events=events, max_seconds=seconds)
        except KeyboardInterrupt:
            collector.stop()
            stats = collector.stats
        self._render_collector_stats(stats)
        return ExitCode.OK

    def _render_collector_stats(self, stats: Any) -> None:
        data = stats.as_dict()
        print_kv(self.console, [
            ("Lines read", data["lines_seen"]),
            ("Events stored", data["events_ingested"]),
            ("Batch writes", data["batches_written"]),
            ("Detection cycles", data["detection_cycles"]),
            ("Last cycle", json.dumps(data["last_detection"])
             if data["last_detection"] else "-"),
            ("Errors", data["db_errors"] or "none"),
            ("Last event", data["last_event_at"] or "-"),
        ], title="Monitor summary")
        if data["last_detection"] and data["last_detection"].get("new_alerts"):
            self.console.print(
                f"[bold yellow]{data['last_detection']['new_alerts']} new alert(s) "
                f"raised.[/bold yellow] Review: sentinelfw alerts list"
            )

    def _mon_status(self) -> int:
        period_label = self.cfg.report.default_period
        start_dt, _ = period_start(period_label)
        start_epoch = start_dt.timestamp()
        stats = self.db.stats(start_epoch)
        payload = {
            "database": str(self.cfg.database_path),
            "database_size_kib": round(self.db.file_size() / 1024, 1),
            "schema_version": self.db.get_meta("schema_version"),
            "created_at": self.db.get_meta("created_at"),
            "retention_days": self.cfg.database.retention_days,
            "monitoring_source": self.cfg.monitoring.source,
            "period": period_label,
            **stats,
        }
        self.emit(payload, lambda p: print_kv(self.console, [
            ("Database", p["database"]),
            ("Size", f"{p['database_size_kib']} KiB"),
            ("Schema", f"v{p['schema_version']}"),
            ("Source setting", p["monitoring_source"]),
            (f"Events ({p['period']})", p["total_events"]),
            ("Blocked", p["blocked_events"]),
            ("Accepted", p["accepted_events"]),
            ("Unique sources", p["unique_sources"]),
            ("Alerts", p["alert_total"]),
        ], title="Monitor status"))

        if payload["total_events"] == 0:
            self.console.print(
                "\n[yellow]No events stored yet.[/yellow]\n"
                "  • Learning?  sentinelfw monitor demo\n"
                "  • Real logs?  sudo sentinelfw monitor start\n"
                "  • Diagnostics: sentinelfw doctor"
            )
        else:
            # Event ids are needed by 'explain event' / 'alerts show'.
            recent = self.db.recent_events(limit=5, since_epoch=start_epoch)
            table = Table(title=f"Most recent events in the last {period_label}",
                          title_style="bold", title_justify="left",
                          border_style="grey37")
            table.add_column("ID", justify="right", no_wrap=True)
            table.add_column("Time", no_wrap=True)
            table.add_column("Action", no_wrap=True)
            table.add_column("Source", overflow="ellipsis", no_wrap=True)
            table.add_column("Port", justify="right", no_wrap=True)
            for event in recent:
                table.add_row(str(event.to_dict().get("id", "-")),
                              str(event.timestamp)[11:19],
                              str(event.action),
                              mask_ip(str(event.source_ip or "-")),
                              str(event.dest_port or "-"))
            self.console.print(table)
            first_id = recent[0].to_dict().get("id", "<id>") if recent else "<id>"
            self.console.print(
                f"[dim]Explain one with: sentinelfw explain event {first_id}[/dim]"
            )
        return ExitCode.OK

    def _mon_detect(self) -> int:
        engine = DetectionEngine(self.cfg, self.db)
        result = engine.run(persist=not self.dry_run)
        payload = result.as_dict()
        self.emit(payload, lambda p: print_kv(self.console, [
            ("Events scanned", p["scanned_events"]),
            ("Findings", p["alerts"]),
            ("New", p["new_alerts"]),
            ("Updated", p["updated_alerts"]),
            ("Kinds", ", ".join(p["kinds"]) or "-"),
            ("Duration", f"{p['duration_seconds']}s"),
        ], title="Detection cycle"))
        if not self.args.json:
            if result.alerts:
                print_alert_table(self.console, [
                    engine.describe_alert(a) for a in result.alerts
                ])
            else:
                success(self.console,
                        "No findings: no event crossed a detection threshold.")
        return ExitCode.OK

    def _mon_prune(self) -> int:
        if self.args.all:
            older_than = None
            label = "ALL events"
        else:
            period = self.args.period or f"{self.cfg.database.retention_days}d"
            start_dt, label = period_start(period)
            older_than = start_dt.timestamp()
        removed = self.db.prune(older_than_epoch=older_than)
        success(self.console,
                f"Removed {removed['events']} event(s), {removed['alerts']} alert(s), "
                f"{removed['rule_hits']} counter row(s) older than {label}.")
        self.db.vacuum()
        self.console.print(f"[dim]Database is now "
                           f"{self.db.file_size() / 1024:.0f} KiB[/dim]")
        return ExitCode.OK

    def _mon_vacuum(self) -> int:
        before = self.db.file_size()
        self.db.vacuum()
        after = self.db.file_size()
        success(self.console,
                f"Compacted database: {before / 1024:.0f} KiB -> {after / 1024:.0f} KiB")
        return ExitCode.OK

    def _mon_reset(self) -> int:
        count = self.db.count_events()
        show_change_preview(
            self.console,
            action="Delete all stored events and alerts",
            target=f"{self.db.path} ({count} event(s) currently stored)",
            effect="The event database is emptied. Firewall rules are NOT touched. "
                   "This cannot be undone.",
            commands=[f"DELETE FROM events; DELETE FROM alerts;  # in {self.db.path}"],
            warnings=["Any evidence you may want for a report is destroyed."],
            undo="None. Export first with: sentinelfw db export",
            dry_run=self.dry_run,
        )
        if self.dry_run:
            return ExitCode.OK
        if not confirm(self.console, f"Delete {count} stored event(s)?",
                       assume_yes=self.args.yes):
            raise UserAbortError("Declined by operator.")
        self.db.reset()
        self.db.vacuum()
        success(self.console, f"Cleared {self.db.path}")
        return ExitCode.OK

    # ==================================================================
    # alerts
    # ==================================================================
    def _alerts(self) -> int:
        command = self.args.command
        handlers = {
            "list": self._al_list,
            "show": self._al_show,
            "ack": self._al_ack,
        }
        handler = handlers.get(command)
        if handler is None:
            error(self.console, f"Unknown alerts action: {command}")
            return ExitCode.USAGE
        return handler()

    def _alert_window(self) -> float:
        period = getattr(self.args, "period", None) or self.cfg.report.default_period
        start_dt, _ = period_start(period)
        return start_dt.timestamp()

    def _al_list(self) -> int:
        since = self._alert_window()
        rows = self.db.alerts(
            since_epoch=since,
            limit=50,
            min_severity=self.args.severity,
            kind=self.args.kind,
            include_acked=self.args.all,
        )
        payload = {
            "period": self.args.period or self.cfg.report.default_period,
            "count": len(rows),
            "alerts": rows,
        }
        if self.args.json:
            self.console.print_json(json.dumps(payload, default=str))
            return ExitCode.OK
        print_alert_table(self.console, rows, explain=self.args.explain)
        self.console.print(
            f"[dim]Period: last {payload['period']}. "
            f"Acknowledge with: sentinelfw alerts ack <id>[/dim]"
        )
        return ExitCode.OK

    def _al_show(self) -> int:
        row = self.db.conn.execute("SELECT * FROM alerts WHERE id = ?",
                                   (self.args.id,)).fetchone()
        if row is None:
            error(self.console, f"No alert with id {self.args.id}.")
            return ExitCode.VALIDATION
        data = dict(row)
        for key, default in (("ports", "[]"), ("evidence", "{}")):
            try:
                data[key] = json.loads(data.get(key) or default)
            except json.JSONDecodeError:
                data[key] = []
        detail = DetectionEngine.describe_alert(data)

        body = Text()
        body.append(f"Severity   : {data['severity'].upper()}\n", style="bold")
        body.append(f"Kind       : {data['kind']}\n", style="bold")
        body.append(f"First seen : {data['first_seen']}\n")
        body.append(f"Last seen  : {data['last_seen']}\n")
        body.append(f"Source     : {data.get('source_ip') or '-'}\n")
        body.append(f"Events     : {data.get('event_count', 0)}\n")
        if data.get("ports"):
            body.append(f"Ports      : {', '.join(str(p) for p in data['ports'][:20])}\n")
        if data.get("acknowledged"):
            body.append("Acknowledged: yes\n", style="dim")
        body.append(f"\n{data.get('description') or ''}\n")
        if detail["explanation"]["why"]:
            body.append("\nWhy this matters:\n", style="bold")
            body.append(f"{detail['explanation']['why']}\n", style="dim")
        if detail["explanation"]["indicators"]:
            body.append("\nTypical indicators:\n", style="bold")
            for item in detail["explanation"]["indicators"]:
                body.append(f"  - {item}\n", style="dim")
        if data.get("evidence"):
            body.append("\nEvidence:\n", style="bold")
            body.append(f"  {json.dumps(data['evidence'], default=str)}\n", style="dim")
        if detail["recommendations"]:
            body.append("\nRecommended actions:\n", style="bold")
            for step in detail["recommendations"]:
                body.append(f"  -> {step}\n", style="green")
        self.console.print(Panel(body, title=f"Alert #{data['id']}",
                                 title_align="left", border_style="yellow"))
        return ExitCode.OK

    def _al_ack(self) -> int:
        if self.db.acknowledge_alert(self.args.id, True):
            success(self.console, f"Alert #{self.args.id} acknowledged.")
            return ExitCode.OK
        error(self.console, f"No alert with id {self.args.id}.")
        return ExitCode.VALIDATION

    # ==================================================================
    # report
    # ==================================================================
    def _report(self) -> int:
        command = self.args.command
        handlers = {"generate": self._rep_generate, "list": self._rep_list}
        handler = handlers.get(command)
        if handler is None:
            error(self.console, f"Unknown report action: {command}")
            return ExitCode.USAGE
        return handler()

    def _rep_generate(self) -> int:
        generator = ReportGenerator(self.cfg, self.db)
        period = self.args.period or self.cfg.report.default_period
        report = generator.generate(period=period)

        if self.args.json or self.args.fmt == "json":
            self.console.print_json(json.dumps(report.to_dict(), default=str))
        elif self.args.brief:
            self.console.print(generator.summary_line(report))
        elif self.args.fmt == "markdown":
            # Markdown tables must not be reflowed by the terminal width.
            self.console.print(report.to_markdown(), soft_wrap=True)
        else:
            self.console.print(report.to_text())

        if self.args.save:
            path = generator.save(report, fmt=self.args.fmt)
            success(self.console, f"Report saved to {path}")
        elif not self.args.json:
            self.console.print(
                f"\n[dim]Save it with: sentinelfw report generate --save "
                f"--format {self.args.fmt}[/dim]"
            )
        return ExitCode.OK

    def _rep_list(self) -> int:
        directory = self.cfg.report_dir
        if not directory.is_dir():
            success(self.console, f"No reports yet in {directory}")
            return ExitCode.OK
        files = sorted((p for p in directory.iterdir() if p.is_file()),
                       key=lambda p: p.stat().st_mtime, reverse=True)
        table = Table(title=f"Saved reports ({len(files)})", title_style="bold",
                      border_style="grey37")
        table.add_column("File", overflow="ellipsis")
        table.add_column("Size", justify="right")
        table.add_column("Modified")
        for path in files[:self.args.limit]:
            modified = datetime.fromtimestamp(path.stat().st_mtime).strftime(
                "%Y-%m-%d %H:%M")
            table.add_row(path.name, f"{path.stat().st_size / 1024:.0f} KiB",
                          modified)
        if not files:
            table.add_row("[dim]none[/dim]", "", "")
        self.console.print(table)
        return ExitCode.OK

    # ==================================================================
    # dashboard
    # ==================================================================
    def _dashboard(self) -> int:
        dashboard = Dashboard(self.cfg, self.db, console=self.console)
        label = self.args.range_label or self.cfg.dashboard.default_range

        if self.args.json:
            snapshot = dashboard.snapshot(label)
            from dashboard.terminal import _jsonable

            self.console.print_json(json.dumps(_jsonable(snapshot), default=str))
            return ExitCode.OK

        if self.args.once:
            dashboard.render_static(dashboard.snapshot(label))
            return ExitCode.OK

        self.console.print(
            "[dim]Refreshing every "
            f"{self.cfg.dashboard.refresh_seconds:g}s. Press Ctrl+C to stop.[/dim]\n"
        )
        dashboard.run_live(range_label=label, iterations=self.args.iterations,
                           console=self.console)
        return ExitCode.OK

    # ==================================================================
    # explain
    # ==================================================================
    def _explain(self) -> int:
        command = self.args.command
        handlers = {"port": self._exp_port, "attack": self._exp_attack,
                    "event": self._exp_event}
        handler = handlers.get(command)
        if handler is None:
            error(self.console, f"Unknown explain subject: {command}")
            return ExitCode.USAGE
        return handler()

    def _exp_port(self) -> int:
        data = explain_port(self.args.port)
        body = Text()
        body.append(f"Port      : {data['port']}\n", style="bold")
        body.append(f"Service   : {data['service']}\n", style="bold")
        body.append(f"Risk      : {data['risk'].upper()}\n",
                    style={"critical": "bold red", "high": "magenta",
                           "medium": "yellow"}.get(data["risk"], "green"))
        body.append(f"\n{data['summary']}\n")
        if data["exposure"]:
            body.append(f"\nWhy attackers care:\n  {data['exposure']}\n", style="dim")
        body.append(f"\nSuggestion: {data['suggestion']}\n", style="green")
        self.console.print(Panel(body, title=f"Port {data['port']}",
                                 title_align="left", border_style="cyan"))
        if self.args.json:
            self.console.print_json(json.dumps(data, default=str))
        return ExitCode.OK

    def _exp_attack(self) -> int:
        if self.args.list or not self.args.kind:
            table = Table(title="Known detection kinds", title_style="bold",
                          border_style="grey37")
            table.add_column("Kind")
            table.add_column("Severity")
            table.add_column("Meaning")
            from monitor.explain import ATTACK_KNOWLEDGE

            for kind, info in ATTACK_KNOWLEDGE.items():
                table.add_row(kind, info.severity, truncate(info.what, 60))
            self.console.print(table)
            self.console.print("[dim]Full detail: sentinelfw explain attack <kind>[/dim]")
            return ExitCode.OK

        data = explain_attack(self.args.kind)
        if data is None:
            error(self.console, f"Unknown detection kind: {self.args.kind}",
                  "List them with: sentinelfw explain attack --list")
            return ExitCode.VALIDATION
        if self.args.json:
            self.console.print_json(json.dumps(data, default=str))
            return ExitCode.OK

        body = Text()
        body.append(f"{data['title']}  [{data['severity'].upper()}]\n",
                    style="bold magenta")
        body.append(f"\n{data['what']}\n")
        if data["why"]:
            body.append(f"\nWhy this matters:\n  {data['why']}\n", style="dim")
        if data["indicators"]:
            body.append("\nIndicators:\n", style="bold")
            for item in data["indicators"]:
                body.append(f"  - {item}\n", style="dim")
        if data["response"]:
            body.append("\nHow to respond:\n", style="bold")
            for index, step in enumerate(data["response"], start=1):
                body.append(f"  {index}. {step}\n", style="green")
        if data["references"]:
            body.append("\nReferences:\n", style="dim")
            for ref in data["references"]:
                body.append(f"  - {ref}\n", style="dim")
        self.console.print(Panel(body, title=f"Detection: {data['kind']}",
                                 title_align="left", border_style="magenta"))
        return ExitCode.OK

    def _exp_event(self) -> int:
        event_id = self.args.id
        if self.args.last is not None:
            if self.args.last < 1:
                error(self.console, "--last must be 1 or greater.")
                return ExitCode.VALIDATION
            row = self.db.conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT 1 OFFSET ?",
                (self.args.last - 1,),
            ).fetchone()
            if row is None:
                error(self.console, f"There are not {self.args.last} stored events.")
                return ExitCode.VALIDATION
        elif event_id is not None:
            row = self.db.conn.execute("SELECT * FROM events WHERE id = ?",
                                       (event_id,)).fetchone()
        else:
            error(self.console, "Give an event id or use --last N.",
                  "Example: sentinelfw explain event --last 1")
            return ExitCode.VALIDATION

        if row is None:
            error(self.console, f"No stored event with id {event_id}.",
                  "Find ids with: sentinelfw monitor status")
            return ExitCode.VALIDATION
        event = FirewallEvent.from_row(row)
        explanation = explain_event(event,
                                    watch_ports=self.cfg.detection.watch_ports)
        if self.args.json:
            self.console.print_json(json.dumps({
                "event": event.to_dict(), **explanation}, default=str))
            return ExitCode.OK
        self.console.print(Panel(Text(explanation["text"]),
                                 title=f"Event #{event.to_dict().get('id', self.args.id)}",
                                 title_align="left", border_style="cyan"))
        if event.raw:
            self.console.print(Panel(Text(event.raw), title="Raw log line",
                                     title_align="left", border_style="grey37"))
        return ExitCode.OK

    # ==================================================================
    # database
    # ==================================================================
    def _db_maintenance(self) -> int:
        command = self.args.command
        handlers = {"stats": self._dbg_stats, "export": self._dbg_export}
        handler = handlers.get(command)
        if handler is None:
            error(self.console, f"Unknown db action: {command}",
                  "Available: stats, export (plus monitor prune/vacuum/reset)")
            return ExitCode.USAGE
        return handler()

    def _dbg_stats(self) -> int:
        start_dt, label = period_start(self.args.period
                                        or self.cfg.report.default_period)
        rows = self.db.conn.execute(
            """
            SELECT action, COUNT(*) AS c FROM events GROUP BY action ORDER BY c DESC
            """
        ).fetchall()
        by_kind = self.db.conn.execute(
            "SELECT kind, severity, COUNT(*) AS c FROM alerts GROUP BY kind ORDER BY c DESC"
        ).fetchall()
        payload = {
            "database": str(self.db.path),
            "size_kib": round(self.db.file_size() / 1024, 1),
            "schema_version": self.db.get_meta("schema_version"),
            "created_at": self.db.get_meta("created_at"),
            "total_events": self.db.count_events(),
            "events_in_period": self.db.count_events(
                since_epoch=start_dt.timestamp()),
            "period": label,
            "by_action": {r["action"]: r["c"] for r in rows},
            "alerts_by_kind": {r["kind"]: r["c"] for r in by_kind},
        }
        self.emit(payload, self._render_db_stats)
        return ExitCode.OK

    def _render_db_stats(self, payload: dict[str, Any]) -> None:
        print_kv(self.console, [
            ("Database", payload["database"]),
            ("Size", f"{payload['size_kib']} KiB"),
            ("Schema", f"v{payload['schema_version']}"),
            ("Created", payload["created_at"] or "-"),
            ("Total events", payload["total_events"]),
            (f"Events (last {payload['period']})", payload["events_in_period"]),
        ], title="Database")
        table = Table(title="Events by action", title_style="bold",
                      border_style="grey37")
        table.add_column("Action")
        table.add_column("Count", justify="right")
        for action, count in payload["by_action"].items():
            table.add_row(str(action), str(count))
        if not payload["by_action"]:
            table.add_row("[dim]no events[/dim]", "0")
        self.console.print(table)
        if payload["alerts_by_kind"]:
            table2 = Table(title="Alerts by kind", title_style="bold",
                           border_style="grey37")
            table2.add_column("Kind")
            table2.add_column("Count", justify="right")
            for kind, count in payload["alerts_by_kind"].items():
                table2.add_row(str(kind), str(count))
            self.console.print(table2)

    def _dbg_export(self) -> int:
        start_epoch: float | None = None
        if self.args.period:
            start_dt, _ = period_start(self.args.period)
            start_epoch = start_dt.timestamp()
        rows = self.db.export_rows(since_epoch=start_epoch, limit=self.args.limit)

        if self.args.fmt == "csv":
            import csv
            import io

            buffer = io.StringIO()
            columns = ["id", "timestamp", "source_ip", "dest_ip", "protocol",
                       "source_port", "dest_port", "action", "severity",
                       "description"]
            writer = csv.DictWriter(buffer, fieldnames=columns,
                                    extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
            content = buffer.getvalue()
        else:
            content = json.dumps(rows, indent=2, default=str)

        if self.args.output:
            path = Path(self.args.output).expanduser()
            path.write_text(content, encoding="utf-8")
            path.chmod(0o600)
            success(self.console, f"Exported {len(rows)} event(s) to {path}")
        else:
            # Raw export: keep rows intact for piping into jq/csvkit.
            self.console.print(content, soft_wrap=True, highlight=False)
        return ExitCode.OK

    # ==================================================================
    # config
    # ==================================================================
    def _config(self) -> int:
        command = self.args.command
        handlers = {
            "init": self._cfg_init,
            "show": self._cfg_show,
            "path": self._cfg_path,
            "check": self._cfg_check,
            "harden": self._cfg_harden,
        }
        handler = handlers.get(command)
        if handler is None:
            error(self.console, f"Unknown config action: {command}")
            return ExitCode.USAGE
        return handler()

    def _cfg_init(self) -> int:
        # Honour --config, then SENTINELFW_CONFIG, then the search list; the
        # resolved cfg knows which file would actually be written.
        target = Path(self.args.config) if self.args.config else self.cfg.config_path
        show_change_preview(
            self.console,
            action="Create configuration file",
            target=str(target or (self.cfg.config_path)),
            effect="Writes a commented default configuration with mode 0600.",
            commands=f"write {target or self.cfg.config_path}",
            undo=f"rm {target or self.cfg.config_path}",
            dry_run=self.dry_run,
        )
        if self.dry_run:
            return ExitCode.OK
        path = write_template(target, force=self.args.force)
        success(self.console, f"Created {path} (mode 0600)")
        self.console.print(
            "[dim]Review the thresholds under 'detection:' before going live.[/dim]"
        )
        return ExitCode.OK

    def _cfg_show(self) -> int:
        payload = self.cfg.to_dict()
        payload["_resolved"] = {
            "root_dir": str(self.cfg.root_dir),
            "config_path": str(self.cfg.config_path),
            "state_file": str(self.cfg.state_file),
            "database": str(self.cfg.database_path),
            "backup_dir": str(self.cfg.backup_dir),
            "report_dir": str(self.cfg.report_dir),
            "log_file": str(self.cfg.log_file),
            "managed_table": self.cfg.table_ref,
            "managed_chain": self.cfg.chain_ref,
        }
        if self.args.json:
            self.console.print_json(json.dumps(payload, default=str))
            return ExitCode.OK
        from rich.tree import Tree

        tree = Tree(f"[bold]config.yaml[/bold]  [dim]{self.cfg.config_path}[/dim]")

        def add_nodes(node: Any, data: dict[str, Any]) -> None:
            for key, value in data.items():
                if isinstance(value, dict):
                    add_nodes(node.add(f"[cyan]{key}[/cyan]"), value)
                else:
                    node.add(f"[cyan]{key}[/cyan] = [white]{value}[/white]")

        add_nodes(tree, payload)
        self.console.print(tree)
        warning = self.cfg.permissions_warning()
        if warning:
            warn(self.console, warning)
        return ExitCode.OK

    def _cfg_path(self) -> int:
        pairs = [
            ("config", self.cfg.config_path),
            ("rules state", self.cfg.state_file),
            ("database", self.cfg.database_path),
            ("backups", self.cfg.backup_dir),
            ("reports", self.cfg.report_dir),
            ("log file", self.cfg.log_file),
            ("project root", self.cfg.root_dir),
        ]
        self.emit({k: str(v) for k, v in pairs},
                  lambda p: print_kv(self.console, list(p.items()),
                                     title="SentinelFW paths"))
        return ExitCode.OK

    def _cfg_check(self) -> int:
        try:
            load_config(self.args.config, require=False)
        except SentinelFWError as exc:
            error(self.console, exc.message, exc.hint)
            return exc.exit_code
        success(self.console, f"Configuration is valid: {self.cfg.config_path}")
        warning = self.cfg.permissions_warning()
        if warning:
            warn(self.console, warning)
        return ExitCode.OK

    def _cfg_harden(self) -> int:
        targets = [self.cfg.config_path, self.cfg.state_file]
        show_change_preview(
            self.console,
            action="Restrict file permissions",
            target=", ".join(str(t) for t in targets),
            effect="Sets mode 0600 on the configuration and rules files so only "
                   "your user can read them.",
            commands=[f"chmod 600 {t}" for t in targets],
            undo=f"chmod 644 <file>   (not recommended)",
            dry_run=self.dry_run,
        )
        if self.dry_run:
            return ExitCode.OK
        if not confirm(self.console, "Apply 0600 permissions?",
                       assume_yes=self.args.yes):
            raise UserAbortError("Declined by operator.")
        self.cfg.harden_permissions()
        success(self.console, "Permissions set to 0600.")
        return ExitCode.OK

    # ==================================================================
    # doctor
    # ==================================================================
    def _doctor(self) -> int:
        """Diagnose this machine without changing anything."""
        checks: list[tuple[str, bool, str]] = []

        # -- Python and dependencies
        checks.append((f"Python {sys.version.split()[0]}", True,
                       "supported (3.10+)"))
        for module, package in (("rich", "rich"), ("yaml", "pyyaml")):
            try:
                __import__(module)
                checks.append((f"package: {package}", True, "installed"))
            except ImportError:
                checks.append((f"package: {package}", False,
                               f"missing - pip install {package}"))

        # -- nftables
        try:
            version = self.manager.ensure_available()
            checks.append(("nft binary", True, version))
        except SentinelFWError as exc:
            checks.append(("nft binary", False, exc.message))

        # -- privileges
        root = is_root()
        checks.append((
            "root privileges", root,
            "yes - firewall changes are permitted"
            if root else
            "no - reading the live ruleset and applying changes need sudo",
        ))

        # -- config
        exists = self.cfg.config_path.is_file()
        checks.append((
            "config.yaml", exists,
            str(self.cfg.config_path) if exists
            else "missing - run: sentinelfw config init",
        ))
        permission_warning = self.cfg.permissions_warning()
        checks.append(("config permissions", not permission_warning,
                       permission_warning or "0600"))

        # -- rules state
        rules = self.store.rules
        checks.append((
            "rules.yaml", True,
            f"{len(rules)} rule(s) in {self.cfg.state_file}"
            if self.cfg.state_file.is_file() else "no rules file yet (fine)",
        ))

        # -- firewall sync
        try:
            status = self.manager.status(require_root=False)
            if not status.available:
                checks.append(("firewall table", False, "nft unavailable"))
            else:
                checks.append((
                    "firewall table", status.table_exists,
                    f"{self.cfg.table_ref} installed "
                    f"({status.rule_count} live rule(s))" if status.table_exists
                    else "not installed - run: sudo sentinelfw firewall apply",
                ))
        except SentinelFWError as exc:  # pragma: no cover
            checks.append(("firewall table", False, exc.message))

        # -- log source
        monitoring = self.cfg.monitoring
        if monitoring.source == "journal":
            journalctl = any(
                (p / "journalctl").exists()
                for p in (__import__("pathlib").Path("/usr/bin"),
                          __import__("pathlib").Path("/bin"))
            )
            checks.append((
                "journalctl", journalctl,
                "available" if journalctl else
                "missing - switch monitoring.source to file or demo",
            ))
            checks.append((
                "journal access", os.geteuid() == 0 or _in_group("systemd-journal"),
                "can read the kernel journal" if (
                    os.geteuid() == 0 or _in_group("systemd-journal"))
                else "denied - use sudo, or add yourself to the systemd-journal group",
            ))
        elif monitoring.source == "file":
            found = next((p for p in monitoring.log_files
                          if __import__("pathlib").Path(p).is_file()), None)
            checks.append((
                "log file", bool(found),
                str(found) if found else
                "none of monitoring.log_files exist - use source: journal",
            ))
        else:
            checks.append(("log source", True, f"{monitoring.source}"))

        # -- database
        db_exists = self.cfg.database_path.exists()
        try:
            total = self.db.count_events()
            checks.append((
                "event database", True,
                f"{total} event(s), {self.db.file_size() / 1024:.0f} KiB"
                if db_exists else f"will be created at {self.cfg.database_path}",
            ))
        except SentinelFWError as exc:
            checks.append(("event database", False, exc.message))

        # -- log file
        log_ok = True
        try:
            self.cfg.log_file.parent.mkdir(parents=True, exist_ok=True)
            if self.cfg.log_file.exists():
                log_ok = bool(self.cfg.log_file.stat().st_mode & 0o200)
        except OSError as exc:
            log_ok = False
            log.detail = str(exc)
        checks.append((
            "log file", log_ok, str(self.cfg.log_file)))

        # -- disk
        try:
            usage = __import__("shutil").disk_usage(str(self.cfg.root_dir))
            free_mb = usage.free / 1024 / 1024
            checks.append((
                "free disk", free_mb > 500,
                f"{free_mb:.0f} MiB free in {self.cfg.root_dir}"))
        except OSError:  # pragma: no cover
            checks.append(("free disk", False, "unknown"))

        table = Table(title=f"{APP_NAME} doctor", title_style="bold",
                      border_style="grey37", show_edge=False)
        table.add_column("Check", style="bold")
        table.add_column("Result", no_wrap=True)
        table.add_column("Detail", overflow="fold")
        for name, ok, detail in checks:
            table.add_row(name, "[green]OK[/green]" if ok else "[red]PROBLEM[/red]",
                          detail)
        self.console.print(table)

        failures = [name for name, ok, _ in checks if not ok]
        if failures:
            self.console.print(
                f"[bold yellow]{len(failures)} check(s) need attention:[/bold yellow]\n"
                + "\n".join(f"  - {name}" for name in failures)
            )
            return ExitCode.DEPENDENCY
        success(self.console, "All checks passed. SentinelFW is ready to use.")
        return ExitCode.OK


def action_of(block: bool) -> str:
    """Helper so block/allow command pairs stay symmetrical."""
    return RuleAction.DROP if block else RuleAction.ACCEPT


def _in_group(name: str) -> bool:
    """Whether the current user belongs to ``name``."""
    import grp

    try:
        return name in {g.gr_name for g in grp.getgrall()}
    except (OSError, PermissionError):  # pragma: no cover
        return False


# ---------------------------------------------------------------------------
# Entry point used by main.py
# ---------------------------------------------------------------------------
def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    return SentinelCLI(argv).run()
