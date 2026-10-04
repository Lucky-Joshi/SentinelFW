"""Terminal presentation helpers.

Everything the operator sees goes through this module, which keeps three
concerns in one place:

* **Colour** - disabled automatically when stdout is not a TTY, when ``NO_COLOR``
  is set, or when ``--no-color`` is passed, so piped output stays clean.
* **Previews** - :func:`show_change_preview` is used by every mutating command.
  The preview shows *what will happen*, *which commands will run*, and *how to
  undo it* before asking for confirmation. This is the single most important
  safety behaviour in the tool.
* **Confirmation** - :func:`confirm` refuses to auto-accept in a non-interactive
  session unless ``--yes`` was given, so a rule cannot be added by accident from
  a cron job or a stray pipe.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Iterable, Sequence

from rich.box import ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

__all__ = [
    "make_console",
    "show_change_preview",
    "confirm",
    "print_rule_table",
    "print_alert_table",
    "print_kv",
    "warn",
    "success",
    "error",
]


def make_console(*, no_color: bool = False, json_mode: bool = False,
                 force_terminal: bool | None = None) -> Console:
    """Build a Rich console with sane defaults for CLI use.

    ``soft_wrap`` stays off for both modes: it disables all wrapping, which
    makes Panels crop their content instead of reflowing it, and the change
    preview must show the *whole* nft script. Long machine-readable output that
    genuinely should not wrap (e.g. ``db export``) opts in per call via
    ``console.print(..., soft_wrap=True)``.
    """
    if force_terminal is not None:
        return Console(no_color=no_color, force_terminal=force_terminal,
                       highlight=False, soft_wrap=False)
    return Console(no_color=no_color, highlight=False, soft_wrap=False)


def _is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


# ---------------------------------------------------------------------------
# Change preview
# ---------------------------------------------------------------------------
def show_change_preview(
    console: Console,
    *,
    action: str,
    target: str,
    effect: str,
    commands: Sequence[str] | str = (),
    reason: str | None = None,
    warnings: Sequence[str] = (),
    undo: str | None = None,
    dry_run: bool = False,
) -> None:
    """Print the standard "here is what I am about to do" block.

    Parameters
    ----------
    action:
        Short verb phrase, e.g. ``"Block IP address"``.
    target:
        The object being acted on, e.g. the address or port.
    effect:
        What the kernel will do, in plain English.
    commands:
        The literal ``nft`` commands / script that will be executed.
    warnings:
        Things the operator should notice (e.g. blocking their own address).
    undo:
        How to reverse the change.
    """
    body = Text()
    body.append("Action    : ", style="bold")
    body.append(f"{action}\n", style="bold cyan")
    body.append("Target    : ", style="bold")
    body.append(f"{target}\n")
    body.append("Effect    : ", style="bold")
    body.append(f"{effect}\n", style="white")
    body.append("Backend   : ", style="bold")
    body.append("nftables (requires root)\n")

    if reason:
        body.append("Reason    : ", style="bold")
        body.append(f"{reason}\n")

    body.append("Commands  :\n", style="bold")
    if not commands:
        body.append("  (none - this only updates local rule storage)\n", style="dim")
    elif isinstance(commands, str):
        for line in commands.strip().splitlines():
            body.append(f"  {line}\n", style="yellow")
    else:
        for line in commands:
            body.append(f"  {line}\n", style="yellow")

    if undo:
        body.append("\nUndo      : ", style="bold")
        body.append(f"{undo}\n", style="green")

    border = "yellow" if dry_run else "red"
    title = "DRY RUN - nothing was changed" if dry_run else "FIREWALL CHANGE REQUESTED"
    console.print(Panel(body, title=title, title_align="left",
                        border_style=border, box=ROUNDED))

    for warning in warnings:
        console.print(f"[bold yellow]![/bold yellow] [yellow]{warning}[/yellow]")

    if dry_run:
        console.print("[dim]Dry run: no nft command was executed.[/dim]")


def confirm(console: Console, question: str, *, assume_yes: bool = False,
            default: bool = False) -> bool:
    """Ask for confirmation.

    Rules:
    * ``--yes`` skips the prompt (for scripts).
    * A non-interactive session without ``--yes`` is treated as **no**, because
      assuming consent in a pipeline is how machines get locked out.
    """
    if assume_yes:
        console.print("[dim]--yes given; proceeding without confirmation[/dim]")
        return True
    if not _is_interactive():
        console.print(
            "[yellow]Refusing to continue: stdin is not a terminal and --yes was "
            "not given.[/yellow]"
        )
        console.print("[dim]Re-run with --yes if this is intentional.[/dim]")
        return False
    suffix = "[Y/n][/]" if default else "[y/N][/]"
    try:
        answer = console.input(f"[bold]{question}[/bold] {suffix} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        console.print()
        return False
    if not answer:
        return default
    return answer in {"y", "yes"}


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------
def print_rule_table(console: Console, rules: Iterable[Any], *,
                     title: str = "Firewall rules") -> None:
    """Render :class:`firewall.rules.Rule` objects as a table."""
    table = Table(title=title, title_style="bold", title_justify="left",
                  header_style="bold", border_style="grey37", expand=True)
    table.add_column("ID", justify="right", no_wrap=True)
    table.add_column("Action", no_wrap=True)
    table.add_column("Kind", no_wrap=True)
    table.add_column("Target", overflow="ellipsis")
    table.add_column("Comment", overflow="ellipsis")
    table.add_column("Enabled", no_wrap=True)

    count = 0
    for rule in rules:
        count += 1
        colour = {"DROP": "red", "ACCEPT": "green", "REJECT": "red",
                  "LOG": "cyan"}.get(rule.verdict, "white")
        table.add_row(
            str(rule.id or "-"),
            f"[{colour}]{rule.verdict}[/]",
            rule.kind.replace("_", " "),
            rule.target,
            f"[dim]{rule.comment or '-'}[/dim]",
            "[green]yes[/]" if rule.enabled else "[dim]no[/dim]",
        )
    if not count:
        table.add_row("-", "[dim]no rules defined[/dim]", "", "", "", "")
    console.print(table)


def print_alert_table(console: Console, alerts: Sequence[dict[str, Any]], *,
                      explain: bool = False) -> None:
    """Render alert dictionaries as a table."""
    from monitor.explain import SEVERITY_COLORS

    table = Table(title=f"Alerts ({len(alerts)})", title_style="bold",
                  title_justify="left", header_style="bold",
                  border_style="grey37", expand=True)
    table.add_column("ID", justify="right", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Finding", overflow="ellipsis")
    table.add_column("Source", no_wrap=True)
    table.add_column("Events", justify="right", no_wrap=True)
    table.add_column("Last seen", no_wrap=True)

    for alert in alerts:
        sev = str(alert.get("severity", "info"))
        table.add_row(
            str(alert.get("id", "-")),
            f"[{SEVERITY_COLORS.get(sev, 'white')}]{sev.upper()}[/]",
            str(alert.get("title", "")),
            str(alert.get("source_ip") or "-"),
            str(alert.get("event_count", 0)),
            str(alert.get("last_seen", ""))[:19],
        )
    if not alerts:
        table.add_row("-", "-", "[dim]no alerts in this window[/dim]", "", "", "")
    console.print(table)

    if explain:
        for alert in alerts:
            from monitor.detector import DetectionEngine

            detail = DetectionEngine.describe_alert(alert)
            body = Text()
            body.append(str(alert.get("description", "")), style="white")
            if detail["explanation"]["why"]:
                body.append("\n\nWhy this matters:\n", style="bold")
                body.append(detail["explanation"]["why"], style="dim")
            if detail["recommendations"]:
                body.append("\n\nWhat to do:\n", style="bold")
                for step in detail["recommendations"][:6]:
                    body.append(f"  - {step}\n", style="green")
            console.print(Panel(body, title=str(alert.get("title"))[:80],
                                title_align="left", border_style="yellow"))


def print_kv(console: Console, pairs: Sequence[tuple[str, Any]], *,
             title: str | None = None) -> None:
    """Render a simple aligned key/value block.

    A value may be a plain string (printed literally) or a :class:`Text` object
    for callers that need colour. Strings are never parsed as markup, so paths
    and values containing ``[`` survive intact.
    """
    body = Text()
    width = max((len(k) for k, _ in pairs), default=0)
    for key, value in pairs:
        body.append(f"{key.ljust(width)} : ", style="bold")
        if isinstance(value, Text):
            body.append_text(value)
            body.append("\n")
        else:
            body.append(f"{value}\n")
    console.print(Panel(body, title=title, title_align="left",
                        border_style="grey37") if title else body)


# ---------------------------------------------------------------------------
# Small status messages
# ---------------------------------------------------------------------------
def success(console: Console, message: str) -> None:
    console.print(f"[bold green]OK[/bold green] {message}")


def warn(console: Console, message: str) -> None:
    console.print(f"[bold yellow]![/bold yellow] [yellow]{message}[/yellow]")


def error(console: Console, message: str, hint: str | None = None) -> None:
    console.print(f"[bold red]ERROR[/bold red] {message}")
    if hint:
        console.print(f"  [dim]hint:[/dim] {hint}")


def env_flag(name: str) -> bool:
    """Read a truthy environment variable (used for CI-safe defaults)."""
    return str(os.environ.get(name, "")).lower() in {"1", "true", "yes", "on"}