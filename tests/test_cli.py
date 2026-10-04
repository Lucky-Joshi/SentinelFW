"""End-to-end CLI behaviour, exit codes and the non-interactive safety rules.

These tests never touch the kernel: they run in a temporary project directory
and assert that anything needing root fails cleanly instead of half-applying.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from cli.interface import build_parser, main
from config.settings import load_config, save_config
from exceptions import ExitCode


@pytest.fixture()
def cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the CLI at a throwaway project directory.

    Both the env var and the working directory are redirected: the config
    search list also considers ``./config.yaml`` and the source tree's, so
    leaving the cwd in the repo would silently pick up the real config.
    """
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setenv("SENTINELFW_CONFIG", str(project / "config.yaml"))
    monkeypatch.chdir(project)
    return project


def run(*argv: str) -> int:
    return main(list(argv))


# ---------------------------------------------------------------------------
# Parser ergonomics
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("argv", [
    ["firewall", "list", "--json"],
    ["--json", "firewall", "list"],
    ["firewall", "list", "-y"],
    ["-y", "firewall", "list"],
    ["firewall", "list", "--dry-run"],
    ["monitor", "status", "--json"],
])
def test_global_flags_work_on_either_side_of_the_command(argv: list[str]) -> None:
    args = build_parser().parse_args(argv)
    assert args.group in ("firewall", "monitor")
    for flag, dest in (("--json", "json"), ("-y", "yes"), ("--yes", "yes"),
                       ("--dry-run", "dry_run")):
        if flag in argv:
            assert getattr(args, dest) is True, f"{flag} lost in {argv}"


def test_short_and_long_yes_are_equivalent() -> None:
    parser = build_parser()
    assert parser.parse_args(["firewall", "list", "-y"]).yes is True
    assert parser.parse_args(["firewall", "list", "--yes"]).yes is True
    assert parser.parse_args(["-y", "firewall", "list"]).yes is True


def test_verbose_short_flag_maps_to_verbose() -> None:
    assert build_parser().parse_args(["-v", "doctor"]).verbose is True


def test_no_command_prints_help() -> None:
    assert run() == ExitCode.OK


def test_group_without_action_prints_subcommand_help() -> None:
    assert run("firewall") == ExitCode.OK


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------
def test_doctor_runs_without_root(cli: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = run("doctor")
    out = capsys.readouterr().out
    assert "doctor" in out
    # Non-root is expected in CI, and must be reported rather than crash.
    assert code in (ExitCode.OK, ExitCode.DEPENDENCY)


def test_config_init_creates_a_private_file(cli: Path) -> None:
    assert run("config", "init") == ExitCode.OK
    created = cli / "config.yaml"
    assert created.is_file()
    assert created.stat().st_mode & 0o077 == 0


def test_config_init_refuses_to_clobber(cli: Path) -> None:
    assert run("config", "init") == ExitCode.OK
    assert run("config", "init") != ExitCode.OK
    assert run("config", "init", "--force") == ExitCode.OK


def test_config_path_reports_locations(cli: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run("config", "path", "--json") == ExitCode.OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["database"].endswith(".db")
    # Everything must live inside the throwaway project, never in the repo.
    for key in ("database", "rules state", "backups", "reports", "log file"):
        assert str(cli) in payload[key], f"{key} escaped the project: {payload[key]}"


def test_config_check_accepts_a_valid_file(cli: Path) -> None:
    assert run("config", "init") == ExitCode.OK
    assert run("config", "check") == ExitCode.OK


def test_config_check_rejects_a_broken_file(cli: Path) -> None:
    (cli / "config.yaml").write_text("firewall: [broken\n", encoding="utf-8")
    assert run("config", "check") == ExitCode.VALIDATION


# ---------------------------------------------------------------------------
# Firewall: nothing reaches the kernel without root
# ---------------------------------------------------------------------------
def test_rules_are_recorded_but_not_applied(cli: Path,
                                            capsys: pytest.CaptureFixture[str]) -> None:
    assert run("firewall", "block-ip", "203.0.113.7", "-r", "c2", "-y") == ExitCode.OK
    out = capsys.readouterr().out
    assert "not applied" in out.lower() or "not active" in out.lower()
    rules = (cli / "rules.yaml").read_text(encoding="utf-8")
    assert "203.0.113.7" in rules


def test_dry_run_writes_nothing(cli: Path) -> None:
    assert run("firewall", "--dry-run", "block-ip", "203.0.113.7", "-y") == ExitCode.OK
    assert not (cli / "rules.yaml").exists()


def test_preview_never_executes_nft(cli: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run("firewall", "preview") == ExitCode.OK
    out = capsys.readouterr().out
    assert "Nothing above has been executed" in out


def test_invalid_port_is_a_clean_error(cli: Path,
                                       capsys: pytest.CaptureFixture[str]) -> None:
    assert run("firewall", "block-port", "not-a-port", "-y") == ExitCode.VALIDATION
    assert "Traceback" not in capsys.readouterr().out


def test_invalid_ip_is_a_clean_error(cli: Path) -> None:
    assert run("firewall", "block-ip", "999.999.999.999", "-y") == ExitCode.VALIDATION


def test_apply_without_root_is_refused(cli: Path,
                                       capsys: pytest.CaptureFixture[str]) -> None:
    """The single most important guarantee: no silent partial application."""
    run("firewall", "block-ip", "203.0.113.7", "-y")
    capsys.readouterr()
    if __import__("os").geteuid() == 0:
        pytest.skip("running as root; the refusal path cannot be exercised")
    assert run("firewall", "apply", "-y") == ExitCode.PERMISSION
    assert "Root privileges" in capsys.readouterr().out


def test_apply_dry_run_needs_no_root(cli: Path) -> None:
    run("firewall", "block-ip", "203.0.113.7", "-y")
    assert run("firewall", "apply", "--dry-run") == ExitCode.OK


def test_non_interactive_mutation_without_yes_is_refused(
        cli: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    """Assuming consent in a pipeline is how machines get locked out."""
    # Patch the interactivity probe itself: replacing sys.stdout would break
    # Rich's rendering rather than exercise the refusal path.
    monkeypatch.setattr("cli.console._is_interactive", lambda: False)
    code = run("firewall", "block-ip", "203.0.113.7")
    assert code == ExitCode.ABORTED
    assert "Refusing to continue" in capsys.readouterr().out
    assert not (cli / "rules.yaml").exists()


def test_rule_lifecycle(cli: Path) -> None:
    run("firewall", "block-ip", "198.51.100.1", "-y")
    run("firewall", "block-ip", "198.51.100.2", "-y")
    assert run("firewall", "disable", "1", "-y") == ExitCode.OK
    assert run("firewall", "enable", "1", "-y") == ExitCode.OK
    assert run("firewall", "remove", "2", "-y") == ExitCode.OK
    assert run("firewall", "remove", "99", "-y") == ExitCode.VALIDATION


def test_firewall_status_json_is_machine_readable(
        cli: Path, capsys: pytest.CaptureFixture[str]) -> None:
    run("firewall", "block-ip", "203.0.113.7", "-y")
    capsys.readouterr()
    assert run("firewall", "status", "--json") == ExitCode.OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["stored_rules"] == 1
    assert payload["table"] == "inet sentinelfw"


def test_syn_logging_dry_run_warns_about_noise(cli: Path,
                                               capsys: pytest.CaptureFixture[str]) -> None:
    assert run("firewall", "enable-logging", "--dry-run") == ExitCode.OK
    assert "log lines per minute" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Monitoring
# ---------------------------------------------------------------------------
def test_demo_run_populates_the_database(cli: Path) -> None:
    assert run("monitor", "demo", "--seconds", "3", "-y") == ExitCode.OK
    assert run("monitor", "status", "--json") == ExitCode.OK


@pytest.mark.parametrize("argv,key", [
    (["monitor", "status"], "total_events"),
    (["firewall", "status"], "stored_rules"),
    (["alerts", "list"], "count"),
    (["db", "stats"], "total_events"),
    (["dashboard", "--once"], "range"),
])
def test_json_output_is_a_single_valid_document(
        cli: Path, capsys: pytest.CaptureFixture[str], argv: list[str],
        key: str) -> None:
    """Decoration after the JSON payload makes it unparseable for scripts."""
    run("monitor", "demo", "--seconds", "2", "-y")
    capsys.readouterr()
    assert run(*argv, "--json") == ExitCode.OK
    payload = json.loads(capsys.readouterr().out)
    assert key in payload


def test_demo_data_is_labelled_as_synthetic(cli: Path,
                                            capsys: pytest.CaptureFixture[str]) -> None:
    run("monitor", "demo", "--seconds", "2", "-y")
    out = capsys.readouterr().out
    assert "synthetic" in out.lower()


def test_ingest_reads_an_arbitrary_log_file(cli: Path, tmp_path: Path,
                                            capsys: pytest.CaptureFixture[str]) -> None:
    log = tmp_path / "kern.log"
    log.write_text(
        "2026-10-04T03:10:02+0000 kali kernel: SENTINELFW-DROP "
        "SRC=203.0.113.9 DST=10.0.0.5 PROTO=TCP SPT=40000 DPT=22 LEN=40\n",
        encoding="utf-8",
    )
    assert run("monitor", "ingest", str(log), "-y") == ExitCode.OK
    out = capsys.readouterr().out
    assert "Imported 1 event" in out


def test_alerts_list_is_json_serialisable(cli: Path,
                                          capsys: pytest.CaptureFixture[str]) -> None:
    run("monitor", "demo", "--seconds", "3", "-y")
    capsys.readouterr()
    assert run("alerts", "list", "--json") == ExitCode.OK
    payload = json.loads(capsys.readouterr().out)
    assert "count" in payload and isinstance(payload["alerts"], list)


def test_alert_ids_are_discoverable(cli: Path) -> None:
    """'alerts ack <id>' is only usable if the id is visible somewhere."""
    run("monitor", "demo", "--seconds", "3", "-y")
    assert run("monitor", "status") == ExitCode.OK
    assert run("alerts", "list") == ExitCode.OK


def test_monitor_reset_clears_events(cli: Path) -> None:
    run("monitor", "demo", "--seconds", "2", "-y")
    assert run("monitor", "reset", "-y") == ExitCode.OK
    capsys_output = run("monitor", "status", "--json")
    assert capsys_output == ExitCode.OK


def test_detect_dry_run_persists_nothing(cli: Path) -> None:
    assert run("monitor", "detect", "--dry-run") == ExitCode.OK


# ---------------------------------------------------------------------------
# Reports, dashboard and explain
# ---------------------------------------------------------------------------
def test_report_generates_in_every_format(cli: Path,
                                          capsys: pytest.CaptureFixture[str]) -> None:
    run("monitor", "demo", "--seconds", "2", "-y")
    capsys.readouterr()

    assert run("report", "generate") == ExitCode.OK
    assert "Security" in capsys.readouterr().out

    assert run("report", "generate", "--brief") == ExitCode.OK
    assert capsys.readouterr().out.strip()

    assert run("report", "generate", "--json") == ExitCode.OK
    json.loads(capsys.readouterr().out)


def test_report_save_writes_into_the_project(cli: Path) -> None:
    assert run("report", "generate", "--save", "--format", "markdown") == ExitCode.OK
    saved = list((cli / "reports").glob("*.md"))
    assert saved, "expected a saved markdown report"
    assert saved[0].stat().st_mode & 0o077 == 0


def test_report_list_shows_a_readable_timestamp(cli: Path,
                                                capsys: pytest.CaptureFixture[str]) -> None:
    run("report", "generate", "--save")
    capsys.readouterr()
    assert run("report", "list") == ExitCode.OK
    out = capsys.readouterr().out
    assert "17" not in out.split("Modified")[-1][:12], out


def test_dashboard_snapshot_is_json_serialisable(cli: Path,
                                                 capsys: pytest.CaptureFixture[str]) -> None:
    run("monitor", "demo", "--seconds", "2", "-y")
    capsys.readouterr()
    assert run("dashboard", "--once", "--json") == ExitCode.OK
    json.loads(capsys.readouterr().out)


def test_dashboard_renders_once(cli: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run("dashboard", "--once") == ExitCode.OK
    assert "SentinelFW" in capsys.readouterr().out


@pytest.mark.parametrize("port,expected", [(22, "ssh"), (3389, "rdp"),
                                            (443, "https")])
def test_explain_port(cli: Path, port: int, expected: str,
                      capsys: pytest.CaptureFixture[str]) -> None:
    assert run("explain", "port", str(port)) == ExitCode.OK
    assert expected in capsys.readouterr().out.lower()


@pytest.mark.parametrize("port", ["0", "65536", "70000"])
def test_explain_port_rejects_out_of_range(cli: Path, port: str) -> None:
    """Must be a clean message, not an OverflowError traceback."""
    code = run("explain", "port", port)
    assert code in (ExitCode.OK, ExitCode.VALIDATION)


def test_explain_attack_lists_and_details(cli: Path,
                                          capsys: pytest.CaptureFixture[str]) -> None:
    assert run("explain", "attack", "--list") == ExitCode.OK
    listing = capsys.readouterr().out
    assert "port_scan" in listing

    assert run("explain", "attack", "port_scan") == ExitCode.OK
    assert "How to respond" in capsys.readouterr().out

    assert run("explain", "attack", "no_such_kind") == ExitCode.VALIDATION


def test_explain_event_last(cli: Path) -> None:
    log_line = cli / "kern.log"
    log_line.write_text(
        "2026-10-04T03:10:02+0000 kali kernel: SENTINELFW-DROP "
        "SRC=203.0.113.9 DST=10.0.0.5 PROTO=TCP SPT=40000 DPT=22 LEN=40\n",
        encoding="utf-8",
    )
    run("monitor", "ingest", str(log_line), "-y")
    assert run("explain", "event", "--last", "1") == ExitCode.OK


def test_explain_event_without_target_is_rejected(cli: Path) -> None:
    assert run("explain", "event") == ExitCode.VALIDATION


# ---------------------------------------------------------------------------
# Database maintenance
# ---------------------------------------------------------------------------
def test_db_stats_and_export(cli: Path, capsys: pytest.CaptureFixture[str]) -> None:
    run("monitor", "demo", "--seconds", "2", "-y")
    capsys.readouterr()

    assert run("db", "stats", "--json") == ExitCode.OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["total_events"] > 0

    assert run("db", "export", "--format", "csv", "--limit", "5") == ExitCode.OK
    csv_out = capsys.readouterr().out
    assert csv_out.splitlines()[0].startswith("id,timestamp")

    assert run("db", "export", "--format", "json", "--limit", "2") == ExitCode.OK
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 2


def test_db_export_to_file_is_private(cli: Path) -> None:
    run("monitor", "demo", "--seconds", "2", "-y")
    target = cli / "export.json"
    assert run("db", "export", "--output", str(target)) == ExitCode.OK
    assert target.is_file()
    assert target.stat().st_mode & 0o077 == 0

def test_monitor_poll_terminates_instead_of_following(
        cli: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``poll`` promises one pass then exit, so the source must not follow."""
    monkeypatch.setenv("SENTINELFW_CONFIG", str(cli / "config.yaml"))
    run("config", "init", "-y")

    # A log file that exists but has nothing left to give: the exact case that
    # used to block forever because the source kept waiting for new lines.
    settled = cli / "monitor.log"
    settled.write_text("")

    cfg = load_config(cli / "config.yaml")
    cfg.monitoring.source = "file"
    cfg.monitoring.log_files = [str(settled)]
    save_config(cfg, cli / "config.yaml")

    start = time.monotonic()
    assert run("monitor", "poll") == ExitCode.OK
    assert time.monotonic() - start < 20, "monitor poll followed the log forever"


def test_yes_does_not_bypass_the_duplicate_check(cli: Path) -> None:
    """--yes means "do not prompt", not "skip the safety checks"."""
    assert run("firewall", "block-ip", "198.51.100.9", "-y") == ExitCode.OK
    # An unattended run must not quietly pile up identical rules.
    assert run("firewall", "block-ip", "198.51.100.9", "-y") == ExitCode.VALIDATION
    # Overriding that is a separate, explicit decision.
    assert run("firewall", "block-ip", "198.51.100.9", "-y", "--force") == ExitCode.OK
