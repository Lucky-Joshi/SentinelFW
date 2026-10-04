"""Configuration loading, validation and file-permission safety."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from config.settings import (
    config_from_mapping,
    load_config,
    save_config,
    write_template,
)
from exceptions import ConfigNotFoundError, ConfigValidationError, SentinelFWError


def test_defaults_when_no_file(tmp_path: Path) -> None:
    cfg = load_config(tmp_path / "missing.yaml", require=False)
    assert cfg.firewall.table == "sentinelfw"
    assert cfg.firewall.family == "inet"
    assert cfg.firewall.chain == "input"
    assert cfg.firewall.priority == -10
    assert cfg.firewall.policy == "accept"
    assert cfg.state_file.name == "rules.yaml"
    assert cfg.database_path.suffix == ".db"


def test_require_raises_when_absent(tmp_path: Path) -> None:
    with pytest.raises(ConfigNotFoundError):
        load_config(tmp_path / "missing.yaml", require=True)


def test_saved_config_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    cfg = config_from_mapping({}, config_path=path, root_dir=tmp_path)
    save_config(cfg, path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_template_is_commented_and_private(tmp_path: Path) -> None:
    path = write_template(tmp_path / "tpl.yaml")
    text = path.read_text(encoding="utf-8")
    assert text.lstrip().startswith("#"), "template must be commented out"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_template_refuses_to_clobber_without_force(tmp_path: Path) -> None:
    path = write_template(tmp_path / "tpl.yaml")
    path.write_text("firewall:\n  table: mine\n", encoding="utf-8")
    with pytest.raises(SentinelFWError):
        write_template(path, force=False)
    write_template(path, force=True)  # force overwrites


def test_explicit_values_are_honoured(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        "firewall:\n"
        "  table: lab\n"
        "  priority: -5\n"
        "database:\n"
        "  retention_days: 7\n",
        encoding="utf-8",
    )
    cfg = load_config(path)
    assert cfg.firewall.table == "lab"
    assert cfg.firewall.priority == -5
    assert cfg.database.retention_days == 7
    assert cfg.table_ref == "inet lab"
    assert cfg.chain_ref == "inet lab input"


def test_relative_paths_resolve_against_root(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    cfg = load_config(path)
    cfg.root_dir = tmp_path
    assert cfg.resolve("logs/x.log") == tmp_path / "logs" / "x.log"
    absolute = cfg.resolve("/etc/sentinelfw/x")
    assert absolute == Path("/etc/sentinelfw/x")


def test_nested_unknown_keys_are_ignored_not_fatal(tmp_path: Path) -> None:
    """A typo in a nested key must not silently change behaviour unnoticed.

    Unknown nested keys are ignored (the dataclass keeps its default), which is
    documented behaviour rather than an error.
    """
    path = tmp_path / "config.yaml"
    path.write_text("firewall:\n  tabel: typo\n  table: real\n", encoding="utf-8")
    cfg = load_config(path)
    assert cfg.firewall.table == "real"


def test_yaml_is_parsed_safely(tmp_path: Path) -> None:
    """A python/object tag must never be constructed."""
    path = tmp_path / "config.yaml"
    path.write_text(
        "firewall: !!python/object/apply:os.system ['touch /tmp/sentinelfw-pwned']\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigValidationError):
        load_config(path)
    assert not Path("/tmp/sentinelfw-pwned").exists()


def test_malformed_yaml_is_reported_clearly(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("firewall:\n  table: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigValidationError):
        load_config(path)


def test_non_mapping_document_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ConfigValidationError):
        load_config(path)


@pytest.mark.parametrize(
    "document",
    [
        "firewall:\n  table: 'bad name'\n",
        "firewall:\n  family: ethernet\n",
        "firewall:\n  policy: reject\n",
        "firewall:\n  priority: 9999\n",
        "firewall:\n  log_level: verbose\n",
        "firewall:\n  log_prefix: 'has space'\n",
        "monitoring:\n  source: carrier-pigeon\n",
        "detection:\n  port_scan_threshold: 1\n",
        "detection:\n  port_scan_window_seconds: 1\n",
        "database:\n  retention_days: -1\n",
    ],
)
def test_invalid_values_are_rejected(tmp_path: Path, document: str) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(document, encoding="utf-8")
    with pytest.raises(ConfigValidationError):
        load_config(path)


def test_watch_ports_range_is_validated(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("detection:\n  watch_ports: [22, 70000]\n", encoding="utf-8")
    with pytest.raises(ConfigValidationError):
        load_config(path)


def test_permissions_warning_detects_loose_mode(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    save_config(config_from_mapping({}, config_path=path, root_dir=tmp_path), path)
    os.chmod(path, 0o644)
    cfg = load_config(path)
    warning = cfg.permissions_warning()
    assert warning and "644" in warning
    cfg.harden_permissions()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert cfg.permissions_warning() is None


def test_env_var_selects_config_file(tmp_path: Path,
                                     monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "elsewhere.yaml"
    save_config(
        config_from_mapping({"firewall": {"table": "fromenv"}},
                            config_path=path, root_dir=tmp_path),
        path,
    )
    monkeypatch.setenv("SENTINELFW_CONFIG", str(path))
    cfg = load_config(None)
    assert cfg.firewall.table == "fromenv"
    assert cfg.config_path == path