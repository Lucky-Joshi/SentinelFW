"""Shared pytest fixtures.

Every test runs against a throwaway project directory so the suite can never
touch the operator's real ``config.yaml``, database or rules.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import AppConfig, load_config  # noqa: E402
from firewall.rules import RuleStore  # noqa: E402
from monitor.database import Database  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_from_the_real_project(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Make it impossible for any test to write into the source tree.

    Autouse, because several CLI tests construct the application without
    asking for a fixture and would otherwise fall back to the repository's own
    ``config.yaml``, creating ``logs/``, ``database/`` and ``rules.yaml`` next to
    the source during a test run. Pointing the environment at a throwaway path
    means forgetting a fixture leaks into ``tmp_path`` instead of into the
    operator's project.
    """
    root = tmp_path / "autoisolate"
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("SENTINELFW_CONFIG", str(root / "config.yaml"))
    monkeypatch.chdir(root)
    yield


@pytest.fixture()
def project_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An isolated SentinelFW project root."""
    monkeypatch.delenv("SENTINELFW_CONFIG", raising=False)
    return tmp_path / "sentinelfw"


@pytest.fixture()
def config(project_dir: Path) -> AppConfig:
    """A default config rooted in the temporary project directory.

    ``root_dir`` must be set explicitly: ``load_config`` keeps the process-wide
    ``ROOT_DIR`` when it falls back to built-in defaults, which would point the
    database and rules file at the operator's real project.
    """
    project_dir.mkdir(parents=True, exist_ok=True)
    cfg = load_config(project_dir / "config.yaml", require=False)
    cfg.root_dir = project_dir
    for directory in (cfg.backup_dir, cfg.report_dir, cfg.log_file.parent,
                      cfg.database_path.parent):
        directory.mkdir(parents=True, exist_ok=True)
    return cfg


@pytest.fixture()
def store(config: AppConfig) -> RuleStore:
    return RuleStore(config.state_file)


@pytest.fixture()
def db(config: AppConfig) -> Iterator[Database]:
    database = Database(config.database_path)
    database.conn  # force migration
    try:
        yield database
    finally:
        database.close()