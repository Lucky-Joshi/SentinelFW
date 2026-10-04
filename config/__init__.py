"""Configuration package.

Re-exports the public API of :mod:`config.settings` so callers can simply do
``from config import load_config``.
"""

from __future__ import annotations

from config.settings import (  # noqa: F401
    CONFIG_TEMPLATE,
    ROOT_DIR,
    AppConfig,
    DashboardSettings,
    DatabaseSettings,
    DetectionSettings,
    FirewallSettings,
    LoggingSettings,
    MonitoringSettings,
    ReportSettings,
    config_from_mapping,
    config_search_paths,
    default_config_path,
    load_config,
    save_config,
    write_template,
)

__all__ = [
    "CONFIG_TEMPLATE",
    "ROOT_DIR",
    "AppConfig",
    "DashboardSettings",
    "DatabaseSettings",
    "DetectionSettings",
    "FirewallSettings",
    "LoggingSettings",
    "MonitoringSettings",
    "ReportSettings",
    "config_from_mapping",
    "config_search_paths",
    "default_config_path",
    "load_config",
    "save_config",
    "write_template",
]