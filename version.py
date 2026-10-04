"""Single source of truth for the SentinelFW version string."""

from __future__ import annotations

__all__ = ["__version__", "APP_NAME", "SCHEMA_VERSION"]

#: Semantic version of the tool itself.
__version__ = "1.0.0"

#: Human readable product name used in banners and reports.
APP_NAME = "SentinelFW"

#: Version of the on-disk SQLite schema. Bump when the schema changes and add
#: a matching migration in ``monitor/database.py``.
SCHEMA_VERSION = 1