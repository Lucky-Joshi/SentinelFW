"""Monitoring plane.

Modules
-------
``monitor.database``
    SQLite storage for events and alerts.
``monitor.log_parser``
    Kernel log parsing plus the pluggable log sources.
``monitor.monitor``
    The collector that joins source -> parser -> database -> detector.
``monitor.detector``
    Threshold-based anomaly detection.
``monitor.explain``
    The knowledge base used to explain events and findings.
``monitor.reports``
    Report generation in text, markdown and JSON.
"""

from __future__ import annotations

from monitor.database import (  # noqa: F401
    SEVERITY_ORDER,
    Alert,
    Database,
    FirewallEvent,
    Severity,
)
from monitor.detector import DetectionEngine, DetectionResult  # noqa: F401
from monitor.log_parser import (  # noqa: F401
    DemoLogSource,
    FileLogSource,
    JournalLogSource,
    LogSource,
    NFLogParser,
    build_source,
)
from monitor.monitor import LogCollector, make_collector  # noqa: F401
from monitor.reports import ReportGenerator, SecurityReport  # noqa: F401

__all__ = [
    "Alert",
    "Database",
    "DemoLogSource",
    "DetectionEngine",
    "DetectionResult",
    "FileLogSource",
    "FirewallEvent",
    "JournalLogSource",
    "LogCollector",
    "LogSource",
    "NFLogParser",
    "ReportGenerator",
    "SEVERITY_ORDER",
    "SecurityReport",
    "Severity",
    "build_source",
    "make_collector",
]