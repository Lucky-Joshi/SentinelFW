"""Firewall management plane.

Modules
-------
``firewall.rules``
    Rule model, validation and persistence (``rules.yaml``).
``firewall.nft_manager``
    The only place that executes ``nft``.
``firewall.backup``
    Ruleset snapshots and recovery.
"""

from __future__ import annotations

from firewall.backup import BackupEntry, BackupManager  # noqa: F401
from firewall.nft_manager import (  # noqa: F401
    NFTRule,
    NFTStatus,
    NFTManager,
    is_root,
)
from firewall.rules import (  # noqa: F401
    Rule,
    RuleAction,
    RuleKind,
    RuleStore,
    port_service_name,
    validate_ip_or_network,
    validate_port,
    validate_protocol,
)

__all__ = [
    "BackupEntry",
    "BackupManager",
    "NFTRule",
    "NFTStatus",
    "NFTManager",
    "Rule",
    "RuleAction",
    "RuleKind",
    "RuleStore",
    "is_root",
    "port_service_name",
    "validate_ip_or_network",
    "validate_port",
    "validate_protocol",
]