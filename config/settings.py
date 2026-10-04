"""Configuration loading, validation and safe persistence.

Safety properties
-----------------
* YAML is parsed with ``yaml.safe_load`` only. Arbitrary Python object
  construction (``!!python/object``) is impossible, so a tampered config file
  cannot achieve code execution.
* Values are validated *before* they reach nftables. A bad config produces a
  list of readable problems, not an obscure kernel error.
* Writes are atomic (temp file + ``os.replace``) and land with mode ``0600``,
  because the config records the firewall posture of the host.
* Missing files are never silently invented during a normal run; ``--create``
  (or ``sentinelfw config init``) must be asked for explicitly.
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Mapping

import yaml

from exceptions import ConfigNotFoundError, ConfigValidationError, SentinelFWError
from logsetup import get_logger
from utils import atomic_write_text, ensure_dir, now_iso

log = get_logger("config")

__all__ = [
    "ROOT_DIR",
    "AppConfig",
    "FirewallSettings",
    "DatabaseSettings",
    "MonitoringSettings",
    "DetectionSettings",
    "ReportSettings",
    "LoggingSettings",
    "DashboardSettings",
    "load_config",
    "save_config",
    "default_config_path",
    "config_search_paths",
    "CONFIG_TEMPLATE",
]

#: Repository root - every relative path in the config is resolved against it.
ROOT_DIR = Path(__file__).resolve().parent.parent

CONFIG_FILENAME = "config.yaml"
ENV_CONFIG_PATH = "SENTINELFW_CONFIG"


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------
@dataclass
class FirewallSettings:
    """How SentinelFW talks to nftables.

    The table/chain names are configurable, but SentinelFW will only ever
    write inside ``firewall.table``. That containment is a hard safety rule
    enforced in ``firewall/nft_manager.py``.
    """

    table: str = "sentinelfw"
    family: str = "inet"
    chain: str = "input"
    hook: str = "input"
    #: Chain priority. -10 places our chain *before* the standard filter chain
    #: so our drops take effect first, while the policy stays ``accept`` so we
    #: can never lock the operator out of their own machine.
    priority: int = -10
    policy: str = "accept"
    log_enabled: bool = True
    log_level: str = "info"
    log_prefix: str = "SENTINELFW"
    state_file: str = "rules.yaml"
    backup_dir: str = "backups"
    backup_keep: int = 20
    command_timeout: float = 15.0
    sync_state_on_change: bool = True


@dataclass
class DatabaseSettings:
    path: str = "database/events.db"
    retention_days: int = 90
    busy_timeout_ms: int = 5000
    batch_size: int = 200


@dataclass
class MonitoringSettings:
    #: Monitoring never starts on its own. The operator runs
    #: ``sentinelfw monitor start`` explicitly.
    source: str = "journal"
    log_files: list[str] = field(
        default_factory=lambda: ["/var/log/kern.log", "/var/log/syslog"]
    )
    journal_identifier: str = "kernel"
    follow: bool = True
    poll_interval: float = 1.0
    read_since_minutes: int = 5
    batch_size: int = 200
    #: Emit an nft rule that logs every incoming SYN (high volume!).
    enable_syn_logging: bool = False


@dataclass
class DetectionSettings:
    port_scan_threshold: int = 20
    port_scan_window_seconds: int = 60
    brute_force_threshold: int = 100
    brute_force_window_seconds: int = 300
    spike_threshold: int = 300
    spike_window_seconds: int = 60
    repeated_block_threshold: int = 50
    repeated_block_window_seconds: int = 600
    watch_ports: list[int] = field(
        default_factory=lambda: [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                                 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
                                 27017]
    )
    alert_cooldown_seconds: int = 900


@dataclass
class ReportSettings:
    output_dir: str = "reports"
    default_period: str = "24h"
    top_n: int = 10


@dataclass
class LoggingSettings:
    level: str = "INFO"
    file: str = "logs/sentinelfw.log"
    max_bytes: int = 5 * 1024 * 1024
    backup_count: int = 5


@dataclass
class DashboardSettings:
    refresh_seconds: float = 3.0
    default_range: str = "24h"
    top_n: int = 8
    max_events: int = 12


@dataclass
class AppConfig:
    """The full configuration tree."""

    root_dir: Path = ROOT_DIR
    config_path: Path = field(default_factory=lambda: ROOT_DIR / CONFIG_FILENAME)
    firewall: FirewallSettings = field(default_factory=FirewallSettings)
    database: DatabaseSettings = field(default_factory=DatabaseSettings)
    monitoring: MonitoringSettings = field(default_factory=MonitoringSettings)
    detection: DetectionSettings = field(default_factory=DetectionSettings)
    report: ReportSettings = field(default_factory=ReportSettings)
    logging: LoggingSettings = field(default_factory=LoggingSettings)
    dashboard: DashboardSettings = field(default_factory=DashboardSettings)

    # -- path helpers ------------------------------------------------------
    def resolve(self, relative: str | os.PathLike[str]) -> Path:
        """Resolve a config path relative to the project root."""
        p = Path(relative).expanduser()
        return p if p.is_absolute() else (self.root_dir / p)

    @property
    def state_file(self) -> Path:
        return self.resolve(self.firewall.state_file)

    @property
    def backup_dir(self) -> Path:
        return self.resolve(self.firewall.backup_dir)

    @property
    def database_path(self) -> Path:
        return self.resolve(self.database.path)

    @property
    def report_dir(self) -> Path:
        return self.resolve(self.report.output_dir)

    @property
    def log_file(self) -> Path:
        return self.resolve(self.logging.file)

    @property
    def table_ref(self) -> str:
        """``inet sentinelfw`` - the only object SentinelFW may modify."""
        return f"{self.firewall.family} {self.firewall.table}"

    @property
    def chain_ref(self) -> str:
        return f"{self.firewall.family} {self.firewall.table} {self.firewall.chain}"

    @property
    def log_prefix(self) -> str:
        return self.firewall.log_prefix.strip() or "SENTINELFW"

    # -- (de)serialisation -------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("root_dir", "config_path"):
            data.pop(key, None)
        return data

    def permissions_warning(self) -> str | None:
        """Warn when the config file is readable by other users."""
        path = self.config_path
        try:
            mode = path.stat().st_mode & 0o777
        except OSError:
            return None
        if mode & 0o077:
            return (
                f"{path} is mode {mode:04o}; it should be 0600. "
                f"Run: chmod 600 {path}"
            )
        return None

    def harden_permissions(self) -> None:
        for target, mode in (
            (self.config_path, 0o600),
            (self.state_file, 0o600),
        ):
            if target.exists():
                try:
                    target.chmod(mode)
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def _as_bool(value: Any, key: str, errors: list[str]) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "yes", "on", "1"}:
        return True
    if isinstance(value, str) and value.lower() in {"false", "no", "off", "0"}:
        return False
    errors.append(f"{key}: expected a boolean, got {value!r}")
    return False


def _as_int(value: Any, key: str, errors: list[str], minimum: int | None = None) -> int:
    try:
        out = int(value)
    except (TypeError, ValueError):
        errors.append(f"{key}: expected an integer, got {value!r}")
        return minimum if minimum is not None else 0
    if minimum is not None and out < minimum:
        errors.append(f"{key}: must be >= {minimum}, got {out}")
        return minimum
    return out


def _as_float(value: Any, key: str, errors: list[str], minimum: float | None = None) -> float:
    try:
        out = float(value)
    except (TypeError, ValueError):
        errors.append(f"{key}: expected a number, got {value!r}")
        return minimum if minimum is not None else 0.0
    if minimum is not None and out < minimum:
        errors.append(f"{key}: must be >= {minimum}, got {out}")
        return minimum
    return out


def _as_str(value: Any, key: str, errors: list[str], choices: tuple[str, ...] | None = None) -> str:
    if not isinstance(value, str):
        errors.append(f"{key}: expected a string, got {value!r}")
        return ""
    if choices and value not in choices:
        errors.append(f"{key}: must be one of {', '.join(choices)}, got {value!r}")
    return value


def _as_str_list(value: Any, key: str, errors: list[str]) -> list[str]:
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return list(value)
    errors.append(f"{key}: expected a list of strings, got {value!r}")
    return []


def _as_int_list(value: Any, key: str, errors: list[str], low: int, high: int) -> list[int]:
    out: list[int] = []
    if not isinstance(value, list):
        errors.append(f"{key}: expected a list, got {value!r}")
        return out
    for item in value:
        try:
            port = int(item)
        except (TypeError, ValueError):
            errors.append(f"{key}: {item!r} is not a valid port number")
            continue
        if not low <= port <= high:
            errors.append(f"{key}: port {port} outside {low}-{high}")
            continue
        out.append(port)
    return out


_VALID_NFT_IDENT = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
_NFT_RESERVED = {"table", "chain", "rule", "set", "map", "add", "delete", "flush", "list", "type", "policy", "hook", "priority"}


def _validate_identifier(value: str, key: str, errors: list[str]) -> str:
    if not value:
        errors.append(f"{key}: must not be empty")
        return value
    if not set(value) <= _VALID_NFT_IDENT:
        errors.append(
            f"{key}: {value!r} may only contain letters, digits and underscore"
        )
    if value[0].isdigit():
        errors.append(f"{key}: {value!r} must not start with a digit")
    if value in _NFT_RESERVED:
        errors.append(f"{key}: {value!r} is a reserved nftables keyword")
    return value


def _build_section(cls: type, raw: Any, prefix: str, errors: list[str]):
    """Coerce a raw mapping into a dataclass, collecting every problem."""
    instance = cls()
    if raw is None:
        return instance
    if not isinstance(raw, Mapping):
        errors.append(f"{prefix}: expected a mapping, got {type(raw).__name__}")
        return instance

    type_map = {
        "bool": bool,
        "int": int,
        "float": float,
        "str": str,
    }
    for f in fields(cls):
        if f.name not in raw:
            continue
        value = raw[f.name]
        key = f"{prefix}.{f.name}"
        kind = type_map.get(f.type) if isinstance(f.type, str) else f.type
        if kind is bool:
            setattr(instance, f.name, _as_bool(value, key, errors))
        elif kind is int:
            minimum = 0 if f.name in {"backup_keep", "retention_days", "batch_size",
                                      "busy_timeout_ms", "max_bytes", "backup_count",
                                      "top_n", "max_events", "read_since_minutes"} else None
            setattr(instance, f.name, _as_int(value, key, errors, minimum))
        elif kind is float:
            minimum = 0.0 if f.name in {"command_timeout", "poll_interval",
                                        "refresh_seconds"} else None
            setattr(instance, f.name, _as_float(value, key, errors, minimum))
        elif kind is str:
            setattr(instance, f.name, _as_str(value, key, errors))
        elif f.name == "log_files":
            instance.log_files = _as_str_list(value, key, errors)
        elif f.name == "watch_ports":
            instance.watch_ports = _as_int_list(value, key, errors, 1, 65535)
    return instance


def _validate_semantics(cfg: AppConfig, errors: list[str]) -> None:
    fw = cfg.firewall
    _validate_identifier(fw.table, "firewall.table", errors)
    _validate_identifier(fw.chain, "firewall.chain", errors)
    _validate_identifier(fw.family, "firewall.family", errors)
    _validate_identifier(fw.hook, "firewall.hook", errors)
    if fw.family not in {"inet", "ip", "ip6", "bridge"}:
        errors.append("firewall.family: use inet, ip, ip6 or bridge")
    if fw.policy not in {"accept", "drop"}:
        errors.append("firewall.policy: must be 'accept' or 'drop'")
    if not -300 <= fw.priority <= 300:
        errors.append("firewall.priority: must be between -300 and 300")
    if fw.log_level not in {"emerg", "alert", "crit", "err", "warn",
                            "notice", "info", "debug"}:
        errors.append("firewall.log_level: invalid syslog level")
    # The prefix is interpolated inside log prefix "..." in the nft script, so
    # spaces, quotes and backslashes would break the quoting.
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,16}", fw.log_prefix or ""):
        errors.append(
            "firewall.log_prefix: use 1-16 letters, digits, '-' or '_' only "
            "(no spaces or quotes)"
        )

    if cfg.monitoring.source not in {"journal", "file", "demo"}:
        errors.append("monitoring.source: use journal, file or demo")
    if cfg.report.default_period.strip() == "":
        errors.append("report.default_period: must not be empty")

    det = cfg.detection
    for name in ("port_scan_threshold", "brute_force_threshold", "spike_threshold",
                 "repeated_block_threshold"):
        if getattr(det, name) < 2:
            errors.append(f"detection.{name}: must be >= 2 to avoid alert storms")
    for name in ("port_scan_window_seconds", "brute_force_window_seconds",
                 "spike_window_seconds", "repeated_block_window_seconds"):
        if getattr(det, name) < 5:
            errors.append(f"detection.{name}: must be >= 5 seconds")


def config_from_mapping(data: Mapping[str, Any], *, config_path: Path | None = None,
                        root_dir: Path | None = None) -> AppConfig:
    """Build an :class:`AppConfig` from a raw mapping, validating everything."""
    errors: list[str] = []
    cfg = AppConfig(
        root_dir=Path(root_dir) if root_dir else ROOT_DIR,
        config_path=Path(config_path) if config_path else ROOT_DIR / CONFIG_FILENAME,
        firewall=_build_section(FirewallSettings, data.get("firewall"), "firewall", errors),
        database=_build_section(DatabaseSettings, data.get("database"), "database", errors),
        monitoring=_build_section(MonitoringSettings, data.get("monitoring"), "monitoring", errors),
        detection=_build_section(DetectionSettings, data.get("detection"), "detection", errors),
        report=_build_section(ReportSettings, data.get("report"), "report", errors),
        logging=_build_section(LoggingSettings, data.get("logging"), "logging", errors),
        dashboard=_build_section(DashboardSettings, data.get("dashboard"), "dashboard", errors),
    )
    _validate_semantics(cfg, errors)
    if errors:
        raise ConfigValidationError(
            "Configuration is invalid:\n  - " + "\n  - ".join(errors),
            hint="Fix config.yaml or regenerate it with 'sentinelfw config init --force'.",
        )
    return cfg


# ---------------------------------------------------------------------------
# Loading / saving
# ---------------------------------------------------------------------------
def config_search_paths() -> list[Path]:
    """Candidate config locations, most specific first."""
    candidates: list[Path] = []
    env_value = os.environ.get(ENV_CONFIG_PATH)
    if env_value:
        candidates.append(Path(env_value).expanduser())
    candidates.append(Path.cwd() / CONFIG_FILENAME)
    candidates.append(ROOT_DIR / CONFIG_FILENAME)
    return candidates


def default_config_path() -> Path:
    return ROOT_DIR / CONFIG_FILENAME


def load_config(
    path: str | os.PathLike[str] | None = None,
    *,
    create: bool = False,
    require: bool = False,
) -> AppConfig:
    """Load the configuration.

    Parameters
    ----------
    path:
        Explicit file to read. Skips the search list.
    create:
        Write a commented default config when none exists.
    require:
        Raise instead of falling back to defaults when nothing is found.
    """
    search = [Path(path).expanduser()] if path else config_search_paths()
    chosen = next((p for p in search if p.is_file()), None)

    if chosen is None:
        target = search[0] if path else (Path.cwd() / CONFIG_FILENAME
                                         if not os.environ.get(ENV_CONFIG_PATH)
                                         else Path(os.environ[ENV_CONFIG_PATH]).expanduser())
        if create:
            log.info("No config found; creating %s", target)
            save_config(config_from_mapping({}, config_path=target), path=target)
            chosen = target
        elif require:
            raise ConfigNotFoundError(
                f"Configuration file not found: {target}",
                hint="Create it with: sentinelfw config init",
            )
        else:
            log.debug("No config file found; using built-in defaults")
            return config_from_mapping({}, config_path=target)

    try:
        raw_text = chosen.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigNotFoundError(f"Cannot read config {chosen}: {exc}") from exc

    try:
        # safe_load only: no arbitrary object construction from YAML tags.
        data = yaml.safe_load(raw_text) or {}
    except yaml.YAMLError as exc:
        raise ConfigValidationError(
            f"{chosen} is not valid YAML: {exc}",
            hint="Indentation errors are the usual cause. Check with: python3 -c \"import yaml,sys;yaml.safe_load(open(sys.argv[1]))\" " + str(chosen),
        ) from exc

    if not isinstance(data, Mapping):
        raise ConfigValidationError(
            f"{chosen} must contain a YAML mapping at the top level."
        )

    unknown = sorted(set(data) - {f.name for f in fields(AppConfig)})
    if unknown:
        log.warning("Ignoring unknown config keys: %s", ", ".join(unknown))

    cfg = config_from_mapping(data, config_path=chosen)

    warning = cfg.permissions_warning()
    if warning:
        log.warning("%s", warning)
    return cfg


def save_config(cfg: AppConfig, path: str | os.PathLike[str] | None = None) -> Path:
    """Persist ``cfg`` atomically with mode 0600."""
    target = Path(path).expanduser() if path else cfg.config_path
    payload = {k: v for k, v in cfg.to_dict().items()}
    header = (
        "# SentinelFW configuration\n"
        f"# Generated: {now_iso()}\n"
        "# Permissions should stay 0600 (chmod 600 "
        f"{target.name}).\n"
        "# Every relative path is resolved against the project root: "
        f"{cfg.root_dir}\n\n"
    )
    body = yaml.safe_dump(payload, sort_keys=False, default_flow_style=False,
                          allow_unicode=True)
    written = atomic_write_text(target, header + body, mode=0o600)
    ensure_dir(target.parent)
    log.info("Configuration written to %s (mode 0600)", written)
    return written


CONFIG_TEMPLATE = """\
# SentinelFW configuration
# ------------------------
# SentinelFW keeps this file at mode 0600 because it records the exact
# firewall posture of this machine. Do not commit it (it is in .gitignore).
#
# Relative paths below are resolved against the SentinelFW project directory.

firewall:
  # SentinelFW ONLY ever writes inside this table. It will never touch
  # tables created by other tools (docker, ufw, libvirt, ...).
  table: sentinelfw
  family: inet
  chain: input
  hook: input
  # -10 runs our chain before the normal filter chain, so our drops win.
  # policy stays 'accept' so SentinelFW can never lock you out of SSH.
  priority: -10
  policy: accept
  log_enabled: true
  log_level: info
  log_prefix: SENTINELFW
  state_file: rules.yaml
  backup_dir: backups
  backup_keep: 20
  command_timeout: 15.0
  sync_state_on_change: true

database:
  path: database/events.db
  retention_days: 90
  busy_timeout_ms: 5000
  batch_size: 200

monitoring:
  # journal = journalctl -kf (recommended on Kali/systemd)
  # file   = tail a log file such as /var/log/kern.log
  # demo   = generated synthetic traffic (no root needed, for learning)
  source: journal
  log_files:
    - /var/log/kern.log
    - /var/log/syslog
  journal_identifier: kernel
  follow: true
  poll_interval: 1.0
  read_since_minutes: 5
  batch_size: 200
  # Logs EVERY incoming SYN. Useful for full visibility, very noisy.
  enable_syn_logging: false

detection:
  port_scan_threshold: 20
  port_scan_window_seconds: 60
  brute_force_threshold: 100
  brute_force_window_seconds: 300
  spike_threshold: 300
  spike_window_seconds: 60
  repeated_block_threshold: 50
  repeated_block_window_seconds: 600
  alert_cooldown_seconds: 900
  watch_ports: [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306,
                3389, 5432, 5900, 6379, 8080, 8443, 27017]

report:
  output_dir: reports
  default_period: 24h
  top_n: 10

logging:
  level: INFO
  file: logs/sentinelfw.log
  max_bytes: 5242880
  backup_count: 5

dashboard:
  refresh_seconds: 3.0
  default_range: 24h
  top_n: 8
  max_events: 12
"""


def write_template(path: str | os.PathLike[str] | None = None, *, force: bool = False) -> Path:
    """Write the commented starter configuration."""
    target = Path(path).expanduser() if path else default_config_path()
    if target.exists() and not force:
        raise SentinelFWError(
            f"{target} already exists.",
            hint="Pass --force to overwrite it.",
        )
    written = atomic_write_text(target, CONFIG_TEMPLATE, mode=0o600)
    log.info("Wrote configuration template to %s", written)
    return written