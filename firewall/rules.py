"""Rule model, validation and persistence.

This module is pure logic: it decides *what* an nftables expression should be,
whether the input is sane, and how rules are stored on disk. It never calls
``nft`` and never needs root, which makes it trivial to unit test.

Safety notes
------------
* Every rule lives inside SentinelFW's own table (see
  :mod:`firewall.nft_manager`). Nothing here can express a command against
  another table.
* User-supplied text (comments) is sanitised before it reaches an nftables
  string, because a comment is embedded in a quoted nft expression.
* Rules are ordered so that allow-rules are evaluated *before* drop-rules.
  Without this, ``allow-ip 10.0.0.5`` would be useless once
  ``block-port 22`` exists.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

import yaml

from exceptions import RuleConflictError, RuleValidationError, SentinelFWError
from logsetup import get_logger
from utils import atomic_write_text, now_iso

log = get_logger("firewall.rules")

__all__ = [
    "Rule",
    "RuleStore",
    "RuleAction",
    "RuleKind",
    "VALID_PROTOCOLS",
    "validate_ip_or_network",
    "validate_port",
    "validate_protocol",
    "sanitize_comment",
    "local_addresses",
    "port_service_name",
]

#: SentinelFW only emits these protocols. ``any`` expands to tcp + udp rules.
VALID_PROTOCOLS = ("tcp", "udp", "any", "icmp")


class RuleAction:
    """Verdict applied to matching packets."""

    DROP = "drop"
    ACCEPT = "accept"
    REJECT = "reject"
    LOG = "log"

    ALL = (DROP, ACCEPT, REJECT, LOG)


class RuleKind:
    """What the rule matches."""

    IP_BLOCK = "ip_block"
    IP_ALLOW = "ip_allow"
    PORT_BLOCK = "port_block"
    PORT_ALLOW = "port_allow"
    ESTABLISHED = "established"
    SYN_LOG = "syn_log"
    CUSTOM = "custom"

    ALL = (IP_BLOCK, IP_ALLOW, PORT_BLOCK, PORT_ALLOW, ESTABLISHED, SYN_LOG, CUSTOM)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def validate_ip_or_network(value: str) -> str:
    """Validate an IPv4/IPv6 address or CIDR network, returning it normalised."""
    if not isinstance(value, str) or not value.strip():
        raise RuleValidationError("An IP address or network is required.")
    text = value.strip()
    try:
        if "/" in text:
            net = ipaddress.ip_network(text, strict=False)
            if net.num_addresses > 65536:
                raise RuleValidationError(
                    f"{text} is too broad ({net.num_addresses} addresses).",
                    hint="Blocking /0 or a huge prefix would cut off all traffic. "
                         "Use a /24 or smaller.",
                )
            return str(net)
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise RuleValidationError(
            f"{text!r} is not a valid IP address or network.",
            hint="Examples: 45.33.22.1, 10.0.0.0/24, 2001:db8::1",
        ) from exc


def validate_port(value: Any) -> int:
    """Validate a TCP/UDP port number."""
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise RuleValidationError(f"{value!r} is not a valid port number.") from exc
    if not 1 <= port <= 65535:
        raise RuleValidationError(
            f"Port {port} is out of range.",
            hint="Valid ports are 1-65535.",
        )
    return port


def validate_protocol(value: str | None) -> str:
    """Validate a protocol keyword (case-insensitive)."""
    if value is None or value == "":
        return "any"
    text = str(value).strip().lower()
    if text in {"all", "any", "ip"}:
        return "any"
    if text not in {"tcp", "udp", "icmp"}:
        raise RuleValidationError(
            f"Unsupported protocol {value!r}.",
            hint="Use tcp, udp, icmp or any.",
        )
    return text


def sanitize_comment(text: str | None, max_length: int = 110) -> str:
    """Make arbitrary user text safe to embed in an nftables quoted string.

    nftables comments live inside ``"..."``. A quote, a backslash or a newline
    would either break the expression or allow a second rule to be injected
    through the comment field, so all three are stripped. ``;`` is stripped as
    well: nft's parser honours the quoting today, but a rule comment is a human
    note and never needs a statement separator, so there is no reason to lean
    on that behaviour.
    """
    if not text:
        return ""
    cleaned = str(text).replace("\\", "").replace('"', "").replace("\n", " ")
    cleaned = cleaned.replace(";", ",")
    cleaned = " ".join(cleaned.split())
    return cleaned[:max_length]


def local_addresses() -> set[str]:
    """Best-effort set of this host's addresses, used to warn about
    "block the machine I am sitting at" mistakes."""
    found: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(str(info[4][0]))
    except OSError:
        pass
    try:
        with open("/proc/net/fib_trie") as handle:  # pragma: no cover - env specific
            for line in handle:
                if "/32 host LOCAL" in line or "/128 host LOCAL" in line:
                    parts = line.split()
                    if parts:
                        found.add(parts[0])
    except OSError:
        pass
    return {a for a in found if a and not a.startswith("127.")}


#: Small service-name table so reports and dashboards read like a human wrote
#: them. Intentionally short: this is a hint, not /etc/services.
_SERVICE_NAMES: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog",
    587: "submission", 631: "ipp", 873: "rsync", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1723: "pptp", 1900: "ssdp", 2049: "nfs",
    3128: "squid-proxy", 3306: "mysql", 3389: "rdp", 4444: "metasploit-default",
    5000: "upnp/flask", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9000: "php-fpm/sonarqube", 9200: "elasticsearch", 27017: "mongodb",
}


def port_service_name(port: int | None) -> str:
    """Best-effort service label for a port."""
    if port is None:
        return ""
    try:
        import socket as _s

        return _s.getservbyport(int(port), "tcp") or _SERVICE_NAMES.get(int(port), "")
    except OSError:
        return _SERVICE_NAMES.get(int(port), "")


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------
@dataclass
class Rule:
    """One SentinelFW-managed nftables rule.

    A single :class:`Rule` may expand into more than one nft expression: a
    ``port_block`` with protocol ``any`` becomes a TCP rule and a UDP rule.
    """

    kind: str
    action: str
    value: str | None = None
    protocol: str = "any"
    comment: str = ""
    enabled: bool = True
    origin: str = "manual"
    created_at: str = field(default_factory=now_iso)
    updated_at: str = ""
    id: int | None = None

    # -- construction helpers ---------------------------------------------
    def __post_init__(self) -> None:
        self.kind = str(self.kind).strip().lower()
        self.action = str(self.action).strip().lower()
        if self.kind not in RuleKind.ALL:
            raise RuleValidationError(
                f"Unknown rule kind {self.kind!r}.",
                hint=f"Valid kinds: {', '.join(RuleKind.ALL)}",
            )
        if self.action not in RuleAction.ALL:
            raise RuleValidationError(
                f"Unknown action {self.action!r}.",
                hint=f"Valid actions: {', '.join(RuleAction.ALL)}",
            )
        self.protocol = validate_protocol(self.protocol)
        self.comment = sanitize_comment(self.comment)
        self.value = self._validate_value()
        self.origin = str(self.origin or "manual").strip().lower()
        if self.origin not in {"manual", "detector", "import", "builtin"}:
            self.origin = "manual"

    def _validate_value(self) -> str | None:
        if self.kind in (RuleKind.IP_BLOCK, RuleKind.IP_ALLOW):
            return validate_ip_or_network(self.value or "")
        if self.kind in (RuleKind.PORT_BLOCK, RuleKind.PORT_ALLOW):
            port = validate_port(self.value)
            return str(port)
        if self.kind in (RuleKind.ESTABLISHED, RuleKind.SYN_LOG):
            return None
        if self.kind == RuleKind.CUSTOM:
            value = (self.value or "").strip()
            if not value:
                raise RuleValidationError(
                    "A custom rule needs a match expression.",
                    hint="Example value: 'tcp dport 8080'",
                )
            if "\n" in value or ";" in value.rstrip(";"):
                # Statements are separated by ';' inside one chain body; a raw
                # newline would allow an extra rule to be smuggled in.
                raise RuleValidationError(
                    "Custom rules must be a single nftables expression "
                    "(no newlines or statement separators).",
                )
            return value
        return self.value

    # -- classification ----------------------------------------------------
    @property
    def is_ip_rule(self) -> bool:
        return self.kind in (RuleKind.IP_BLOCK, RuleKind.IP_ALLOW)

    @property
    def is_port_rule(self) -> bool:
        return self.kind in (RuleKind.PORT_BLOCK, RuleKind.PORT_ALLOW)

    @property
    def is_allow(self) -> bool:
        return self.action == RuleAction.ACCEPT or self.kind in (
            RuleKind.IP_ALLOW, RuleKind.PORT_ALLOW, RuleKind.ESTABLISHED,
        )

    @property
    def verdict(self) -> str:
        """Upper-case action label used in listings."""
        if self.kind == RuleKind.SYN_LOG:
            return "LOG"
        return self.action.upper()

    @property
    def sort_key(self) -> tuple[int, int, str]:
        """Ordering inside the chain.

        Lower sorts first, i.e. is evaluated first by nftables:

        0. allow rules      - a trusted host must beat a blanket port block
        1. established      - keep existing sessions alive before dropping
        2. SYN logging      - visibility
        3. IP blocks
        4. port blocks      - most general match, evaluated last
        """
        if self.kind == RuleKind.IP_ALLOW:
            group = 0
        elif self.kind == RuleKind.ESTABLISHED:
            group = 1
        elif self.kind == RuleKind.SYN_LOG:
            group = 2
        elif self.kind == RuleKind.IP_BLOCK:
            group = 3
        elif self.kind == RuleKind.PORT_BLOCK:
            group = 4
        elif self.kind == RuleKind.PORT_ALLOW:
            group = 5
        else:
            group = 6
        # Within a group, specific beats general: an /32 allow before a /24.
        prefix_len = 32
        if self.is_ip_rule and self.value and "/" in self.value:
            prefix_len = ipaddress.ip_network(self.value, strict=False).prefixlen
        return (group, -prefix_len, self.value or "")

    # -- nftables rendering ------------------------------------------------
    def to_nft(self, *, log_enabled: bool = True, log_level: str = "info",
               log_prefix: str = "SENTINELFW", family: str = "inet") -> list[str]:
        """Render this rule as one or more nftables rule expressions.

        The returned strings are complete rule bodies (no braces, no trailing
        semicolon) and are safe to concatenate into an ``nft -f`` script.
        """
        parts: list[str] = []
        verdict = self.action
        counter = "counter"
        if verdict == RuleAction.LOG:
            counter = ""

        comment = f'comment "{self.comment}"' if self.comment else ""

        if self.kind in (RuleKind.IP_BLOCK, RuleKind.IP_ALLOW):
            family_key = "ip" if (self.value and ":" not in self.value) else "ip6"
            if family == "inet" and self.value:
                family_key = "ip" if ":" not in self.value else "ip6"
            match = f"{family_key} saddr {self.value}"
            parts.append(self._compose(match, verdict, counter, comment,
                                       log_enabled, log_level, log_prefix))
            return parts

        if self.kind in (RuleKind.PORT_BLOCK, RuleKind.PORT_ALLOW):
            protocols = ("tcp", "udp") if self.protocol == "any" else (self.protocol,)
            if self.protocol == "icmp":
                protocols = ("icmp",)
            for proto in protocols:
                if proto == "icmp":
                    match = f"ip protocol icmp"
                else:
                    match = f"{proto} dport {self.value}"
                parts.append(self._compose(match, verdict, counter, comment,
                                           log_enabled, log_level, log_prefix))
            return parts

        if self.kind == RuleKind.ESTABLISHED:
            match = "ct state { established, related }"
            parts.append(self._compose(match, RuleAction.ACCEPT, counter, comment,
                                       False, log_level, log_prefix))
            return parts

        if self.kind == RuleKind.SYN_LOG:
            match = "meta l4proto tcp tcp flags & (syn | ack) == syn"
            tokens = [match, counter,
                      f'log prefix "{log_prefix}-SYN " level {log_level}']
            if comment:
                tokens.append(comment)
            parts.append(" ".join(t for t in tokens if t))
            return parts

        if self.kind == RuleKind.CUSTOM:
            parts.append(self._compose(self.value or "", verdict, counter, comment,
                                       log_enabled, log_level, log_prefix))
            return parts

        return parts

    def _compose(self, match: str, verdict: str, counter: str, comment: str,
                 log_enabled: bool, log_level: str, log_prefix: str) -> str:
        """Assemble ``<match> counter [log] <verdict> [comment]``."""
        tokens = [match, counter]
        if log_enabled and verdict in (RuleAction.DROP, RuleAction.REJECT,
                                       RuleAction.ACCEPT) and verdict != "log":
            tokens.append(f'log prefix "{log_prefix}-{verdict.upper()} " level {log_level}')
        elif verdict == RuleAction.LOG:
            tokens.append(f'log prefix "{log_prefix}-LOG " level {log_level}')
        tokens.append(verdict)
        if comment:
            tokens.append(comment)
        return " ".join(t for t in tokens if t)

    # -- presentation ------------------------------------------------------
    @property
    def target(self) -> str:
        """Human-readable match target, e.g. ``192.168.1.5`` or ``tcp/22``."""
        if self.is_ip_rule:
            return self.value or "-"
        if self.is_port_rule:
            port = int(self.value or 0)
            service = port_service_name(port)
            proto = self.protocol if self.protocol != "any" else "tcp/udp"
            return f"{proto}/{port}" + (f" ({service})" if service else "")
        if self.kind == RuleKind.ESTABLISHED:
            return "established,related"
        if self.kind == RuleKind.SYN_LOG:
            return "incoming SYN"
        return self.value or "-"

    def describe(self) -> str:
        """One-line description used by ``firewall list``."""
        return f"{self.verdict:<6} {self.kind.replace('_', ' '):<12} {self.target}"

    # -- (de)serialisation -------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Rule":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        payload = {k: v for k, v in data.items() if k in known}
        # Tolerate rules written by older versions missing optional keys.
        payload.setdefault("kind", RuleKind.CUSTOM)
        payload.setdefault("action", RuleAction.DROP)
        return cls(**payload)

    def clone(self) -> "Rule":
        return Rule.from_dict(self.to_dict())


# ---------------------------------------------------------------------------
# Rule store
# ---------------------------------------------------------------------------
class RuleStore:
    """Persistent, human-readable rule list stored in ``rules.yaml``.

    Why a separate file from ``config.yaml``? Configuration describes *how* the
    tool behaves; this file describes *what* is blocked. Keeping them apart
    means a mistake in one does not silently rewrite the other, and the rules
    can be backed up, diffed and version-controlled on their own.
    """

    STATE_VERSION = 1

    def __init__(self, path: str | Path, *, logger: Any | None = None) -> None:
        self.path = Path(path)
        self.log = logger or log
        self._rules: list[Rule] = []
        self._next_id = 1
        self._loaded = False

    # -- lifecycle ---------------------------------------------------------
    def load(self) -> "RuleStore":
        """Read the state file. A missing file is a valid empty store."""
        self._rules = []
        self._next_id = 1
        self._loaded = True
        if not self.path.is_file():
            self.log.debug("Rule state file %s does not exist yet", self.path)
            return self

        try:
            raw = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise SentinelFWError(
                f"{self.path} is not valid YAML: {exc}",
                hint="Fix or move the file; SentinelFW will not guess at its contents.",
            ) from exc
        except OSError as exc:
            raise SentinelFWError(f"Cannot read {self.path}: {exc}") from exc

        if not isinstance(raw, dict):
            raise SentinelFWError(f"{self.path} must contain a YAML mapping.")

        version = raw.get("version", self.STATE_VERSION)
        if version > self.STATE_VERSION:
            raise SentinelFWError(
                f"{self.path} was written by a newer SentinelFW (state v{version}).",
                hint="Upgrade SentinelFW or export your rules before downgrading.",
            )

        for entry in raw.get("rules") or []:
            try:
                rule = Rule.from_dict(entry)
            except RuleValidationError as exc:
                self.log.warning("Skipping invalid stored rule %r: %s", entry, exc)
                continue
            if rule.id is None:
                rule.id = self._next_id
            self._next_id = max(self._next_id, rule.id + 1)
            self._rules.append(rule)

        self.log.debug("Loaded %d rule(s) from %s", len(self._rules), self.path)
        return self

    def save(self) -> Path:
        """Atomically persist the store with mode 0600."""
        payload = {
            "version": self.STATE_VERSION,
            "updated_at": now_iso(),
            "note": (
                "Managed by SentinelFW. Entries here are the source of truth; "
                "'sentinelfw firewall apply' mirrors them into the nftables "
                "table configured in config.yaml."
            ),
            "rules": [r.to_dict() for r in self.sorted_rules()],
        }
        text = yaml.safe_dump(payload, sort_keys=False, default_flow_style=False,
                              allow_unicode=True)
        return atomic_write_text(self.path, text, mode=0o600)

    # -- access ------------------------------------------------------------
    def __iter__(self) -> Iterator[Rule]:
        return iter(self.rules)

    def __len__(self) -> int:
        return len(self._rules)

    @property
    def rules(self) -> list[Rule]:
        self._ensure_loaded()
        return list(self._rules)

    def sorted_rules(self) -> list[Rule]:
        """Rules in evaluation order (see :attr:`Rule.sort_key`)."""
        return sorted(self.rules, key=lambda r: r.sort_key)

    def get(self, rule_id: int) -> Rule | None:
        self._ensure_loaded()
        for rule in self._rules:
            if rule.id == rule_id:
                return rule
        return None

    def enabled_rules(self) -> list[Rule]:
        return [r for r in self.sorted_rules() if r.enabled]

    def find_duplicate(self, rule: Rule) -> Rule | None:
        """Return an existing rule that expresses the same thing."""
        self._ensure_loaded()
        for existing in self._rules:
            if (existing.kind == rule.kind and existing.action == rule.action
                    and str(existing.value) == str(rule.value)
                    and existing.protocol == rule.protocol):
                return existing
        return None

    def find_contradiction(self, rule: Rule) -> Rule | None:
        """Return an existing rule that directly opposes ``rule``.

        Used to warn about, for example, ``allow-ip 10.0.0.5`` when
        ``ip_block 10.0.0.0/24`` already exists. A contradiction is not fatal:
        nftables resolves it by order, and ordering is deterministic here.
        """
        self._ensure_loaded()
        if not rule.is_ip_rule or not rule.value:
            return None
        try:
            new_net = ipaddress.ip_network(rule.value, strict=False)
        except ValueError:
            return None
        for existing in self._rules:
            if not existing.is_ip_rule or not existing.value:
                continue
            try:
                old_net = ipaddress.ip_network(existing.value, strict=False)
            except ValueError:
                continue
            if old_net.version != new_net.version:
                continue
            overlap = (
                new_net.subnet_of(old_net) if old_net.prefixlen <= new_net.prefixlen
                else old_net.subnet_of(new_net)
            )
            if not overlap:
                continue
            if existing.is_allow != rule.is_allow:
                return existing
        return None

    # -- mutation ----------------------------------------------------------
    def add(self, rule: Rule, *, allow_duplicate: bool = False,
            allow_contradiction: bool = False) -> Rule:
        """Add a rule, assigning an id and persisting the file."""
        self._ensure_loaded()
        if not rule.enabled:
            rule.enabled = True
        duplicate = self.find_duplicate(rule)
        if duplicate and not allow_duplicate:
            raise RuleConflictError(
                f"An identical rule already exists (id {duplicate.id}): "
                f"{duplicate.describe()}",
                hint="Nothing to do. Use 'firewall remove <id>' to delete it first.",
            )
        contradiction = self.find_contradiction(rule)
        if contradiction and not allow_contradiction:
            self.log.warning(
                "New rule contradicts id %s (%s); nftables order will decide.",
                contradiction.id, contradiction.describe(),
            )
        if rule.id is None:
            rule.id = self._next_id
            self._next_id += 1
        self._rules.append(rule)
        self.save()
        self.log.info("Rule #%d added: %s", rule.id, rule.describe())
        return rule

    def remove(self, rule_id: int) -> Rule:
        self._ensure_loaded()
        rule = self.get(rule_id)
        if rule is None:
            raise SentinelFWError(
                f"No rule with id {rule_id}.",
                hint="Run 'sentinelfw firewall list' to see valid ids.",
            )
        self._rules = [r for r in self._rules if r.id != rule_id]
        self.save()
        self.log.info("Rule #%d removed: %s", rule_id, rule.describe())
        return rule

    def set_enabled(self, rule_id: int, enabled: bool) -> Rule:
        self._ensure_loaded()
        rule = self.get(rule_id)
        if rule is None:
            raise SentinelFWError(f"No rule with id {rule_id}.")
        rule.enabled = enabled
        rule.updated_at = now_iso()
        self.save()
        return rule

    def replace_all(self, rules: Iterable[Rule]) -> None:
        """Overwrite the whole store (used when re-syncing from nftables)."""
        self._rules = []
        self._next_id = 1
        for rule in rules:
            rule.id = self._next_id
            self._next_id += 1
            self._rules.append(rule)
        self.save()

    def next_rule_id(self, *, offset: int = 0) -> int:
        """The id that ``offset``-th from the end will receive (for previews)."""
        self._ensure_loaded()
        return self._next_id + offset

    # -- internals ---------------------------------------------------------
    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()