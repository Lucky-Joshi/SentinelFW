"""Security knowledge base: what an event means and what to do about it.

Separating this from the detector keeps the detection logic honest - it
decides *whether* something is happening; this module explains *what it means*
in language a human can act on. It is also what powers
``sentinelfw explain attack brute_force``.

No network lookups, no external databases: everything ships with the tool so
explanations work offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from monitor.database import FirewallEvent, Severity, severity_rank

__all__ = [
    "PortInfo",
    "AttackInfo",
    "port_info",
    "explain_port",
    "attack_info",
    "explain_attack",
    "classify_event",
    "explain_event",
    "recommendations_for",
    "SEVERITY_COLORS",
    "SEVERITY_ORDER",
]

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

#: Colour hints for the dashboard/report renderers (kept here so severity
#: presentation is consistent everywhere).
SEVERITY_COLORS = {
    "info": "cyan",
    "low": "green",
    "medium": "yellow",
    "high": "magenta",
    "critical": "bold red",
}


@dataclass
class PortInfo:
    """What a port is and why blocking it may or may not help."""

    port: int
    service: str
    risk: str = "low"
    summary: str = ""
    exposure: str = ""


#: Ports worth calling out. Anything not listed gets a generic profile.
PORT_KNOWLEDGE: dict[int, PortInfo] = {
    21: PortInfo(21, "ftp", "high", "Cleartext file transfer; credentials travel in the clear.",
                 "Often brute-forced by scripted malware."),
    22: PortInfo(22, "ssh", "high", "Remote administration and the single most attacked service on the internet.",
                 "Expect constant password and key-probing attempts on any public IP."),
    23: PortInfo(23, "telnet", "critical", "Unencrypted remote shell, obsolete protocol.",
                 "Should never be exposed. Any hit is almost certainly hostile."),
    25: PortInfo(25, "smtp", "medium", "Mail transfer agent, a common relay-abuse target.",
                 "Open relays get you blacklisted fast."),
    53: PortInfo(53, "dns", "low", "Name resolution; unusual volumes suggest amplification or tunnelling.",
                 "Recursion enabled on an open resolver is a classic amplification source."),
    69: PortInfo(69, "tftp", "high", "Trivial FTP with no authentication.",
                 "Used for PXE booting and for dropping payloads without credentials."),
    80: PortInfo(80, "http", "low", "Plain web traffic.", "Normal background noise on the internet."),
    110: PortInfo(110, "pop3", "medium", "Legacy mail retrieval without TLS."),
    135: PortInfo(135, "msrpc", "high", "Windows RPC endpoint mapper.",
                  "Seen in exploitation chains against SMB and DCOM services."),
    139: PortInfo(139, "netbios-ssn", "high", "Legacy Windows network browsing.",
                  "No legitimate reason to expose it to the internet."),
    445: PortInfo(445, "smb", "critical", "Windows file sharing.",
                  "The backbone of EternalBlue and other worms; block from untrusted networks."),
    1433: PortInfo(1433, "mssql", "high", "Microsoft SQL Server.",
                   "Directly internet-exposed SQL servers are scanned within minutes."),
    3306: PortInfo(3306, "mysql", "high", "MySQL database.",
                   "Credential-stuffing and exploit probes are constant."),
    3389: PortInfo(3389, "rdp", "high", "Remote Desktop Protocol.",
                   "A prime brute-force and credential-harvesting target."),
    4444: PortInfo(4444, "metasploit-default", "critical", "Default listener port of Metasploit payloads.",
                   "Something is likely already running a handler, or you are being scanned by a pentester."),
    5432: PortInfo(5432, "postgresql", "high", "PostgreSQL database."),
    5900: PortInfo(5900, "vnc", "high", "VNC remote desktop.",
                   "Often configured without a password; full desktop control when exposed."),
    6379: PortInfo(6379, "redis", "critical", "Redis.",
                   "Unauthenticated by default; famously used for SSH-key injection and cryptomining."),
    8080: PortInfo(8080, "http-alt", "medium", "Common alternative web port and proxy port.",
                   "Proxy scanners target it to find open relays."),
    8443: PortInfo(8443, "https-alt", "medium", "Alternative HTTPS port."),
    9200: PortInfo(9200, "elasticsearch", "critical", "Elasticsearch.",
                   "Frequently exposed unauthenticated, leaking indices or enabling remote code execution."),
    27017: PortInfo(27017, "mongodb", "critical", "MongoDB.",
                    "Historically defaults to no authentication and has been mass-exploited."),
}

#: Generic risk profile for ports with no specific entry.
_GENERIC_RISK_PORTS = (
    (1024, "low"),
    (1025, "medium"),
    (49152, "low"),
    (65535, "high"),
)


@dataclass
class AttackInfo:
    """A detector's finding, described for a human."""

    kind: str
    title: str
    severity: str
    what: str
    why: str = ""
    indicators: list[str] = field(default_factory=list)
    response: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


ATTACK_KNOWLEDGE: dict[str, AttackInfo] = {
    "port_scan": AttackInfo(
        kind="port_scan",
        title="Possible port scan",
        severity="high",
        what=(
            "A single source address touched many different destination ports in a "
            "short window. Scanners sweep a range to discover what is listening."
        ),
        why=(
            "Nobody legitimately probes 20+ unrelated ports on one host in a minute. "
            "This pattern is reconnaissance: the attacker is building a map of your "
            "exposed services before choosing an exploit."
        ),
        indicators=[
            "Many distinct destination ports from one source",
            "Short inter-request intervals (often well under a second)",
            "Usually a wide or sequential port range",
        ],
        response=[
            "Block the source IP: sentinelfw firewall block-ip <ip>",
            "Close the ports that do not need to be reachable",
            "If the source is on your LAN, identify the host before blocking it",
            "Expect follow-up exploitation attempts against whatever it finds open",
        ],
    ),
    "brute_force": AttackInfo(
        kind="brute_force",
        title="Possible brute force attack",
        severity="critical",
        what=(
            "One source address generated a large number of blocked connections to "
            "the same service, which is the signature of password guessing."
        ),
        why=(
            "Login services cannot distinguish a slow human from a fast script by "
            "request rate alone. Automating thousands of guesses per minute is the "
            "cheapest way to find a weak password."
        ),
        indicators=[
            "Hundreds of packets to one port within minutes",
            "Often paired with a SYN scan in the same window",
            "Source addresses rotate through botnet or proxy pools",
        ],
        response=[
            "Block the source IP immediately",
            "Prefer key-based SSH; disable password authentication",
            "Enable fail2ban or equivalent to rate-limit login attempts",
            "Move SSH to a non-standard port only as noise reduction, not protection",
            "Audit successful logins if the volume is high - the password may have fallen",
        ],
        references=["OWASP Authentication Cheat Sheet"],
    ),
    "connection_spike": AttackInfo(
        kind="connection_spike",
        title="Connection volume spike",
        severity="medium",
        what=(
            "The overall rate of logged connections jumped well above the configured "
            "baseline."
        ),
        why=(
            "A sudden jump is either an attack (flood, scan storm) or a legitimate "
            "event (a backup, a deployment, a crawler). The tool cannot tell which, "
            "so it asks you to."
        ),
        indicators=[
            "Blocked connections rising faster than the configured threshold",
            "Often many distinct sources rather than one",
        ],
        response=[
            "Check whether you started something (backup, update, container restart)",
            "If not, look at the source list: many IPs suggests a coordinated flood",
            "Consider rate limiting rather than blocking individual addresses",
        ],
    ),
    "repeated_block": AttackInfo(
        kind="repeated_block",
        title="Repeated blocked requests",
        severity="medium",
        what=(
            "The same source was blocked repeatedly on the same or similar targets, "
            "which usually means an automated tool rather than a curious human."
        ),
        why=(
            "A legitimate client that hits a closed port once or twice stops. "
            "Hundreds of identical attempts indicate a script."
        ),
        indicators=[
            "Recurring blocks against the same rule",
            "Regular timing between attempts",
        ],
        response=[
            "Block the source IP",
            "Review which rule is firing - the block is working as intended",
            "If the IP belongs to a service you use, allowlist it instead",
        ],
    ),
    "sensitive_port": AttackInfo(
        kind="sensitive_port",
        title="Traffic aimed at a sensitive service",
        severity="high",
        what=(
            "Connections were blocked against a port that should never be reachable "
            "from an untrusted network (databases, remote shells, management ports)."
        ),
        why=(
            "These services have no business facing the open internet. Any inbound "
            "attempt is either misconfiguration or hostile intent."
        ),
        indicators=[
            "Destination in the configured watch_ports list",
            "Source address outside your trusted networks",
        ],
        response=[
            "Keep the block in place",
            "Bind the service to localhost or a private interface",
            "If remote access is required, reach it over a VPN or an SSH tunnel",
        ],
    ),
}


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------
def port_info(port: int | None) -> PortInfo:
    """Return knowledge for ``port``, falling back to a generic profile."""
    if not port:
        return PortInfo(0, "unknown", "info", "No destination port recorded.")
    try:
        port = int(port)
    except (TypeError, ValueError):
        return PortInfo(0, "unknown", "info", f"{port!r} is not a port number.")
    if not 0 <= port <= 65535:
        # getservbyport() raises OverflowError outside this range, so reject
        # early with a readable message.
        return PortInfo(port, "invalid", "info",
                        f"{port} is outside the valid port range 0-65535.")
    known = PORT_KNOWLEDGE.get(port)
    if known:
        return known
    risk = "low"
    for bound, level in _GENERIC_RISK_PORTS:
        if port <= bound:
            risk = level
            break
    try:
        import socket

        service = socket.getservbyport(port, "tcp") or "unknown"
    except (OSError, OverflowError):
        service = "unknown"
    return PortInfo(port, service, risk,
                    f"Port {port} ({service}); no specific risk profile on file.")


def explain_port(port: int) -> dict[str, Any]:
    """Full explanation for a port, used by ``sentinelfw explain port``."""
    info = port_info(port)
    return {
        "port": info.port,
        "service": info.service,
        "risk": info.risk,
        "summary": info.summary,
        "exposure": info.exposure,
        "suggestion": (
            f"sentinelfw firewall block-port {info.port}"
            if info.risk in {"high", "critical"} else "No action suggested."
        ),
    }


def attack_info(kind: str) -> AttackInfo | None:
    return ATTACK_KNOWLEDGE.get(str(kind).strip().lower())


def explain_attack(kind: str) -> dict[str, Any] | None:
    """Full explanation for a detector kind."""
    info = attack_info(kind)
    if info is None:
        return None
    return {
        "kind": info.kind,
        "title": info.title,
        "severity": info.severity,
        "what": info.what,
        "why": info.why,
        "indicators": info.indicators,
        "response": info.response,
        "references": info.references,
    }


# ---------------------------------------------------------------------------
# Event classification
# ---------------------------------------------------------------------------
def classify_event(event: FirewallEvent, *, watch_ports: tuple[int, ...] | list[int] = ()
                   ) -> tuple[str, str]:
    """Assign a severity and a one-line description to a single event.

    Severity is intentionally conservative per *event*: a single dropped packet
    is never "critical". Escalation happens in the detector, which sees patterns
    across many events.
    """
    info = port_info(event.dest_port)
    watch = {int(p) for p in (watch_ports or ())}
    parts: list[str] = []

    if event.action in ("DROP", "REJECT"):
        verb = "Dropped" if event.action == "DROP" else "Rejected"
        parts.append(f"{verb} inbound {event.protocol or 'IP'} to port {info.port}"
                     f" ({info.service})")
    elif event.action == "ACCEPT":
        parts.append(f"Accepted inbound {event.protocol or 'IP'} to port {info.port}")
    else:
        parts.append(f"Logged inbound {event.protocol or 'IP'} packet"
                     + (f" to port {info.port}" if event.dest_port else ""))

    if event.dest_port in watch:
        parts.append("target is a watched service")
        severity = Severity.HIGH if info.risk in {"high", "critical"} else Severity.MEDIUM
    elif info.risk == "critical":
        severity = Severity.HIGH
    elif info.risk == "high":
        severity = Severity.MEDIUM
    elif info.risk == "medium":
        severity = Severity.LOW
    else:
        severity = Severity.INFO

    if event.source_ip:
        from firewall.rules import local_addresses

        if event.source_ip in local_addresses():
            parts.append("source is a local interface address (verify the log prefix is correct)")
            severity = Severity.LOW

    if event.action == "ACCEPT":
        # Traffic we deliberately permit is not a finding, whatever port it hit.
        # Downgrade rather than upgrade: a watched port that was allowed is
        # exactly what an allow-rule is for.
        order = list(SEVERITY_ORDER)
        severity = order[min(severity_rank(severity), order.index(Severity.LOW))]

    return severity, "; ".join(parts)


def explain_event(event: FirewallEvent, *, watch_ports: tuple[int, ...] | list[int] = ()
                  ) -> dict[str, Any]:
    """Rich, human-readable explanation of one stored event."""
    severity, description = classify_event(event, watch_ports=watch_ports)
    info = port_info(event.dest_port)
    lines = [
        f"When   : {event.timestamp}",
        f"Action : {event.action}"
        + ("  (packet was blocked)" if event.blocked else ""),
        f"From   : {event.source_ip or 'unknown'}",
        f"To     : port {event.dest_port or '?'}"
        + (f" ({info.service})" if event.dest_port else ""),
        f"Proto  : {event.protocol or 'unknown'}",
        f"Severity: {severity}",
        "",
        "Meaning:",
        f"  {description}",
    ]
    if info.summary:
        lines.append(f"  {info.service}: {info.summary}")
    if info.exposure:
        lines.append(f"  Typical use of this attack: {info.exposure}")
    if event.blocked:
        lines += ["", "Result: the connection never reached the service."]
    else:
        lines += ["", "Result: the connection was permitted by a SentinelFW rule."]
    return {
        "severity": severity,
        "description": description,
        "text": "\n".join(lines),
        "port": info.port,
        "service": info.service,
    }


def recommendations_for(kind: str, *, source_ip: str | None = None,
                        dest_port: int | None = None) -> list[str]:
    """Actionable next steps for a finding, with commands filled in."""
    info = attack_info(kind)
    steps = list(info.response) if info else []
    concrete: list[str] = []
    if source_ip and kind in {"port_scan", "brute_force", "repeated_block", "sensitive_port"}:
        concrete.append(f"sentinelfw firewall block-ip {source_ip}   # then: firewall apply")
    if dest_port and kind in {"sensitive_port", "brute_force"}:
        concrete.append(
            f"sentinelfw firewall block-port {dest_port} --protocol "
            f"{'tcp' if dest_port not in (53, 123, 1900) else 'udp'}"
        )
    return concrete + steps