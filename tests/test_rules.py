"""Rule validation, rendering and the containment guarantees of the nft layer."""

from __future__ import annotations

from pathlib import Path

import pytest

from config.settings import AppConfig
from exceptions import RuleValidationError, SentinelFWError
from firewall.nft_manager import NFTManager
from firewall.rules import (
    Rule,
    RuleAction,
    RuleKind,
    RuleStore,
    port_service_name,
    validate_ip_or_network,
    validate_port,
    validate_protocol,
)


# ---------------------------------------------------------------------------
# Value validation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "value,expected",
    [("1.2.3.4", "1.2.3.4"), ("10.0.0.0/16", "10.0.0.0/16"),
     ("2001:db8::1", "2001:db8::1"), ("  8.8.8.8  ", "8.8.8.8")],
)
def test_valid_ip_or_network(value: str, expected: str) -> None:
    assert validate_ip_or_network(value) == expected


@pytest.mark.parametrize(
    "value", ["", "   ", "not-an-ip", "999.1.1.1", "1.2.3", "1.2.3.4/33", None]
)
def test_invalid_ip_values_are_rejected(value: str | None) -> None:
    with pytest.raises(RuleValidationError):
        validate_ip_or_network(value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["0.0.0.0/0", "10.0.0.0/4"])
def test_absurdly_broad_networks_are_rejected(value: str) -> None:
    """A /0 block would disconnect the machine."""
    with pytest.raises(RuleValidationError):
        validate_ip_or_network(value)


@pytest.mark.parametrize("value,expected", [("22", 22), (443, 443), (" 8080 ", 8080)])
def test_valid_ports(value: object, expected: int) -> None:
    assert validate_port(value) == expected


@pytest.mark.parametrize("value", ["0", "65536", "-1", "abc", "22.5", "", None])
def test_invalid_ports_are_rejected(value: object) -> None:
    with pytest.raises(RuleValidationError):
        validate_port(value)


def test_protocol_normalisation() -> None:
    assert validate_protocol("TCP") == "tcp"
    assert validate_protocol("all") == "any"
    assert validate_protocol(None) == "any"
    with pytest.raises(RuleValidationError):
        validate_protocol("sctp")


def test_port_service_name_is_best_effort() -> None:
    assert port_service_name(22) == "ssh"
    assert port_service_name(None) == ""


# ---------------------------------------------------------------------------
# Rule construction
# ---------------------------------------------------------------------------
def test_ip_rule_target() -> None:
    rule = Rule(kind=RuleKind.IP_BLOCK, action=RuleAction.DROP, value="203.0.113.7")
    assert rule.target == "203.0.113.7"
    assert rule.is_ip_rule


def test_port_rule_target_names_the_service() -> None:
    rule = Rule(kind=RuleKind.PORT_BLOCK, action=RuleAction.DROP, value="22",
                protocol="tcp")
    assert "22" in rule.target
    assert "ssh" in rule.target


def test_unknown_kind_or_action_is_rejected() -> None:
    with pytest.raises(RuleValidationError):
        Rule(kind="teleport", action=RuleAction.DROP, value="1.2.3.4")
    with pytest.raises(RuleValidationError):
        Rule(kind=RuleKind.IP_BLOCK, action="obliterate", value="1.2.3.4")


def test_custom_rule_rejects_statement_smuggling() -> None:
    with pytest.raises(RuleValidationError):
        Rule(kind=RuleKind.CUSTOM, action=RuleAction.DROP,
             value="tcp dport 80\nadd rule inet x y")
    with pytest.raises(RuleValidationError):
        Rule(kind=RuleKind.CUSTOM, action=RuleAction.DROP,
             value="tcp dport 80; accept")


# ---------------------------------------------------------------------------
# Injection safety
# ---------------------------------------------------------------------------
def test_comment_cannot_break_out_of_the_nft_quotes() -> None:
    rule = Rule(kind=RuleKind.IP_BLOCK, action=RuleAction.DROP, value="1.2.3.4",
                comment='evil"; drop; #')
    rendered = "\n".join(rule.to_nft(log_prefix="SENTINELFW", log_level="info"))
    assert rendered.count('"') % 2 == 0, rendered
    assert "; drop;" not in rendered, rendered


def test_comment_newlines_cannot_smuggle_a_second_rule() -> None:
    rule = Rule(kind=RuleKind.IP_BLOCK, action=RuleAction.DROP, value="1.2.3.4",
                comment="harmless\nadd rule inet sentinelfw input accept")
    rendered = "\n".join(rule.to_nft(log_prefix="S", log_level="info"))
    assert "\n" not in rendered, rendered


def test_sanitized_comment_is_used() -> None:
    rule = Rule(kind=RuleKind.IP_BLOCK, action=RuleAction.DROP, value="1.2.3.4",
                comment='quote " and \\ backslash')
    rendered = "\n".join(rule.to_nft(log_prefix="S", log_level="info"))
    assert rendered.count('"') % 2 == 0, rendered


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def test_rendered_rule_contains_expected_tokens() -> None:
    rule = Rule(kind=RuleKind.PORT_BLOCK, action=RuleAction.DROP, value="23",
                protocol="tcp", comment="telnet off")
    rendered = rule.to_nft(log_prefix="SENTINELFW", log_level="info")
    assert len(rendered) == 1
    expression = rendered[0]
    assert "tcp dport 23" in expression
    assert "drop" in expression
    assert 'log prefix "SENTINELFW-DROP "' in expression
    assert "counter" in expression
    assert 'comment "telnet off"' in expression


def test_protocol_any_expands_to_tcp_and_udp() -> None:
    rule = Rule(kind=RuleKind.PORT_BLOCK, action=RuleAction.DROP, value="23",
                protocol="any")
    rendered = rule.to_nft(log_prefix="S", log_level="info")
    assert len(rendered) == 2
    joined = "\n".join(rendered)
    assert "tcp dport 23" in joined
    assert "udp dport 23" in joined


def test_logging_can_be_disabled() -> None:
    rule = Rule(kind=RuleKind.IP_BLOCK, action=RuleAction.DROP, value="1.1.1.1")
    rendered = rule.to_nft(log_enabled=False, log_prefix="S")
    assert "log prefix" not in "\n".join(rendered)


def test_sort_key_puts_allows_before_drops() -> None:
    allow = Rule(kind=RuleKind.IP_ALLOW, action=RuleAction.ACCEPT, value="1.1.1.1")
    block = Rule(kind=RuleKind.IP_BLOCK, action=RuleAction.DROP, value="2.2.2.2")
    assert sorted([block, allow], key=lambda r: r.sort_key)[0] is allow


# ---------------------------------------------------------------------------
# Store persistence
# ---------------------------------------------------------------------------
def test_store_round_trips_rules(tmp_path: Path) -> None:
    path = tmp_path / "rules.yaml"
    store = RuleStore(path)
    first = store.add(Rule(kind=RuleKind.IP_BLOCK, action=RuleAction.DROP,
                           value="1.1.1.1", comment="one"))
    second = store.add(Rule(kind=RuleKind.PORT_ALLOW, action=RuleAction.ACCEPT,
                            value="443", protocol="tcp"))
    assert (first.id, second.id) == (1, 2)

    reloaded = RuleStore(path)
    assert [r.value for r in reloaded.rules] == ["1.1.1.1", "443"]
    assert reloaded.rules[0].comment == "one"
    assert reloaded.get(2) is not None


def test_store_file_is_private(tmp_path: Path) -> None:
    path = tmp_path / "rules.yaml"
    RuleStore(path).add(Rule(kind=RuleKind.IP_BLOCK, action=RuleAction.DROP,
                             value="1.1.1.1"))
    assert path.stat().st_mode & 0o077 == 0


def test_duplicate_rule_is_reported(tmp_path: Path) -> None:
    store = RuleStore(tmp_path / "rules.yaml")
    store.add(Rule(kind=RuleKind.IP_BLOCK, action=RuleAction.DROP, value="1.1.1.1"))
    duplicate = Rule(kind=RuleKind.IP_BLOCK, action=RuleAction.DROP, value="1.1.1.1")
    assert store.find_duplicate(duplicate) is not None
    with pytest.raises(SentinelFWError):
        store.add(duplicate)
    # allow_duplicate=True is the escape hatch used by the detector.
    assert store.add(duplicate, allow_duplicate=True).id is not None


def test_contradiction_is_detected(tmp_path: Path) -> None:
    store = RuleStore(tmp_path / "rules.yaml")
    allow = Rule(kind=RuleKind.IP_ALLOW, action=RuleAction.ACCEPT, value="1.2.3.4")
    store.add(allow)
    shadowed_drop = Rule(kind=RuleKind.IP_BLOCK, action=RuleAction.DROP,
                         value="1.2.3.4")
    assert store.find_contradiction(shadowed_drop) is not None


def test_remove_and_toggle(tmp_path: Path) -> None:
    path = tmp_path / "rules.yaml"
    store = RuleStore(path)
    a = store.add(Rule(kind=RuleKind.IP_BLOCK, action=RuleAction.DROP, value="1.1.1.1"))
    b = store.add(Rule(kind=RuleKind.IP_BLOCK, action=RuleAction.DROP, value="2.2.2.2"))

    store.set_enabled(b.id, False)
    assert RuleStore(path).get(b.id).enabled is False
    assert RuleStore(path).get(a.id).enabled is True

    store.remove(b.id)
    assert store.get(b.id) is None
    assert len(RuleStore(path).rules) == 1
    with pytest.raises(SentinelFWError):
        store.remove(999)


def test_corrupt_state_file_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text("rules: [\n  - broken\n", encoding="utf-8")
    with pytest.raises(SentinelFWError) as excinfo:
        RuleStore(path).rules
    assert "rules.yaml" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Script building and containment
# ---------------------------------------------------------------------------
def test_full_script_declares_table_and_chain(config: AppConfig) -> None:
    manager = NFTManager(config)
    script = manager.build_full_script([])
    assert f"add table {config.table_ref}" in script
    assert f"add chain {config.chain_ref}" in script
    assert "policy accept" in script
    # flush chain, never flush table: keeps the hook reference intact.
    assert f"flush chain {config.chain_ref}" in script
    assert f"flush table {config.table_ref}" not in script


def test_script_never_touches_other_tables(config: AppConfig) -> None:
    script = NFTManager(config).build_full_script([])
    for line in script.splitlines():
        stripped = line.strip()
        if stripped.startswith("add table") or stripped.startswith("delete table"):
            assert stripped == f"add table {config.table_ref}", stripped


def test_disabled_rules_are_omitted(config: AppConfig) -> None:
    rules = [
        Rule(kind=RuleKind.IP_BLOCK, action=RuleAction.DROP, value="1.1.1.1"),
        Rule(kind=RuleKind.IP_BLOCK, action=RuleAction.DROP, value="2.2.2.2",
             enabled=False),
    ]
    script = NFTManager(config).build_rules_script(rules)
    assert "1.1.1.1" in script
    assert "2.2.2.2" not in script


def test_script_is_valid_nft_syntax_shaped(config: AppConfig) -> None:
    """Every statement must be balanced and free of stray quotes."""
    rules = [
        Rule(kind=RuleKind.IP_BLOCK, action=RuleAction.DROP, value="1.1.1.1",
             comment="scanner"),
        Rule(kind=RuleKind.PORT_ALLOW, action=RuleAction.ACCEPT, value="443",
             protocol="any"),
    ]
    script = NFTManager(config).build_full_script(rules)
    statements = [line.strip() for line in script.splitlines() if line.strip()]
    assert statements
    for statement in statements:
        assert statement.count("{") == statement.count("}"), statement
        assert statement.count('"') % 2 == 0, statement
        if statement.startswith("add rule"):
            # Rule bodies carry user-supplied values and comments: no stray
            # statement separators may survive inside them.
            assert ";" not in statement.rstrip(";"), statement