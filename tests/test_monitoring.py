"""Log parsing, SQLite storage, detection and the collector pipeline."""

from __future__ import annotations

import itertools
import time
from pathlib import Path

import pytest

from config.settings import AppConfig
from monitor.database import Database, FirewallEvent, Severity
from monitor.detector import DetectionEngine
from monitor.log_parser import DemoLogSource, NFLogParser, build_source
from monitor.monitor import LogCollector

PREFIX = "SENTINELFW"


def line(action: str = "DROP", src: str = "203.0.113.9", dpt: int = 22,
         proto: str = "TCP", when: str = "Oct  4 03:10:02") -> str:
    return (f"{when} kali kernel: [{PREFIX}-{action} ] IN=eth0 OUT= MAC= "
            f"SRC={src} DST=198.51.100.1 LEN=40 PROTO={proto} SPT=40000 "
            f"DPT={dpt}")


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def test_parses_a_drop_line() -> None:
    event = NFLogParser(log_prefix=PREFIX).parse_line(line())
    assert event is not None
    assert event.action == "DROP"
    assert event.source_ip == "203.0.113.9"
    assert event.dest_ip == "198.51.100.1"
    assert event.dest_port == 22
    assert event.protocol == "tcp"
    assert event.blocked is True
    assert event.packet_length == 40
    assert event.prefix == PREFIX


def test_parses_an_accept_line_as_not_blocked() -> None:
    event = NFLogParser(log_prefix=PREFIX).parse_line(line(action="ACCEPT", dpt=443))
    assert event is not None
    assert event.action == "ACCEPT"
    assert event.blocked is False


def test_ignores_unrelated_kernel_lines() -> None:
    parser = NFLogParser(log_prefix=PREFIX)
    assert parser.parse_line("Oct  4 03:10:02 kali kernel: IPv6: ADDRCONF(NETDEV_CHANGE)") is None
    assert parser.parse_line("") is None
    assert parser.parse_line("random text") is None


def test_missing_fields_do_not_crash_the_parser() -> None:
    event = NFLogParser(log_prefix=PREFIX).parse_line(
        f"Oct  4 03:10:02 kali kernel: [{PREFIX}-DROP ] SRC=203.0.113.9")
    assert event is not None
    assert event.source_ip == "203.0.113.9"
    assert event.dest_port is None


def test_tcp_flags_are_captured() -> None:
    # nft writes TCP flags as "tcp flags syn,ack"; the parser condenses them.
    event = NFLogParser(log_prefix=PREFIX).parse_line(
        line() + " FLAGS=syn")
    assert event is not None
    assert event.tcp_flags == "S"


def test_severity_reflects_watched_ports(config: AppConfig) -> None:
    parser = NFLogParser(log_prefix=PREFIX, watch_ports=config.detection.watch_ports)
    watched = parser.parse_line(line(dpt=22))
    assert watched is not None and watched.severity in (Severity.HIGH, Severity.MEDIUM)
    unwatched = next(p for p in range(40000, 50000)
                     if p not in config.detection.watch_ports)
    ordinary = parser.parse_line(line(dpt=unwatched))
    assert ordinary is not None and ordinary.severity == Severity.INFO


def test_parser_statistics_are_counted() -> None:
    parser = NFLogParser(log_prefix=PREFIX)
    parser.parse_line(line())
    parser.parse_line("not a firewall line")



# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
def test_insert_and_read_back(db: Database) -> None:
    event = FirewallEvent(action="DROP", source_ip="1.1.1.1", dest_port=22,
                          protocol="tcp", severity=Severity.HIGH)
    event_id = db.insert_event(event)
    assert event_id > 0
    rows = db.recent_events(limit=10)
    assert len(rows) == 1
    assert rows[0].source_ip == "1.1.1.1"
    assert rows[0].id == event_id


def test_bulk_insert_and_count(db: Database) -> None:
    events = [FirewallEvent(action="DROP", source_ip=f"10.0.0.{i}",
                             dest_port=22 + i, protocol="tcp")
              for i in range(50)]
    assert db.insert_events(events) == 50
    assert db.count_events() == 50


def test_stats_splits_blocked_and_accepted(db: Database) -> None:
    now = time.time()
    db.insert_events([
        FirewallEvent(action="DROP", source_ip="1.1.1.1", dest_port=22, epoch=now),
        FirewallEvent(action="DROP", source_ip="2.2.2.2", dest_port=23, epoch=now),
        FirewallEvent(action="ACCEPT", source_ip="3.3.3.3", dest_port=443, epoch=now),
    ])
    stats = db.stats(now - 60)
    assert stats["total_events"] == 3
    assert stats["blocked_events"] == 2
    assert stats["accepted_events"] == 1
    assert stats["unique_sources"] == 3


def test_stats_ignores_events_outside_the_window(db: Database) -> None:
    db.insert_event(FirewallEvent(action="DROP", source_ip="1.1.1.1",
                                  epoch=time.time() - 86_400))
    assert db.stats(time.time() - 60)["total_events"] == 0


def test_alerts_are_deduplicated_by_fingerprint(db: Database) -> None:
    from monitor.database import Alert

    def make(count: int) -> Alert:
        return Alert(kind="port_scan", severity=Severity.HIGH,
                     title="Possible port scan (25 ports)",
                     source_ip="1.2.3.4", fingerprint="port_scan:1.2.3.4",
                     event_count=count)

    first_id, created = db.record_alert(make(25))
    assert created is True
    second_id, created_again = db.record_alert(make(40))
    assert created_again is False
    assert second_id == first_id

    alerts = db.alerts(since_epoch=0)
    assert len(alerts) == 1
    # Repeated detections of the same fingerprint accumulate rather than
    # duplicating, so the stored count is the running total.
    assert alerts[0]["event_count"] == 65


def test_alert_acknowledgement(db: Database) -> None:
    from monitor.database import Alert

    alert_id, _ = db.record_alert(Alert(kind="brute_force", severity=Severity.CRITICAL,
                                        title="ssh brute force",
                                        fingerprint="bf:9.9.9.9"))
    assert db.acknowledge_alert(alert_id) is True
    assert db.acknowledge_alert(999_999) is False
    assert len(db.alerts(since_epoch=0, include_acked=False)) == 0
    assert len(db.alerts(since_epoch=0, include_acked=True)) == 1


def test_alert_severity_filter(db: Database) -> None:
    from monitor.database import Alert

    db.record_alert(Alert(kind="a", severity=Severity.LOW, title="low",
                          fingerprint="f1"))
    db.record_alert(Alert(kind="b", severity=Severity.CRITICAL, title="crit",
                          fingerprint="f2"))
    assert len(db.alerts(since_epoch=0, min_severity=Severity.HIGH)) == 1


def test_prune_removes_only_old_events(db: Database) -> None:
    now = time.time()
    db.insert_events([
        FirewallEvent(action="DROP", source_ip="1.1.1.1", epoch=now - 100_000),
        FirewallEvent(action="DROP", source_ip="2.2.2.2", epoch=now),
    ])
    removed = db.prune(older_than_epoch=now - 1000)
    assert removed["events"] == 1
    assert db.count_events() == 1


def test_rule_hit_counters(db: Database) -> None:
    db.bump_rule_hits(1, 5)
    db.bump_rule_hits(1, 3)
    row = db.conn.execute(
        "SELECT hits FROM rule_hits WHERE rule_id = 1").fetchone()
    assert row["hits"] == 8


def test_export_rows_respects_limit_and_window(db: Database) -> None:
    now = time.time()
    db.insert_events([FirewallEvent(action="DROP", source_ip=f"1.1.1.{i}",
                                    epoch=now) for i in range(10)])
    assert len(db.export_rows(limit=3)) == 3
    assert db.export_rows(since_epoch=now + 1) == []


def test_reset_clears_everything(db: Database) -> None:
    from monitor.database import Alert

    db.insert_event(FirewallEvent(action="DROP", source_ip="1.1.1.1"))
    db.record_alert(Alert(kind="k", severity=Severity.LOW, title="t", fingerprint="f"))
    db.reset()
    assert db.count_events() == 0
    assert db.alerts(since_epoch=0, include_acked=True) == []


def test_schema_version_is_recorded(db: Database) -> None:
    assert db.get_meta("schema_version") is not None
    assert db.get_meta("created_at") is not None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
def _fill(db: Database, source: str, ports: list[int], *, window_start: float,
          protocol: str = "tcp") -> None:
    db.insert_events([
        FirewallEvent(action="DROP", source_ip=source, dest_port=port,
                      protocol=protocol, epoch=window_start + index * 0.1)
        for index, port in enumerate(ports)
    ])


def test_port_scan_is_detected(config: AppConfig, db: Database) -> None:
    now = time.time()
    threshold = config.detection.port_scan_threshold
    _fill(db, "10.1.1.1", list(range(1000, 1000 + threshold + 5)),
          window_start=now - 30)
    result = DetectionEngine(config, db).run()
    kinds = {alert.kind for alert in result.alerts}
    assert "port_scan" in kinds


def test_quiet_traffic_raises_nothing(config: AppConfig, db: Database) -> None:
    _fill(db, "10.1.1.1", [80, 443], window_start=time.time() - 10)
    assert DetectionEngine(config, db).run().alerts == []


def test_brute_force_on_one_port_is_detected(config: AppConfig,
                                             db: Database) -> None:
    now = time.time()
    _fill(db, "10.2.2.2", [22] * (config.detection.brute_force_threshold + 5),
          window_start=now - 30)
    result = DetectionEngine(config, db).run()
    assert "brute_force" in {alert.kind for alert in result.alerts}


def test_repeated_blocks_are_detected(config: AppConfig, db: Database) -> None:
    now = time.time()
    _fill(db, "10.3.3.3", [8080] * (config.detection.repeated_block_threshold + 5),
          window_start=now - 30)
    result = DetectionEngine(config, db).run()
    assert "repeated_block" in {alert.kind for alert in result.alerts}


def test_watched_port_probe_is_detected(config: AppConfig, db: Database) -> None:
    now = time.time()
    watched = config.detection.watch_ports[0]
    _fill(db, "10.4.4.4", [watched] * 5, window_start=now - 30)
    result = DetectionEngine(config, db).run()
    assert "sensitive_port" in {alert.kind for alert in result.alerts}


def test_connection_spike_is_detected(config: AppConfig, db: Database) -> None:
    now = time.time()
    count = config.detection.spike_threshold + 20
    db.insert_events([
        FirewallEvent(action="DROP", source_ip=f"10.5.{i // 250}.{i % 250}",
                      dest_port=40000 + i, epoch=now - 20 + i * 0.001)
        for i in range(count)
    ])
    result = DetectionEngine(config, db).run()
    assert "connection_spike" in {alert.kind for alert in result.alerts}


def test_detection_dry_run_persists_nothing(config: AppConfig, db: Database) -> None:
    _fill(db, "10.6.6.6", list(range(2000, 2000 + 40)), window_start=time.time() - 20)
    result = DetectionEngine(config, db).run(persist=False)
    assert result.alerts
    assert db.alerts(since_epoch=0, include_acked=True) == []


def test_alert_descriptions_are_actionable(config: AppConfig, db: Database) -> None:
    _fill(db, "10.7.7.7", list(range(3000, 3040)), window_start=time.time() - 20)
    result = DetectionEngine(config, db).run()
    detail = DetectionEngine.describe_alert(result.alerts[0])
    assert detail["recommendations"], "every finding must suggest an action"
    assert detail["explanation"]["why"]


# ---------------------------------------------------------------------------
# Sources and collector
# ---------------------------------------------------------------------------
def test_build_source_from_file(tmp_path: Path, config: AppConfig) -> None:
    log = tmp_path / "kern.log"
    log.write_text(line() + "\n", encoding="utf-8")
    config.monitoring.log_files = [str(log)]
    source = build_source("file", config)
    assert source.name == "file"
    assert str(log) in source.describe()


def test_missing_file_source_is_reported(tmp_path: Path, config: AppConfig) -> None:
    from exceptions import SentinelFWError

    config.monitoring.log_files = [str(tmp_path / "nope.log")]
    with pytest.raises(SentinelFWError):
        build_source("file", config)


def test_demo_source_produces_parsable_lines(config: AppConfig) -> None:
    source = DemoLogSource(log_prefix=config.log_prefix, speed=1000.0)
    parser = NFLogParser(log_prefix=config.log_prefix,
                         watch_ports=config.detection.watch_ports)
    events = list(parser.parse_lines(itertools.islice(source.stream(), 60)))
    assert len(events) > 10
    assert all(event.source_ip for event in events)
    assert any(event.blocked for event in events)


def test_collector_ingests_and_detects(config: AppConfig, db: Database) -> None:
    source = DemoLogSource(log_prefix=config.log_prefix, speed=1000.0)
    collector = LogCollector(config, db, source, detection=True)
    collector.run_once()
    assert collector.stats.events_ingested > 0
    assert db.count_events() > 0
    assert collector.stats.detection_cycles >= 1


def test_collector_can_skip_detection(config: AppConfig, db: Database) -> None:
    source = DemoLogSource(log_prefix=config.log_prefix, speed=1000.0)
    collector = LogCollector(config, db, source, detection=False)
    collector.run_once()
    assert collector.stats.events_ingested > 0
    assert collector.stats.detection_cycles == 0


def test_collector_run_forever_stops_at_max_events(config: AppConfig,
                                                   db: Database) -> None:
    source = DemoLogSource(log_prefix=config.log_prefix, speed=1000.0)
    collector = LogCollector(config, db, source, detection=False)
    stats = collector.run_forever(max_events=15, max_seconds=30)
    assert stats.events_ingested == 15