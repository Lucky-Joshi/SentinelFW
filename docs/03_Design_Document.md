# 03 — Design Document

## 1. Design principles

1. **Preview before action.** Every kernel change is shown in full first.
2. **One owner.** SentinelFW owns exactly one nftables table.
3. **Fail safe.** A failed operation leaves the machine unchanged.
4. **Human consent.** No mutation without a terminal confirmation or `--yes`.
5. **Data, not code.** Configuration and rules are parsed with `yaml.safe_load`.
6. **No shell.** External commands are argument lists.
7. **Explain, don't just count.** Findings carry evidence and next steps.

## 2. Domain model

### Rule

```
Rule
  id        int
  kind      IP_BLOCK | IP_ALLOW | PORT_BLOCK | PORT_ALLOW | CUSTOM
  action    DROP | ACCEPT
  value     str        (address, network, port, or custom expression)
  protocol  tcp | udp | any
  comment   str        (sanitised)
  enabled   bool
```

Validation: addresses via `ipaddress`, ports range-checked `1–65535`,
protocols against a fixed set, comments stripped of quotes, backslashes,
newlines and `;`, custom rules rejected if they contain a newline or `;`.

`RuleStore` persists JSON/YAML to `rules.yaml` atomically (write to a temporary
file in the same directory, then rename) and enforces mode `0600`. It detects
duplicates and contradictions and controls rule ordering so allows precede
drops.

### FirewallEvent

```
FirewallEvent
  id, timestamp, epoch
  source_ip, dest_ip, protocol, source_port, dest_port
  action (DROP/ACCEPT), prefix, rule_id
  severity (info|low|medium|high|critical)
  packet_length, tcp_flags, raw
```

### Alert

```
Alert
  kind, severity, title, description
  source_ip, dest_port
  fingerprint (unique)
  first_seen, last_seen, first_epoch, last_epoch
  event_count, ports (json), evidence (json), acknowledged
```

## 3. Key workflows

### 3.1 Apply (the only kernel write)

1. Refuse unless root.
2. Build and print the complete script.
3. Snapshot the live ruleset into `backups/`.
4. Confirm, unless `--yes`.
5. `nft -c -f -` syntax check.
6. `nft -f -` atomic apply.
7. Read the live ruleset back and compare.
8. Log every command.

The script builder emits `flush chain`, never `flush table`, so a failed apply
cannot leave a dangling hook reference.

### 3.2 Detection

Every detector is an indexed SQL aggregate over a bounded window, so cost scales
with the window rather than the history. Findings are fingerprinted; a repeated
finding updates one row and is suppressed during `alert_cooldown_seconds`.

| Detector | Trigger | Window |
|---|---|---|
| `port_scan` | 20 distinct ports from one source | 60 s |
| `brute_force` | 100 attempts on one port | 300 s |
| `repeated_block` | 50 hits on one port | 600 s |
| `connection_spike` | 300 connections overall | 60 s |
| `sensitive_port` | any traffic to a watched port | 60 s |

### 3.3 Reporting

`SecurityReport` is assembled once and rendered three ways: Rich text, Markdown
and JSON. It contains statistics, top sources and ports, alerts, hourly
activity, firewall state and recommendations.

## 4. Error handling

Every anticipated failure is a class under `SentinelFWError`, carrying a message,
an optional hint and an exit code. The CLI catches the base class and prints a
clean message instead of a traceback. Exit codes are stable and documented.

## 5. Interfaces

- **CLI** — `sentinelfw <group> <command> [flags]`; global flags accepted before
  or after the command.
- **JSON** — machine-readable commands emit exactly one JSON document.
- **Config** — typed dataclasses with validation; relative paths resolve next to
  the config file.

## 6. Extensibility

- Detectors share a common base; new heuristics implement `detect()`.
- Log sources implement a common `LogSource` interface.
- Report formats share one `SecurityReport` model.
- Schema changes bump `SCHEMA_VERSION` and add a migration in `database.py`.
