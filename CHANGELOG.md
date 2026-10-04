# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-04

First release.

### Added

**Firewall**

- `firewall block-ip` / `allow-ip` for addresses and networks, `block-port` /
  `allow-port` for TCP and UDP ports, each with a `-r` reason stored with the rule.
- `firewall list`, `status`, `preview`, `remove`, `enable`, `disable`, `flush`.
- `firewall enable-logging` to produce the `SENTINELFW-*` log lines the monitor
  parses.
- `firewall backup`, `backups`, `restore`, and `validate`.
- `rules.yaml` as the source of truth; rule changes never reach the kernel
  without an explicit `firewall apply`.
- `firewall apply` shows the whole nft script, takes a backup, asks for
  confirmation, applies atomically with `nft -f -`, then verifies the result by
  reading the live ruleset back.
- `--live` comparison between `rules.yaml` and what the kernel actually has.
- Detection and warning of rules made unreachable by ordering, and of
  allow/allow and drop/drop conflicts on the same target.

**Monitoring**

- Log sources: systemd journal, log files, stdin and a synthetic demo stream.
- SQLite storage with indexed queries, retention pruning and `vacuum`.
- Five detectors: `port_scan`, `brute_force`, `repeated_block`,
  `connection_spike` and `sensitive_port`, all with configurable thresholds and
  windows.
- Alerts de-duplicated by fingerprint with a cooldown, and each stores the
  evidence behind it.
- `monitor start`, `poll`, `ingest`, `demo`, `status`, `detect`, `prune`,
  `vacuum` and `reset`.

**Analysis and reporting**

- `explain port`, `explain attack` and `explain event` with a knowledge base of
  ports, attack patterns and remediation steps.
- `report generate` in text, markdown and JSON, with `--brief` and `--save`;
  `report list` of saved reports.
- `alerts list`, `show` and `ack`.
- Responsive Rich dashboard with a `--once` snapshot mode.
- `db stats` and `db export` to JSON or CSV.
- `doctor` for environment and permissions checks.

**Configuration and safety**

- `config.yaml` created at mode 0600 with commented defaults, validated
  against a typed schema, loaded with `yaml.safe_load` only.
- `config init`, `show`, `path`, `check` and `harden`.
- Explicit `--config` / `SENTINELFW_CONFIG` paths are authoritative and resolve
  relative state next to the chosen file.
- Global flags (`--yes`, `--json`, `--verbose`, `--debug`, `--dry-run`,
  `--no-color`) accepted at any position in the command line.
- Structured exit codes, one exception class per anticipated failure, each with
  a hint, and a top-level handler so failures print a message instead of a
  traceback.
- Rotating logs that record every nft command the tool runs.

### Security

- All rules are confined to `table inet sentinelfw`, chain `input`, base chain
  priority `-10`, policy `accept`; the nft layer refuses any other table.
- Applying flushes only SentinelFW's own chain, never the table, so a failed
  apply cannot leave a dangling hook.
- Addresses are parsed with `ipaddress` and ports are range-checked, so neither
  can inject syntax into the generated script.
- Rule comments are stripped of quotes, backslashes, newlines and `;`;
  multi-line custom rules are rejected.
- Mutations refuse to proceed without a terminal confirmation unless `--yes`
  is given.
- `firewall restore` states plainly that it flushes the entire ruleset,
  including Docker and UFW, before doing it.
- `config harden` sets 0600 on the config and rules files; runtime state
  directories are gitignored.

### Notes

- Requires Python 3.10 or newer, and the `nftables` package for anything that
  changes the live ruleset.
- The root-only paths are `firewall apply`, `validate`, `backup` and `restore`,
  plus journal reads where the user lacks `systemd-journal` access.
- Tested on Kali Linux with Python 3.14, nftables 1.1.7 and SQLite 3.53.

[1.0.0]: https://github.com/Lucky-Joshi/SentinelFW/releases/tag/v1.0.0