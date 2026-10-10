# 06 — User Manual

## 1. What SentinelFW does

SentinelFW manages a single nftables chain and monitors the traffic that chain
logs. You record rules in a file, preview the exact kernel script, apply it when
you are ready, and watch the resulting events.

## 2. Installation

```bash
git clone https://github.com/Lucky-Joshi/SentinelFW.git
cd SentinelFW
python3 -m pip install -e .
```

Requirements: Linux with nftables, Python 3.10+, and root only for operations
that touch the kernel.

## 3. First run

```bash
sentinelfw doctor        # check the machine for problems
sentinelfw config init   # create config.yaml
sentinelfw config show   # print the effective configuration
```

`doctor` reports whether Python, nftables, permissions and the database are in
order, and what to fix if not.

## 4. Managing rules

Rules are stored in `rules.yaml`. Adding a rule never touches the kernel unless
you pass `--apply` or later run `firewall apply`.

```bash
sentinelfw firewall block-ip 203.0.113.10
sentinelfw firewall block-port 23 --protocol tcp
sentinelfw firewall allow-ip 192.168.1.0/24
sentinelfw firewall list                 # configured rules
sentinelfw firewall list --live          # what the kernel currently holds
```

| Command | Purpose |
|---|---|
| `block-ip ADDR` / `allow-ip ADDR` | Block/allow an address or network |
| `block-port PORT` / `allow-port PORT` | Block/allow a TCP/UDP port |
| `remove ID` | Delete a rule |
| `enable ID` / `disable ID` | Toggle a rule |
| `list` | Show configured rules |
| `flush` | Delete all SentinelFW rules |

Useful flags: `--apply` applies immediately after the change, `--force` overrides
a duplicate/contradiction warning, `--comment` attaches a note.

## 5. Preview, validate, apply, revert

Always preview before applying:

```bash
sentinelfw firewall preview        # print the exact nft script
sudo sentinelfw firewall validate  # syntax-check with nft
sudo sentinelfw firewall apply     # snapshot, confirm, apply, verify
```

- `apply` refuses without root, takes a backup first, and asks for confirmation.
- `--no-backup` skips the snapshot (not recommended).
- `sentinelfw firewall backups` lists snapshots; `--diff OLD NEW` compares them.
- `sudo sentinelfw firewall restore TARGET` rolls back.

If anything goes wrong, `flush` removes only SentinelFW's own table.

## 6. Monitoring

```bash
sentinelfw monitor demo --seconds 60      # generate synthetic traffic
sentinelfw monitor start --source journal # live collection + detection
sentinelfw monitor poll --source file --file /var/log/kern.log
sentinelfw monitor ingest /var/log/kern.log
sentinelfw monitor status
```

Sources: `journal` (systemd), `file`, `stdin`, `demo`.

## 7. Alerts

```bash
sentinelfw alerts list
sentinelfw alerts list --severity high --explain
sentinelfw alerts show <fingerprint>
sentinelfw alerts ack <fingerprint>
```

Detectors:

| Kind | Meaning |
|---|---|
| `port_scan` | One source touching many ports |
| `brute_force` | Sustained attempts on one port |
| `repeated_block` | Frequent hits on a closed port |
| `connection_spike` | Overall connection surge |
| `sensitive_port` | Traffic to a watched port |

## 8. Reports and dashboard

```bash
sentinelfw report generate --period 24h
sentinelfw report generate --period 7d --format markdown --save
sentinelfw report list
sentinelfw dashboard            # live view, refresh with --once for one frame
```

## 9. Explain

```bash
sentinelfw explain port 22
sentinelfw explain attack port_scan
sentinelfw explain event --last 1
```

`explain` translates a port, a detector kind, or a stored event into plain
language with a recommended action.

## 10. Global flags

`--config PATH`, `--dry-run`, `--no-color`, `--json`, `--debug`, `--version`.

## 11. Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Generic error |
| 2 | Usage error |
| 3 | Permission denied (needs root) |
| 4 | Validation error |
| 5 | Confirmation required |
| 6 | Backend/command failure |

## 12. Uninstall / cleanup

```bash
sentinelfw monitor reset --yes     # clear events and alerts
sentinelfw firewall flush --apply  # remove SentinelFW's nft table
```

The tool only ever owns the table `inet sentinelfw`; the rest of your ruleset
is untouched.
