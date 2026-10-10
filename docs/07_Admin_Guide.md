# 07 — Administrator Guide

## 1. Configuration

`config.yaml` is created with `sentinelfw config init` and validated with
`sentinelfw config check`. Relative paths resolve next to the configuration
file. `sentinelfw config path` prints the config and state locations.

Principal defaults:

| Setting | Default | Purpose |
|---|---|---|
| `database.path` | `state/sentinelfw.db` | SQLite store |
| `rules_file` | `rules.yaml` | Firewall source of truth |
| `backup_dir` | `backups/` | Ruleset snapshots |
| `log_level` | `INFO` | Logging verbosity |
| `retention_days` | `30` | Event retention |
| `alert_cooldown_seconds` | `300` | De-dup window |
| `detection.port_scan.port_threshold` | `20` | Ports per window |
| `detection.brute_force.attempt_threshold` | `100` | Attempts per port |
| `dashboard.refresh_seconds` | `2` | Dashboard refresh |

## 2. Permissions and hardening

```bash
sudo sentinelfw config harden --apply   # chmod 0600 config.yaml and rules.yaml
```

- Configuration and rule files contain no secrets by design, but are still
  restricted to `0600`.
- The configuration is parsed with `yaml.safe_load`; object tags and custom
  constructors are refused.
- The database is stored under the state directory with restrictive umask.

## 3. Privilege model

Only these operations need root and each refuses cleanly without it:

| Operation | Needs root |
|---|---|
| `firewall preview` | No |
| `firewall validate` | Yes |
| `firewall apply` | Yes |
| `firewall backup` | Yes |
| `firewall restore` | Yes |
| `firewall flush --apply` | Yes |
| `monitor start --source journal` | Usually (journal access) |

## 4. Log sources

### systemd journal

The recommended source. Add the operator to the `systemd-journal` group so
monitoring works without root:

```bash
sudo usermod -aG systemd-journal "$USER"
```

If journal access is unrelated to SentinelFW's own rules, point detection at the
relevant unit or filter.

### Enabling traffic logging

SentinelFW's chain logs only what its own rules match. To observe inbound
attempts, enable SYN logging:

```bash
sudo sentinelfw firewall enable-logging
sudo sentinelfw firewall enable-logging --off   # disable
```

This is deliberately noisy; use it for observation, not permanently.

## 5. Retention and maintenance

```bash
sentinelfw monitor prune --period 30d
sentinelfw monitor prune --all
sentinelfw monitor vacuum
sentinelfw db stats
sentinelfw db export --format csv --output events.csv
```

Schedule `prune` and `vacuum` with a timer if the host is long-lived.

## 6. Backups and recovery

- `firewall apply` snapshots the live ruleset into `backup_dir` unless
  `--no-backup` is given.
- `firewall backups` lists snapshots; `--diff OLD NEW` compares two.
- `firewall restore TARGET` reinstalls a snapshot.

Recovery procedure after a bad change:

1. `sentinelfw firewall backups` — choose a known-good snapshot.
2. `sudo sentinelfw firewall restore <name>`.
3. `sentinelfw firewall status` — confirm the backend and rule sync.

## 7. Deployment notes

- Prefer running the collector as a dedicated service user with journal access
  rather than as root.
- The CLI and collector share one SQLite database; WAL mode allows concurrent
  reads while the collector writes.
- Keep `rules.yaml` under version control; it is the intended audit trail.

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `permission denied` on apply | Not root | Re-run with `sudo` |
| No events collected | Wrong source or no journal access | Check `monitor status`; add to `systemd-journal` |
| Detection seems idle | Thresholds too high / no matching traffic | Run `monitor demo`, tune thresholds |
| `nft` not found | nftables missing | Install the `nftables` package |
| Dashboard needs a wider window | Default range too narrow | `dashboard --range 24h` |

Run `sentinelfw doctor` first for any of these.
