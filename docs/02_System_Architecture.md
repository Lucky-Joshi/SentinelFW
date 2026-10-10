# 02 — System Architecture

## Overview

SentinelFW is organised into four layers, each with a single responsibility.
The full diagrams are in `diagrams/` and embedded in the final report
(`10_Final_Project_Report.pdf`).

```
Presentation   cli/interface.py, cli/console.py, dashboard/terminal.py
Service        firewall manager, log collector, detection engine,
               report generator, explain knowledge base
Domain         firewall/rules.py, firewall/nft_manager.py,
               firewall/backup.py, monitor/log_parser.py
Infrastructure SQLite, nft binary, systemd journal / log files,
               config.yaml, rules.yaml, rotating logs
```

## Diagram index

| Diagram | File |
|---|---|
| Layered architecture | `diagrams/architecture.svg` |
| Component / dependency | `diagrams/component.svg` |
| Use case | `diagrams/usecase.svg` |
| `firewall apply` control flow | `diagrams/flowchart_apply.svg` |
| Detection sequence | `diagrams/sequence_detect.svg` |
| Monitoring activity | `diagrams/activity_monitor.svg` |
| Deployment | `diagrams/deployment.svg` |
| Database ER | `diagrams/er_diagram.svg` |

## Layering rules

- The **presentation** layer never touches the kernel directly; it dispatches
  into the service layer. The dashboard reads the database for display, a
  deliberate read-only exception.
- The **service** layer owns policy: whether to apply, detect or persist.
- The **domain** layer owns correctness: validation, rendering, parsing,
  ordering, conflict detection.
- **Infrastructure** is the only place `nft`, files, SQLite and the journal are
  touched.

## Principal data flows

### Firewall flow

```
block-ip/allow-ip/block-port/allow-port
        │  validate + duplicate/contradiction check
        ▼
    rules.yaml  ──(firewall apply)──►  render full nft script
        │                                   │ print
        │                                   │ backup live ruleset
        │                                   │ confirm
        │                                   │ nft -c -f -  (check)
        │                                   │ nft -f -     (atomic)
        ▼                                   ▼
   source of truth                    verify by read-back
```

### Monitoring flow

```
log source (journal | file | stdin | demo)
        │
        ▼
NFLogParser ──► FirewallEvent ──► batch buffer ──► SQLite (bulk INSERT)
                                                       │
                        DetectionEngine ── aggregate SQL over window
                                │
                     fingerprint de-dup + cooldown
                                │
                        alerts (evidence + recommendations)
                                │
             ┌──────────────────┼───────────────────┐
             ▼                  ▼                   ▼
        dashboard          reports              explain
```

## Failure isolation

- A rule change cannot fail the kernel because it never reaches it.
- A failed `apply` cannot leave a broken chain: it flushes only its own chain
  and applies as one transaction.
- A malformed input cannot reach the generated script.
- A log source that is unavailable produces a clean error, never a crash.
- A database write is transactional; the collector and CLI share one guarded
  connection.

See `SAFETY.md` for the invariants and the tests that enforce them.
