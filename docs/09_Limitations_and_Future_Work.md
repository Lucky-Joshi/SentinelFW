# 09 — Limitations and Future Work

## 1. Scope limitations

| Area | Limitation |
|---|---|
| Rule model | Single host, single chain; no NAT, forwarding, mangle or per-interface rules |
| Users | No authentication or roles; access equals filesystem access |
| Backend | Requires the `nft` binary; no `iptables`/`nftables`-library backend |
| Input | No packet capture, payload inspection or signature matching |
| Scale | Optimised for a single host, not fleets or remote management |
| Detection | Threshold heuristics, not behavioural or ML models |

## 2. Technical limitations

### 2.1 Kernel paths are not exercised in tests

The suite proves that root-only operations **refuse** without root, and that the
generated script is correct and contained. It does not prove that a live kernel
accepts the generated syntax — that requires touching a firewall and is
deliberately excluded. `firewall preview` and `firewall validate` exist so a
human can verify on a machine they control.

### 2.2 Detector evasiveness

Threshold-and-window detection is transparent and tunable but evadable. A
low-and-slow scan below `port_threshold` in the window is invisible. Raising
sensitivity increases false positives.

### 2.3 Metadata is sensitive

The event database holds source IPs, ports and timestamps. This is not a secret
store, but it is not public either; retention and file permissions are the
controls.

### 2.4 Restore is global

`firewall restore` must use `nft flush ruleset`, which clears every table,
including Docker's and UFW's. This is unavoidable for a full snapshot and is
warned about explicitly.

### 2.5 Environment assumptions

Monitoring assumes access to the systemd journal or readable log files; without
the right group membership it degrades to `file`/`stdin` sources.

## 3. Future work

### Near term

1. **Rule sets and profiles** — save and switch named rule sets (e.g. travel,
   office, lockdown).
2. **Time-limited rules** — auto-expiring blocks with a duration.
3. **Allow-list precedence UI** — make ordering and shadowing visible before
   apply.
4. **Structlog-style audit trail** — append-only application of every rule
   change with actor and reason.

### Medium term

5. **Additional detectors** — SYN-flood heuristics, repeated-auth patterns,
   egress anomalies.
6. **Multi-interface and egress rules** — extend the rule model beyond inbound.
7. **Prometheus/OpenMetrics export** — expose counters for existing monitoring.
8. **Geo/ASN enrichment** — optional offline annotation of source addresses.

### Long term

9. **Pluggable backend** — swap nftables for another engine behind the same
   interface.
10. **Fleet mode** — central collection with per-host agents.
11. **Behavioural baseline** — learn normal traffic per host and flag deviation
    instead of fixed thresholds.
12. **Signed rule bundles** — integrity-check shared rule sets.

## 4. Prioritisation rationale

The near-term items reinforce the project's core promise — safe, explained
changes — before broadening capability. Remote fleet management and ML detection
are deliberately last: they add the most complexity and the least to a
single-host learner's safety.
