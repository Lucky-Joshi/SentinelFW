# 05 — Test Report

## 1. Executive summary

| Metric | Result |
|---|---|
| Test functions | **160** |
| Passed | **160** |
| Failed | 0 |
| Errors | 0 |
| Skipped | 0 |
| Total runtime | **50.93 s** |
| Statement coverage | **72%** |
| Kernel interaction during tests | None |
| Root required during tests | No |

Command used:

```bash
python3 -m pytest
# 160 passed in 50.93s
```

## 2. Environment

| Item | Value |
|---|---|
| OS | Kali Linux (Debian-based) |
| Python | CPython 3.14.7 |
| pytest | 9.1.1 |
| nftables (host) | v1.1.7 |
| SQLite | 3.53.4 |

## 3. Results by module

| Test file | Concern | Tests | Passed | Failed |
|---|---|---|---|---|
| `test_cli.py` | CLI, exit codes, safety | 57 | 57 | 0 |
| `test_rules.py` | Validation, rendering, containment | 46 | 46 | 0 |
| `test_monitoring.py` | Parsing, storage, detection | 33 | 33 | 0 |
| `test_config.py` | Configuration and permissions | 24 | 24 | 0 |
| **Total** | | **160** | **160** | **0** |

## 4. Highlighted results

The complete, case-by-case results are Tables 10–14 in
`10_Final_Project_Report.pdf`. Selected evidence:

| ID | Scenario | Expected | Actual | Status |
|---|---|---|---|---|
| R-03 | Block `0.0.0.0/0` | Rejected (would disconnect host) | `RuleValidationError` | PASS |
| R-12 | Custom rule with embedded newline | Rejected | `RuleValidationError` | PASS |
| R-14 | Comment `evil"; drop; #` | Cannot escape quotes | Balanced output | PASS |
| R-28 | Generated script | `flush chain`, never `flush table` | Correct | PASS |
| R-29 | Script contains only SentinelFW table | No foreign table | Correct | PASS |
| C-09 | `!!python/object` config tag | Rejected; no execution | `ConfigValidationError` | PASS |
| M-12 | Alert de-duplication | One row; count accumulates | Correct | PASS |
| M-20 | Port scan detection | `port_scan` alert | Raised | PASS |
| E-16 | `firewall apply` without root | Exit 3; nothing applied | Correct | PASS |
| E-40 | `--yes` does not bypass duplicate check | Conflict, then `--force` | Correct | PASS |
| S-03 | Non-interactive mutation without `--yes` | Exit 5; no file written | Correct | PASS |

## 5. Coverage

Overall statement coverage is **72%**, concentrated where correctness is most
safety-critical.

| Module | Coverage |
|---|---|
| `exceptions.py` | 100% |
| `monitor/detector.py` | 94% |
| `monitor/explain.py` | 94% |
| `config/settings.py` | 85% |
| `monitor/reports.py` | 85% |
| `firewall/rules.py` | 82% |
| `monitor/database.py` | 82% |
| `firewall/nft_manager.py` | 45% |
| `firewall/backup.py` | 30% |
| **Total** | **72%** |

The low figures for `nft_manager.py` and `backup.py` are expected: their
untested branches are the root-only paths that would touch a live firewall, and
the suite deliberately cannot execute them.

## 6. Performance

| Operation | Median | Note |
|---|---|---|
| DB insert (one event) | 0.06 ms | WAL |
| nft script render | 0.02 ms | Pure string build |
| Rule add + remove | 2.1 ms | Atomic write + rewrite |
| Parse 1000 log lines | 160 ms | ≈ 6,300 lines/s |
| Bulk insert 1000 events | 10.2 ms | One transaction |
| End-to-end CLI (typical) | ≈ 310–332 ms | Dominated by interpreter start |

## 7. Defects

No defects were found during the final test run. The suite includes regression
tests for behaviours that were previously wrong and are now locked in:

- `--yes` no longer bypasses the duplicate-rule check (`test_yes_does_not_bypass…`).
- `monitor poll` terminates instead of following the log forever
  (`test_monitor_poll_terminates_instead_of_following`).
- Tests are isolated from the real project environment (autouse fixture).

## 8. Known gaps

- Root-only `apply`/`validate`/`restore` paths are proven to *refuse*, not to
  succeed against a live kernel. Manual verification is available via
  `firewall preview` and `firewall validate`.
- Detector thresholds are validated functionally, not against real-world
  traffic distributions.

## 9. Conclusion

All 160 tests pass. The suite demonstrates that the tool's safety invariants
hold under hostile input, that its detection and storage layers behave as
specified, and that every operation requiring privilege fails safely when it
does not have it.
