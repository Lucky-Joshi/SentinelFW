# 04 — Test Plan

## 1. Purpose

Define how SentinelFW is verified, what is in and out of scope for automated
testing, and the criteria for acceptance.

## 2. Test strategy

The suite rests on one hard constraint: **it must never invoke `nft`** and never
requires root. A test that could change a live firewall is not a test. The suite
therefore verifies:

1. **Generation** — the script SentinelFW would run is correct, contained and
   injection-safe.
2. **Refusal** — root-only operations fail cleanly and change nothing.
3. **Behaviour** — parsing, storage, detection, reporting, configuration and CLI
   dispatch match the specification.

## 3. Levels

| Level | Scope | Examples |
|---|---|---|
| Unit | Pure functions | IP/port validation, protocol normalisation, comment sanitising, rendering |
| Integration | Modules together | rule store round-trip, SQLite storage, detector pipelines, config loading |
| End-to-end | CLI through `main(argv)` | exit codes, JSON output, refusals, report generation |
| Safety | Invariants | containment, injection, confirmation bypass, root refusal |

## 4. Environment

| Item | Value |
|---|---|
| OS | Kali Linux (Debian-based) |
| Python | CPython 3.14.7 |
| pytest | 9.1.1 |
| Coverage | pytest-cov |
| Privileges | Unprivileged |
| Kernel interaction | None |

## 5. Test data isolation

An autouse fixture points `SENTINELFW_CONFIG` at a temporary directory and
changes into it, so no test can write into the operator's real project. The CLI
tests patch the interactivity probe rather than replacing `sys.stdout`.

## 6. Entry and exit criteria

**Entry:** code imports cleanly; `pytest` collects the suite without error.

**Exit:** 0 failures, 0 errors; coverage measured; every safety invariant covered
by at least one test.

## 7. Coverage targets

| Area | Target | Rationale |
|---|---|---|
| Validation and rendering | high | Injection and containment live here |
| Configuration | high | Trust boundary for untrusted YAML |
| Storage and detection | high | Core behaviour |
| Root-only paths | refusal only | Cannot be executed unprivileged |

## 8. Out of scope

- Executing `nft -f -` against a live kernel (covered manually via `preview` and
  `validate`).
- Filesystem race conditions on shared hosts.
- Detection quality against real traffic (heuristics require tuning).

## 9. Test case inventory

The full inventory of 160 tests, with results, is in
`05_Test_Report.md` and Appendix D of the final report. The suite is organised as:

| File | Concern |
|---|---|
| `tests/test_rules.py` | Validation, rendering, containment |
| `tests/test_config.py` | Configuration and permissions |
| `tests/test_monitoring.py` | Parsing, storage, detection |
| `tests/test_cli.py` | CLI, exit codes, safety |
