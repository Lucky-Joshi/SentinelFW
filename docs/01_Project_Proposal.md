# 01 — Project Proposal

## Title

**SentinelFW — Local nftables Firewall Manager and Security Monitor**

## Author

Lucky Joshi

## Summary

SentinelFW is a local-first tool that manages a single nftables chain and
monitors the traffic that chain logs. It is written in Python and aimed at
learners and single-host operators who need to change a firewall safely and then
understand what the firewall is doing.

## Motivation

Changing a firewall is one of the few routine actions that can render a machine
unreachable, yet most beginner-facing tooling hides the command it runs, applies
rules with no snapshot, and offers no route back. At the same time, the firewall
produces a stream of kernel log lines that is rich but opaque. SentinelFW closes
both gaps: it makes firewall changes inspectable and reversible, and it turns the
firewall's own logs into explanations a learner can act on.

## Objectives

1. Manage firewall rules safely, with validation and a readable source of truth.
2. Separate the decision to change a rule from the act of changing it.
3. Contain blast radius to one nftables object.
4. Monitor firewall activity from realistic log sources.
5. Detect suspicious behaviour with transparent, tunable heuristics.
6. Explain findings in plain language with recommended actions.
7. Generate human and machine-readable reports.
8. Require explicit consent for every mutation; never assume it.
9. Be testable without a live firewall or root.

## Scope

**In scope:** address/network/port rule management; safe atomic application;
journal, file, stdin and synthetic log ingestion; SQLite storage; five
detectors; alert de-duplication; a terminal dashboard; text/Markdown/JSON
reports; a knowledge base for ports and attacks.

**Out of scope:** full-ruleset authoring; packet capture and deep packet
inspection; signature-based IDS; remote/multi-host management; machine learning.

## Deliverables

- A Python package (`cli`, `config`, `firewall`, `monitor`, `dashboard`) with
  a `sentinelfw` console entry point.
- A test suite of 160 tests that never invokes `nft`.
- Documentation: this proposal, architecture, design, test plan, test report,
  user manual, admin guide, security analysis, limitations and future work.
- A final PDF report with diagrams, screenshots and measured results.

## Success criteria

- All tests pass; coverage documented and concentrated on safety-critical code.
- A rule can be recorded, previewed, applied, verified and reverted without risk
  to unrelated rulesets.
- Synthetic traffic produces detectable, explained alerts.
- No operation runs a shell or loads YAML as code.

## Indicative timeline

| Phase | Work |
|---|---|
| 1 | Requirements, safety invariants, project skeleton |
| 2 | Configuration model and rule validation/rendering |
| 3 | nft manager, containment, backup/restore |
| 4 | Log parsing, sources, SQLite storage |
| 5 | Detectors, alerts, reporting, dashboard, explain |
| 6 | CLI integration, exit codes, error handling |
| 7 | Testing, coverage, documentation, final report |
