# 08 — Security Analysis

This document analyses SentinelFW's own security properties. It complements
`SECURITY.md` (disclosure policy) and `docs/SAFETY.md` (the safety model).

## 1. Threat model

A firewall manager is privileged software running on a host that may already be
under attack. The relevant attacker capabilities are:

| Adversary | Capability | Concern |
|---|---|---|
| Remote network attacker | Sends traffic to the host | Crafted addresses/ports must not reach the nft script |
| Local unprivileged user | Writes files the tool may read as root | Symlinks, world-readable state |
| Malicious configuration | Controls `config.yaml` / `rules.yaml` | YAML must not execute code |
| Automation misuse | Pipes input, runs without a tty | Must not mutate silently |

## 2. Assets

- The live packet filter and the host's reachability.
- Rule and configuration integrity (the source of truth).
- Event history (source IPs, ports, timing) — sensitive metadata.
- The root privilege the tool may temporarily hold.

## 3. Controls

### 3.1 Containment

SentinelfW owns exactly one object — `table inet sentinelfw`, chain `input`,
priority `-10`, policy `accept`. It never modifies a table it did not create.
The script builder emits `flush chain`, not `flush table`, so a failed apply
cannot leave a dangling hook. The only exception is the documented, loudly
warned `firewall restore`, which must clear the whole ruleset.

### 3.2 Input handling

| Input | Control | Failure mode |
|---|---|---|
| Address/network | `ipaddress` parsing and normalisation | Rejected |
| Port | `int()`, range `1–65535` | Rejected |
| Protocol | Fixed allow-list | Rejected |
| Comment | Strips quotes, backslashes, newlines, `;` | Sanitised |
| Custom rule | Rejected if it contains a newline or `;` | Rejected |
| Table/chain name | `^[a-z_][a-z0-9_]*$` per component | Rejected |

The statement separator is the injection primitive: an attacker who can insert
`;` can append nft statements. Removing it from comments and rejecting it in
custom rules closes the path.

### 3.3 No shell

All external processes start at `utils.run_command()` and are passed as argument
lists. No code passes `shell=True`, so no input can become a second command.

### 3.4 Configuration as data

All YAML is read with `yaml.safe_load`. Object tags (`!!python/object`) and custom
constructors are refused. `tests/test_config.py` proves a `!!python/object`
payload is rejected without execution.

### 3.5 Privilege and consent

Root-only operations refuse cleanly without privilege. Every mutation requires a
terminal confirmation or an explicit `--yes`; a piped, non-interactive invocation
without `--yes` changes nothing. This prevents accidental lockout from
automation.

### 3.6 Data at rest

Event history is sensitive metadata. `config harden` sets `0600` on the
configuration and rule files; `database/`, `logs/` and `reports/` are gitignored.
Operators are advised to treat them as confidential.

## 4. Residual risk

| Risk | Status | Mitigation |
|---|---|---|
| Generated nft syntax untested against a live kernel in CI | Accepted | `preview`/`validate` for manual verification |
| `firewall restore` clears unrelated rulesets | By design, warned | Confirmation, no quiet flag |
| Detection can be evaded by low-and-slow traffic | Inherent to thresholds | Tunable windows and thresholds |
| Full access to event DB reveals host activity | Operational | File permissions, retention/prune |
| Tool holds root transiently | Inherent | Minimal root-only surface, no shell |

## 5. What SentinelFW does not protect against

- It is **not** a hardened perimeter or an IDS. The chain policy is `accept`;
  unmatched traffic is not rejected.
- It only sees what the kernel logged; no packet capture or DPI.
- It does not defend the host against compromise by other means.

## 6. Verification

Each control maps to tests that would catch a regression:

| Control | Evidence |
|---|---|
| Containment | `test_rules.py` — generated script contains only SentinelFW's table |
| Injection safety | `test_rules.py` — metacharacters/newlines/`;` through every field |
| YAML is data | `test_config.py` — `!!python/object` rejected |
| Consent | `test_cli.py` — non-interactive mutation without `--yes` refuses |
| Root refusal | `test_cli.py` — apply/validate/restore raise `RootRequiredError` |
| No shell | Code audit — no `shell=True` anywhere |
