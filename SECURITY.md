# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | yes |
| < 1.0 | no |

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security
report.** Public reports give an attacker a head start, and a firewall tool has
an unusually large blast radius.

Report privately through GitHub's "Report a vulnerability" button on the
Security tab of the repository, or by email to the maintainer listed in
`git log`. Please include:

- what the issue is and which file or command is involved,
- the version or commit,
- the steps to reproduce, and
- the impact — what an attacker gains.

You should get an acknowledgement within 72 hours and a status update within
seven days. If a fix is warranted you will be credited in the release notes and
`CHANGELOG.md` unless you would rather stay anonymous.

## Scope

Especially interested in reports about:

- **Input reaching the nft script unescaped.** Anything that lets a crafted
  address, port, comment or custom rule modify rules outside
  `table inet sentinelfw`, or inject additional statements.
- **Containment failures.** Any code path that can flush, modify or remove a
  table SentinelFW does not own, other than the documented full-ruleset restore.
- **Confirmation bypass.** Any mutation that proceeds without a terminal
  confirmation or an explicit `--yes`.
- **Privilege escalation.** Any operation that requires root when it should not,
  or that runs something as root beyond what the user asked for.
- **Unsafe deserialisation.** `yaml.safe_load` must be used everywhere;
  anything that loads untrusted YAML with a loader that can construct objects
  is a vulnerability.
- **File handling.** Predictable paths or symlink targets that let an
  unprivileged user influence which file the tool writes as root, and any
  secret or event history written world-readable.
- **Command injection.** Any shell invocation built from user input instead of
  being passed as an argument list.

Out of scope: running `firewall restore` and losing unrelated rulesets (that is
the documented behaviour, warned about at the prompt), and detection quality
issues that do not involve a security boundary.

## What SentinelFW does and does not protect

Worth being explicit, because a firewall tool invites bad assumptions.

SentinelFW filters traffic in `table inet sentinelfw`, chain `input`, priority
`-10`, policy `accept`. It is an *additional* layer in front of whatever else
manages the host — it is not a hardened perimeter, and it does not replace a
real firewall. The chain has an accept policy, so traffic that no SentinelFW
rule matches continues to be processed normally rather than being rejected.

It only ever sees what the kernel logged. It does not capture packets, inspect
payloads, or detect anything the kernel did not log.

The event database and reports contain the source IP addresses, ports and
timestamps of connections to your host. Treat `database/`, `logs/` and
`reports/` as sensitive: they are gitignored, and `config harden` sets 0600 on
the config and rules files. Anyone with read access to those files learns which
addresses are talking to your machine and when.