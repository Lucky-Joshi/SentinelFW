# SentinelFW

**Local nftables firewall manager and security monitor for Kali Linux.**

SentinelFW keeps a set of firewall rules in a YAML file, shows you the exact
`nft` script before anything touches the kernel, stores the firewall's own log
lines in SQLite, and explains what it finds in plain English.

It is built to be read before it is trusted: every firewall change is previewed,
backed up and confirmed, and the tool refuses to touch any nftables table other
than the one it owns.

Repository: <https://github.com/Lucky-Joshi/SentinelFW.git>

---

## Table of contents

- [Why](#why)
- [Requirements](#requirements)
- [Install](#install)
- [First run](#first-run)
- [How SentinelFW stays safe](#how-sentinelfw-stays-safe)
- [Firewall commands](#firewall-commands)
- [Monitoring and detection](#monitoring-and-detection)
- [Alerts, reports and the dashboard](#alerts-reports-and-the-dashboard)
- [Explaining things](#explaining-things)
- [Configuration](#configuration)
- [Project layout](#project-layout)
- [Exit codes](#exit-codes)
- [Testing](#testing)
- [Limitations](#limitations)
- [License](#license)

---

## Why

A firewall change is one of the few things a user can do that can make a machine
unreachable. Most tooling hides the actual command being run, applies rules
straight from a text file, and gives you no way back if it was wrong.

SentinelFW inverts that:

- rules live in `rules.yaml` until you explicitly install them;
- installing shows the **complete** `nft` script and takes a backup first;
- rules are applied atomically, so a syntax error cannot leave a half-configured
  chain;
- SentinelFW only ever modifies `table inet sentinelfw`, its own chain, at
  priority `-10` with policy `accept`, so it adds filtering without ever
  becoming the thing that locks you out;
- every detected finding is explained in language that does not assume you
  already know what "SYN flood" means.

## Requirements

| | |
|---|---|
| OS | Linux (developed and tested on Kali Linux) |
| Python | 3.10 or newer |
| Python packages | `rich`, `PyYAML` |
| System package | `nftables` — only needed to change the live ruleset |

On Kali, Debian and Ubuntu, everything comes from apt:

```bash
sudo apt update
sudo apt install -y nftables python3-rich python3-yaml
```

Prefer pip, or on a distro that does not package those two libraries?

```bash
sudo apt install -y nftables
pip install rich PyYAML     # add --break-system-packages if pip refuses (PEP 668)
```

## Install

```bash
git clone https://github.com/Lucky-Joshi/SentinelFW.git
cd SentinelFW
```

**Run it straight from this folder.** Nothing to install, no virtualenv:

```bash
./sentinelfw doctor
```

`python3 main.py <command>` works identically if you prefer that.

**Optional: install the `sentinelfw` command system-wide.**

Kali marks its Python as externally managed, so a plain `pip install .` is
refused. Use `pipx`, which gives the command its own environment:

```bash
sudo apt install -y pipx     # if you do not have it already
pipx install .
sentinelfw doctor
```

Or manage it in a virtualenv yourself:

```bash
python3 -m venv ~/.venvs/sentinelfw
~/.venvs/sentinelfw/bin/pip install .
~/.venvs/sentinelfw/bin/sentinelfw doctor
```

Either way the dependencies come with it; `requirements.txt` is there for
environments you build yourself.

## First run

```bash
# 1. See whether this machine is ready.
#    Exit code 6 means "some checks need attention" - read the list it prints.
./sentinelfw doctor

# 2. Create the configuration file (mode 0600).
./sentinelfw config init

# 3. Learn the interface with synthetic traffic. No root, no real attacker,
#    and it is labelled as fabricated everywhere it appears. It asks before
#    writing to your database; add -y to skip the question in a script.
./sentinelfw monitor demo --seconds 30

# 4. Watch the result.
./sentinelfw dashboard --once
./sentinelfw alerts list --explain
./sentinelfw report generate
```

Then, when you are ready to change the real firewall:

```bash
# Record a rule. This only edits rules.yaml.
./sentinelfw firewall block-ip 203.0.113.7 -r "scanner"

# Check exactly what would run.
./sentinelfw firewall preview

# Install it. Takes a backup, asks for confirmation, applies atomically.
sudo ./sentinelfw firewall apply
```

### Letting the monitor read logs without root

`monitor start` uses the systemd journal, which is normally root-only. To read
it as your own user, join the journal group, then start a new login session (or
reboot) so it takes effect:

```bash
sudo usermod -aG systemd-journal "$USER"
```

`./sentinelfw doctor` reports journal access explicitly. If you would rather not
change group membership, run the monitor with `sudo`, or point
`monitoring.source` at log files instead.

### Where your data lives

`config path` prints every location in use. Running from a clone, state goes into
that folder. An **installed** command run from a new directory creates its
project there, so run `config init` from wherever you want it to live:

```bash
mkdir -p ~/work/lab && cd ~/work/lab
sentinelfw config init
```

To keep it somewhere specific regardless of where you run from:

```bash
SENTINELFW_CONFIG=~/work/lab/config.yaml sentinelfw monitor status
```

## How SentinelFW stays safe

**It owns exactly one object.** All generated rules land in
`table inet sentinelfw`, chain `input`, base chain priority `-10`, policy
`accept`. `nft_manager.py` refuses to operate on any other table. Being an
early-priority chain with an accept policy means SentinelFW filters *before*
most services but cannot become the reason the machine stops answering.

**Rule changes and kernel changes are separate steps.** Adding a rule writes to
`rules.yaml`. Nothing reaches the kernel until `firewall apply`, which:

1. requires root,
2. prints the entire `nft` script,
3. snapshots the live ruleset into `backups/`,
4. asks for confirmation,
5. pipes the script to `nft -f -` as one atomic transaction,
6. re-reads the live ruleset and verifies the result.

**`flush chain`, never `flush table`.** Applying empties only SentinelFW's own
chain and leaves the chain definition in place, so a failure cannot leave a
dangling hook reference.

**No unattended consent.** Without a terminal, any mutation refuses unless you
pass `--yes`. Assuming consent in a pipeline is how machines get locked out.

**`firewall restore` is the honest exception.** Restoring a full snapshot has to
use `nft flush ruleset`, which clears *every* table on the machine — including
Docker's and UFW's. The command says so before it does it.

**Input cannot escape into the ruleset.** Addresses and ports are parsed with
`ipaddress`, comments are stripped of quotes, backslashes, newlines and
statement separators, and custom rules are rejected if they contain a newline
or `;`.

**Every nft invocation is logged** to `logs/sentinelfw.log`.

## Firewall commands

```
firewall list                 show configured rules (--live to diff against the kernel)
firewall status               backend availability and rule sync
firewall block-ip ADDRESS     block an IP or network       [-r reason] [--apply] [--force]
firewall allow-ip ADDRESS     allow an IP or network
firewall block-port PORT      block a TCP/UDP port         [--protocol tcp|udp|any]
firewall allow-port PORT      allow a TCP/UDP port
firewall remove ID            delete a rule
firewall enable ID            re-enable a disabled rule
firewall disable ID           disable without deleting
firewall preview              print the nft script without running it
firewall validate             ask nft to check the script (root)
firewall apply                install rules into the kernel (root)
firewall flush                remove the whole SentinelFW table (root)
firewall backup               snapshot the live ruleset (root)
firewall backups              list available backups
firewall restore FILE         restore a snapshot (root; flushes everything)
firewall enable-logging       log every incoming SYN (noisy)  [--off]
```

Rules are ordered so that allows are evaluated before drops, and SentinelFW
tells you when a rule you added makes another one unreachable.

Recording an identical or contradicting rule is refused. Note that `--yes` only
suppresses the prompt — it does **not** bypass that check, so an unattended run
cannot quietly accumulate duplicate rules. Overriding it is a separate, explicit
decision: `--force`.

Global flags work before or after the command, which is what people actually
type:

```bash
sentinelfw --json firewall status
sentinelfw firewall status --json
```

## Monitoring and detection

SentinelFW reads the log lines its own rules produce. The prefix is
`SENTINELFW-DROP` / `SENTINELFW-ACCEPT`, which is what the parser looks for.

```
monitor start          follow the journal and detect anomalies (root, for the journal)
monitor poll           one pass over buffered logs, then exit
monitor ingest FILE    import an existing log file
monitor demo           synthetic traffic for N seconds
monitor status         database and parser statistics
monitor detect         run one detection cycle now   [--dry-run]
monitor prune          delete events older than a period   [--period 30d | --all]
monitor vacuum         compact the database file
monitor reset          delete all events and alerts
```

Log sources are chosen in `config.yaml` under `monitoring.source`:
`journal` (systemd, the usual choice on Kali), `file` (a list of paths such as
`/var/log/kern.log`), or `demo`. Reading the kernel journal normally needs root
or membership of the `systemd-journal` group — `doctor` checks this for you.

### Detectors

| Kind | Default trigger | Meaning |
|---|---|---|
| `port_scan` | 20 ports from one source in 60s | reconnaissance across many services |
| `brute_force` | 100 attempts on one port in 300s | automated password or key probing |
| `repeated_block` | 50 hits on one port in 600s | persistent hammering of a closed port |
| `connection_spike` | 300 connections in 60s | unusual overall volume |
| `sensitive_port` | any traffic to a watched port | FTP, Telnet, SSH, databases, RDP… |

The watched ports are FTP (21), SSH (22), Telnet (23), SMTP (25), DNS (53),
HTTP (80), POP3 (110), IMAP (143), HTTPS (443), SMB (445), MSSQL (1433),
MySQL (3306), RDP (3389), PostgreSQL (5432), VNC (5900), Redis (6379),
HTTP-alt (8080/8443) and MongoDB (27017).

Every threshold and window lives under `detection:` in `config.yaml`, together
with `alert_cooldown_seconds` (900 by default). Alerts are
de-duplicated by fingerprint, so a continuing attack updates one row instead of
flooding you. Each one is stored with the evidence that produced it and a set of
recommended actions.

## Alerts, reports and the dashboard

```
alerts list             list findings       [--severation high] [--kind …] [--explain]
alerts show ID          one finding in full, with evidence and next steps
alerts ack ID           mark as handled

report generate         build a report      [--period 24h] [--format text|markdown|json]
                                        [--brief] [--save]
report list             list saved reports

dashboard               live refreshing view
dashboard --once        render a single snapshot and exit
```

The dashboard and reports adapt to the terminal width: on a narrow window they
drop optional columns rather than shrinking every column to one character.

`--json` is supported on the machine-readable commands and always emits a
single valid JSON document, so this is safe to pipe:

```bash
sentinelfw alerts list --json | jq '.alerts[] | select(.severity=="high")'
sentinelfw db export --format csv --output events.csv
```

## Explaining things

```
explain port 22              what this port is, why attackers want it, what to do
explain attack --list        every detection SentinelFW can raise
explain attack port_scan     what one detection means and how to respond
explain event --last 1       explain the most recent stored event
```

Event and alert IDs are shown in `monitor status` and `alerts list`, so
`explain event <id>` and `alerts show <id>` are always reachable.

## Configuration

`config.yaml` is created with mode `0600` and holds commented defaults. Useful
commands:

```
config init      create it (refuses to overwrite without --force)
config show      print the effective configuration and resolved paths
config path      print where config, rules, database, backups, reports and logs live
config check     validate it
config harden    set 0600 on config and rules files
```

Relative paths resolve next to `config.yaml`, so pointing `--config` or
`SENTINELFW_CONFIG` at another directory moves the whole project there instead
of scattering state back into the source tree:

```bash
SENTINELFW_CONFIG=~/work/lab/config.yaml sentinelfw monitor status
```

Files that hold your rules, your logs or your event history are local state, not
source: `config.yaml`, `rules.yaml`, `database/`, `logs/`, `backups/` and
`reports/` are all in `.gitignore`.

## Project layout

```
SentinelFW/
├── sentinelfw              executable launcher (no install needed)
├── main.py                 entry point: python3 main.py
├── cli/
│   ├── interface.py        argument parsing, command dispatch, confirmation flow
│   └── console.py          change previews, tables, confirmations
├── config/settings.py      typed configuration, validation, safe loading
├── firewall/
│   ├── rules.py            rule model, validation, nft rendering, rules.yaml
│   ├── nft_manager.py      the only code that runs nft; containment rules
│   └── backup.py           snapshot and restore
├── monitor/
│   ├── database.py         SQLite schema, event and alert storage
│   ├── log_parser.py       kernel log parsing and the log sources
│   ├── detector.py         the five detectors
│   ├── monitor.py          the collector that joins it all together
│   ├── explain.py          the knowledge base behind `explain`
│   └── reports.py          text, markdown and JSON reports
├── dashboard/terminal.py   Rich dashboard
├── exceptions.py           one exception per anticipated failure, each with a hint
├── logsetup.py             rotating logs, including every nft command
├── utils.py                time, formatting and small helpers
├── version.py
├── docs/SAFETY.md          the invariants, and the tests that enforce them
└── tests/                  160 tests; none of them touch the kernel
```

## Exit codes

| Code | Meaning | Raised by |
|---|---|---|
| 0 | success | |
| 1 | operational error | `FirewallError`, `DatabaseError`, `NftablesCommandError`, `ReportError`, `MonitoringError`, `BackupError` |
| 2 | configuration file not found | `ConfigNotFoundError` |
| 3 | insufficient privileges | `RootRequiredError`, `PrivilegeError`, `SafetyViolationError` |
| 4 | validation failure | `ConfigValidationError`, `RuleValidationError`, `RuleConflictError` |
| 5 | aborted by the operator | `UserAbortError`, including Ctrl-C |
| 6 | dependency or environment problem | `NftablesNotAvailableError`, `LogSourceError` |

Codes 2, 3, 4 and 6 mean "retrying with different inputs or privileges will
help"; code 1 means something operational went wrong; code 5 means nothing was
changed.

## Testing

```bash
python3 -m pytest              # 160 tests, about 50 seconds
python3 -m pytest -v           # per-test output
python3 -m pytest tests/test_cli.py
```

The suite runs entirely against temporary directories and **never invokes
`nft`**. It covers config validation and `safe_load` behaviour, rule validation
and nft rendering, injection attempts against rule comments, the containment
guarantees of the script builder, the log parser, every detector, SQLite
storage and pruning, and the CLI end to end — including the paths that must
refuse rather than half-apply.

Because the suite runs as an unprivileged user, the root-only branches
(`firewall apply`, `validate`, `restore`) are exercised by asserting that they
*refuse*, not by applying rules.

## Limitations

Being straight with you about what this is not:

- **It is not a firewall.** It manages one nftables chain. If you need a
  complete firewall policy, use `nftables` directly or a distribution tool and
  let SentinelFW add filtering ahead of it.
- **Findings are heuristics.** Severity comes from event volume and pattern
  matching, not packet inspection. Treat every alert as a lead to investigate,
  never as proof of compromise.
- **No live packet capture.** SentinelFW analyses what the kernel logged, so
  anything not logged cannot be detected.
- **Restore is destructive.** `firewall restore` flushes the whole ruleset
  because that is the only way to restore a full snapshot.
- **Detection thresholds need tuning.** The defaults are reasonable for a
  single-purpose host, not for a busy server. Watch for false positives and
  raise the thresholds under `detection:`.
- **Demo data is fabricated.** `monitor demo` writes to the same database as
  real events. It is labelled everywhere, but clear it with
  `monitor reset` when you are done.

## License

MIT — see [LICENSE](LICENSE).