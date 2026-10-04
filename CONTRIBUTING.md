# Contributing to SentinelFW

Thanks for helping. This is a tool that edits a firewall, so the review bar is
higher than usual — please read [Safety rules](#safety-rules-for-pull-requests)
before opening a change.

## Getting set up

SentinelFW runs from a clone with no install step:

```bash
git clone https://github.com/Lucky-Joshi/SentinelFW.git
cd SentinelFW
sudo apt update
sudo apt install -y nftables python3-rich python3-yaml
python3 -m pytest
```

For a sandbox where the live firewall does not matter:

```bash
sudo unshare --net --map-root-user python3 -m pytest
```

## Development principles

**1. Nothing touches the kernel implicitly.** `firewall/nft_manager.py` is the
only module allowed to execute `nft`. New code that needs to run a command must
go through it, not `subprocess` directly. No change may make a routine command
require root — only `apply`, `validate`, `backup` and `restore` do.

**2. Every anticipated failure has an exception with a hint.** Users get one
line saying what went wrong and one line saying what to do next. Raise from
`exceptions.py` rather than letting a bare `ValueError` escape into a traceback.

**3. `--json` means exactly one valid JSON document.** Nothing may be printed
to stdout alongside the payload — no tables, no hints, no blank lines. Use
stderr for decoration if you must.

**4. Inputs are validated before they are rendered.** Anything that becomes
part of an nft script goes through `ipaddress`, `int()` range checks, or the
comment sanitizer in `firewall/rules.py`. Add a test that tries to break it.

**5. Confirmations are not bypassable.** Mutations require a terminal or
`--yes`. Do not add a flag that makes a destructive change unconditional.

**6. State is local.** `config.yaml`, `rules.yaml`, `database/`, `logs/`,
`backups/` and `reports/` are gitignored. Never commit them.

## Safety rules for pull requests

A change touching any of these needs an explicit "tested on a live firewall"
note in the PR description, with the `nft list ruleset` output before and after:

- `firewall/nft_manager.py` — anything at all
- the containment logic that keeps rules inside `table inet sentinelfw`
- `flush chain` / `flush table` behaviour
- backup and restore
- anything that changes how the nft script is generated

## Tests

```bash
python3 -m pytest                      # whole suite
python3 -m pytest tests/test_cli.py    # CLI integration
python3 -m pytest -k detector          # one area
```

New behaviour needs a test. Bug fixes need a test that fails before the fix.
The suite must pass on the current stable Python (3.14) and stay compatible
with 3.10, so avoid syntax newer than 3.10.

Never write a test that runs `nft`, touches the real firewall, reads
`/var/log/auth.log`, or writes outside its temporary directory. The fixtures in
`tests/conftest.py` give you an isolated config, rules file and database.

## Style

Follow the surrounding code: 4-space indent, `from __future__ import
annotations`, standard-library imports first, then third-party, then local. Type
hints on public functions. Docstrings say what the thing does and why, and
prefer naming the invariant:

```python
def _run(self) -> int:
    """Dispatch to the requested subcommand."""
```

Comments explain reasoning, not mechanics. Do not add comments to code that is
already obvious.

## Commit messages

Short imperative subject, under 72 characters:

```
Add --limit to db export
Fix table name in firewall status JSON
Reject rules whose comment contains a newline
```

## Reporting bugs

Open an issue with the output of `sentinelfw doctor`, your Python and nftables
versions, the exact command, what you expected, and what happened. Please
redact IP addresses and hostnames from any output you paste.

## Reporting vulnerabilities

Do not open a public issue. See [SECURITY.md](SECURITY.md).