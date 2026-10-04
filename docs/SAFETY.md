# Safety model

SentinelFW edits a firewall. A bug in it can make a machine unreachable, so the
design is built around a small number of invariants. This document states them,
explains how each is enforced, and names the test that would catch a regression.

Read this before changing anything in `firewall/`.

---

## The invariants

### 1. One rule change never touches the kernel

Adding, editing or removing a rule writes to `rules.yaml` and nothing else. The
kernel is only touched by `firewall apply`, which is a separate, explicit,
root-only command.

This is the single most important property in the project. Everything else
assumes it.

**Enforced by:** `firewall/rules.py` has no access to `subprocess` at all, and
only `firewall/nft_manager.py` calls `run_command` with `nft` as the binary.
`--apply` is an opt-in flag on the individual commands; the default is to stop.

### 2. SentinelFW owns exactly one nftables object

All rules live in:

```
table inet sentinelfw
  chain input {
    type filter hook input priority -10; policy accept;
  }
```

Nothing else on the host is ever read for modification or written to, apart from
the deliberate full-ruleset restore in `firewall restore`.

The design consequences are intentional:

- **Base chain priority `-10`** runs before most services' own chains.
- **Policy `accept`** means traffic that no SentinelFW rule matches carries on
  being processed normally. SentinelFW can add filtering; it cannot become the
  reason the host stops responding.

**Enforced by:** `nft_manager.py` resolves the table from the configuration,
checks that the base chain exists, and refuses to operate on any table it did
not create. Tests assert that the generated script contains no other table
statement, and that a configuration naming a different table is rejected.

### 3. A failed apply cannot leave a broken chain

Applying does **not** delete the table or the chain. It flushes only SentinelFW's
own chain and re-populates it. If the new script is invalid, `nft -f -` rejects
the whole transaction atomically and the previous rules remain in place.

The script is delivered as one `nft -f -` invocation, so it is applied as a
single transaction: it either succeeds completely or not at all. There is no
window in which half the rules are live.

**Enforced by:** the script builder emits `flush chain` rather than
`flush table`. `firewall apply` re-reads the live ruleset afterwards and
compares it with what it intended to install, reporting a mismatch instead of
claiming success.

### 4. Consent is never assumed

Every mutation requires either an interactive terminal where the user confirms,
or an explicit `--yes`. When there is no terminal and no `--yes`, the command
refuses and changes nothing.

**Why it matters:** `sentinelfw firewall block-ip 1.2.3.4 | some-script` would
otherwise silently block an address because stdout was not a tty. That is how
automation locks people out of their own machines.

**Enforced by:** `cli/console.py` refuses any confirmation prompt when
`_is_interactive()` is false and `--yes` was not given.

### 5. Input cannot escape into the generated script

The nft script is built by string concatenation, so every value that reaches it
is validated or escaped:

| Input | Handling |
|---|---|
| IP address or network | `ipaddress.ip_address()` / `ip_network()`, so the value is a normalised address or CIDR and nothing else |
| Port | `int()`, range-checked `1`–`65535` |
| Protocol | compared against a fixed set, never interpolated blind |
| Rule comment | newlines, quotes, backslashes and `;` stripped; the statement separator is the interesting one |
| Custom rules | rejected outright if they contain a newline or `;`, because splitting across statements is exactly the injection primitive |
| Table name | validated against `^[a-z_][a-z0-9_]*$` per component |

**Enforced by:** `firewall/rules.py` sanitisers and the injection tests in
`tests/test_rules.py`, which feed shell metacharacters, newlines, nft statement
separators and oversized values through every field that reaches the script.

### 6. Restore is loud about being destructive

`firewall restore` cannot be made selective: restoring a full snapshot has to
use `nft flush ruleset`, which clears **every** table on the machine, including
Docker's and UFW's.

The command says exactly this, names what it will destroy, requires `--yes` or a
confirmation, and refuses to run when the named backup does not exist.

**Enforced by:** `firewall/backup.py` plus the CLI confirmation text. There is no
flag that makes it quieter.

### 7. Configuration is parsed as data, never as code

Configuration and rule files are read with `yaml.safe_load` only. `safe_load`
cannot construct arbitrary Python objects, so a malicious `config.yaml` cannot
achieve execution by being read.

**Enforced by:** the only YAML entry points are `config/settings.py` and
`firewall/rules.py`, both of which use `safe_load`. There is no `yaml.load`,
`yaml.unsafe_load` or `FullLoader` anywhere in the codebase.

### 8. Nothing runs a shell

Commands are executed as argument lists, never as shell strings, so no input can
become a second command.

**Enforced by:** every external process starts at `utils.run_command()`, which
calls `subprocess.run(argv)` with an explicit argument list. No call in the
codebase passes `shell=True`, and no command string is ever built for a shell to
interpret.

---

## What happens on each operation

### `firewall block-ip 203.0.113.7`

1. Validate the address with `ipaddress`.
2. Check for an existing equivalent rule and refuse or update rather than
   duplicating.
3. Append to `rules.yaml` atomically (write to a temporary file in the same
   directory, then rename).
4. If `--apply` was given, hand over to `firewall apply` below. Otherwise stop
   and tell the user what command would install it.

### `firewall apply`

1. Refuse unless running as root.
2. Build the complete script and print all of it.
3. Take a backup of the live ruleset into `backups/`.
4. Ask for confirmation, unless `--yes`.
5. Re-check the script with `nft -c -f -` (check only, no changes).
6. Apply it with `nft -f -` as one transaction.
7. Read the live ruleset back and verify it matches the intent.
8. Log every command that was run.

Any failure between 6 and 8 is reported as a failure. The tool never claims to
have installed rules it has not verified.

### `firewall restore backups/<name>.nft`

1. Refuse unless running as root.
2. Confirm the backup exists and is readable.
3. State, in full, that this flushes the entire ruleset on this host and will
   remove rules belonging to Docker, UFW and anything else.
4. Confirm, unless `--yes`.
5. `nft flush ruleset`, then `nft -f <backup>`.
6. Verify the result.

---

## Testing without root

The test suite never invokes `nft` and never needs privileges. Root-only branches
are covered by asserting that they **refuse**:

```python
def test_apply_requires_root(store, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    with pytest.raises(RootRequiredError):
        manager.apply(script)
```

So the suite proves the refusal paths and the script generation, but it does not
prove that a real `nft` accepts the generated syntax. That is the one thing
which cannot be verified without touching a live firewall, and it is why
`firewall validate` and `firewall preview` exist: they let a person check the
script on a machine they control before installing it.

## Adding a feature

If your change can influence the kernel, ask these questions:

1. Does it still only touch `table inet sentinelfw`?
2. Can it run without root?
3. Does it need confirmation?
4. Does every user-supplied value go through a validator or sanitiser?
5. Is there a test that fails if the containment or the confirmation breaks?

If any answer is "no", that is probably fine — but say so explicitly in the
pull request, with the reason.