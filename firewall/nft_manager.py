"""nftables backend.

This is the only module in SentinelFW that executes ``nft``. Everything is
routed through :func:`utils.run_command`, so every command is logged and can be
suppressed with ``dry_run=True``.

Safety model
------------
1. **Containment.** SentinelFW only ever writes to the table named in
   ``config.yaml`` (``inet sentinelfw`` by default). Any attempt to build a
   command against another table raises :class:`SafetyViolationError`.
2. **Advisory chain, accept policy.** Our base chain runs at priority ``-10``
   (before the standard filter chain) with ``policy accept``. Consequence: our
   drops fire early, but if SentinelFW is ever removed or misconfigured the
   machine keeps its normal connectivity. A firewall manager that can lock you
   out of SSH is a liability.
3. **Atomic transactions.** Rule sets are applied with ``nft -f -`` over a
   generated script, so the kernel either accepts all of it or none of it. A
   partial ruleset is not a reachable state.
4. **Backups first.** :meth:`NFTManager.apply_rules` refuses to run without an
   automatic backup unless explicitly told otherwise.
5. **Verification.** After a change the ruleset is re-read and compared, so a
   silent no-op is reported as a failure instead of pretending to succeed.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from config import AppConfig
from exceptions import (
    NftablesCommandError,
    NftablesNotAvailableError,
    RootRequiredError,
    SafetyViolationError,
    SentinelFWError,
)
from firewall.backup import BackupManager
from firewall.rules import Rule, RuleKind
from logsetup import get_logger
from utils import run_command

log = get_logger("firewall.nft")

__all__ = ["NFTManager", "NFTRule", "NFTStatus", "is_root", "NFT_BINARY"]

NFT_BINARY = os.environ.get("SENTINELFW_NFT", "nft")


def is_root() -> bool:
    """Whether the current process has an effective uid of 0."""
    return os.geteuid() == 0


@dataclass
class NFTRule:
    """A rule as reported by nftables (parsed from ``nft -a -j list``)."""

    handle: int
    table: str
    chain: str
    family: str
    raw: dict[str, Any] = field(default_factory=dict)
    expression: str = ""

    @property
    def text(self) -> str:
        """Best-effort human rendering of the rule body."""
        if self.expression:
            return self.expression
        try:
            return str(self.raw["expr"][0]["text"])
        except (KeyError, IndexError, TypeError):
            return json.dumps(self.raw)[:120]


@dataclass
class NFTStatus:
    """Snapshot of the backend, used by ``firewall status`` and the dashboard."""

    available: bool
    version: str = ""
    table_exists: bool = False
    chain_exists: bool = False
    rule_count: int = 0
    hook: str = ""
    priority: int | None = None
    policy: str = ""
    log_enabled: bool = False
    nftables_service_active: bool | None = None
    detail: str = ""

    @property
    def healthy(self) -> bool:
        return self.available and self.table_exists


class NFTManager:
    """High-level, safety-checked wrapper around the ``nft`` binary."""

    def __init__(self, config: AppConfig, *, dry_run: bool = False) -> None:
        self.config = config
        self.dry_run = dry_run
        self.backups = BackupManager(config.backup_dir, keep=config.firewall.backup_keep)
        self._version: str | None = None

    # ------------------------------------------------------------------
    # Availability / privileges
    # ------------------------------------------------------------------
    @property
    def table(self) -> str:
        return self.config.firewall.table

    @property
    def chain(self) -> str:
        return self.config.firewall.chain

    @property
    def family(self) -> str:
        return self.config.firewall.family

    @property
    def table_ref(self) -> str:
        return f"{self.family} {self.table}"

    @property
    def chain_ref(self) -> str:
        return f"{self.family} {self.table} {self.chain}"

    def _assert_managed(self, ref: str) -> None:
        """Refuse to build a command that touches anything but our table."""
        parts = ref.split()
        if not parts or parts[0] not in {"inet", "ip", "ip6", "bridge"}:
            raise SafetyViolationError(
                f"Refusing to touch {ref!r}: not a valid nftables object reference."
            )
        if len(parts) > 1 and parts[1] != self.table:
            raise SafetyViolationError(
                f"Refusing to touch table {parts[1]!r}.",
                hint=f"SentinelFW only manages the table '{self.table}'. "
                     f"Other tables belong to you or to other tools.",
            )

    def require_root(self, action: str = "this operation") -> None:
        """Raise :class:`RootRequiredError` unless running as root."""
        if not is_root():
            raise RootRequiredError(
                f"Root privileges are required for {action}.",
                hint="Re-run with sudo, e.g.: sudo sentinelfw firewall apply",
            )

    def binary_path(self) -> str:
        return shutil.which(NFT_BINARY) or NFT_BINARY

    def ensure_available(self, *, require_root: bool = False) -> str:
        """Verify the backend exists and return its version string."""
        if self._version is not None:
            return self._version
        if shutil.which(NFT_BINARY) is None:
            raise NftablesNotAvailableError(
                f"'{NFT_BINARY}' was not found in PATH.",
                hint="Install it with: sudo apt update && sudo apt install nftables",
            )
        result = run_command([NFT_BINARY, "--version"], timeout=10.0, logger=log,
                             log_prefix="nft")
        if not result.ok:
            raise NftablesNotAvailableError(
                f"'{NFT_BINARY} --version' failed: {result.stderr.strip()}",
                hint="The nftables backend is not usable on this kernel.",
            )
        self._version = result.stdout.strip() or "unknown"
        if require_root:
            self.require_root("querying the live ruleset")
        return self._version

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------
    def _nft(self, args: Sequence[str], *, ref: str | None = None,
             require_root: bool = False, stdin: str | None = None) -> Any:
        """Run an ``nft`` command and return the raw :class:`CommandResult`.

        ``ref`` is the object this command will modify; it is checked against
        SentinelFW's own table before the process is ever spawned.
        """
        self._assert_managed(ref or self.chain_ref)
        if require_root and not self.dry_run:
            self.require_root("this operation")
        return run_command(
            [NFT_BINARY, *args],
            dry_run=self.dry_run,
            timeout=self.config.firewall.command_timeout,
            input_text=stdin,
            logger=log,
            log_prefix="nft",
        )

    def list_ruleset(self, *, require_root: bool = True) -> str:
        """Full ruleset text (``nft list ruleset``) - used for backups."""
        self.ensure_available(require_root=require_root)
        result = self._nft(["list", "ruleset"], ref=self.table_ref,
                          require_root=require_root)
        if not result.ok:
            raise NftablesCommandError(
                "Could not read the nftables ruleset.",
                command=result.args,
                returncode=result.returncode,
                stderr=result.stderr,
                hint="Try: sudo nft list ruleset  (root is required to read netfilter state)",
            )
        return result.stdout

    def list_managed_rules(self, *, require_root: bool = True) -> list[NFTRule]:
        """Parse the rules currently live in SentinelFW's own table."""
        self.ensure_available(require_root=require_root)
        if self.dry_run:
            return []
        result = self._nft(
            ["-j", "-a", "list", "table", self.family, self.table],
            ref=self.table_ref,
            require_root=require_root,
        )
        if not result.ok:
            # A missing table is not an error - it simply means no rules yet.
            if "No such file" in result.stderr or "does not exist" in result.stderr:
                return []
            raise NftablesCommandError(
                f"Could not list table {self.table_ref!r}.",
                command=result.args,
                returncode=result.returncode,
                stderr=result.stderr,
            )
        return self._parse_rules_json(result.stdout)

    def _parse_rules_json(self, payload: str) -> list[NFTRule]:
        """Turn ``nft -j -a list table`` output into :class:`NFTRule` objects."""
        try:
            data = json.loads(payload or "{}")
        except json.JSONDecodeError:
            log.debug("nft returned non-JSON payload")
            return []

        items = data.get("nftables") if isinstance(data, dict) else None
        if not isinstance(items, list):
            return []

        found: list[NFTRule] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            rule = item.get("rule")
            if not isinstance(rule, dict):
                continue
            try:
                found.append(
                    NFTRule(
                        handle=int(rule.get("handle", 0)),
                        table=str(rule.get("table", self.table)),
                        chain=str(rule.get("chain", self.chain)),
                        family=str(rule.get("family", self.family)),
                        raw=rule,
                    )
                )
            except (TypeError, ValueError):
                continue
        return found

    def get_chain(self, *, require_root: bool = True) -> dict[str, Any] | None:
        """Return the chain object for our base chain, or ``None``."""
        self.ensure_available(require_root=require_root)
        if self.dry_run:
            return None
        result = self._nft(
            ["-j", "list", "chain", self.family, self.table, self.chain],
            ref=self.chain_ref,
            require_root=require_root,
        )
        if not result.ok:
            return None
        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return None
        items = data.get("nftables") or []
        for item in items:
            if isinstance(item, dict) and "chain" in item:
                return item["chain"]
        return None

    def status(self, *, require_root: bool = False) -> NFTStatus:
        """Cheap, non-fatal status snapshot for the dashboard."""
        try:
            version = self.ensure_available()
        except SentinelFWError as exc:
            return NFTStatus(available=False, detail=str(exc))

        status = NFTStatus(available=True, version=version)
        if self.dry_run or not is_root():
            status.detail = "live rules require root; showing stored state only"
            return status
        try:
            status.rule_count = len(self.list_managed_rules(require_root=False))
            chain = self.get_chain(require_root=False)
            if chain:
                status.table_exists = True
                status.chain_exists = True
                status.hook = str(chain.get("hook", ""))
                status.policy = str(chain.get("policy", ""))
                prio = chain.get("prio")
                status.priority = int(prio) if prio is not None else None
            status.log_enabled = self.config.firewall.log_enabled
            status.nftables_service_active = self._service_active()
        except SentinelFWError as exc:  # pragma: no cover - depends on host state
            status.detail = str(exc)
        return status

    def _service_active(self) -> bool | None:
        """Is the systemd nftables unit active? ``None`` when unknown."""
        if shutil.which("systemctl") is None:
            return None
        result = run_command(["systemctl", "is-active", "nftables"], timeout=5.0,
                             logger=None)
        if result.returncode != 0 and not result.stdout.strip():
            return None
        return result.stdout.strip() == "active"

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------
    def build_base_chain_script(self) -> str:
        """nft script that (re)creates the table and base chain."""
        fw = self.config.firewall
        return (
            f"add table {self.family} {self.table}\n"
            f"add chain {self.family} {self.table} {self.chain} "
            f"{{ type filter hook {fw.hook} priority {fw.priority}; "
            f"policy {fw.policy}; }}\n"
        )

    def build_rules_script(self, rules: Iterable[Rule]) -> str:
        """nft script body appending every enabled rule to our chain."""
        fw = self.config.firewall
        lines: list[str] = []
        for rule in rules:
            if not rule.enabled:
                continue
            for expression in rule.to_nft(
                log_enabled=fw.log_enabled,
                log_level=fw.log_level,
                log_prefix=self.config.log_prefix,
                family=self.family,
            ):
                lines.append(f"add rule {self.family} {self.table} "
                             f"{self.chain} {expression}")
        return "\n".join(lines) + ("\n" if lines else "")

    def build_full_script(self, rules: Iterable[Rule], *,
                          flush: bool = True) -> str:
        """Complete, self-contained transaction.

        ``flush chain`` (not ``flush table``) is used deliberately: it empties
        only our chain's rules and preserves the chain definition, so a
        failure cannot leave a dangling reference to the hook.
        """
        script = self.build_base_chain_script()
        if flush:
            script += f"flush chain {self.family} {self.table} {self.chain}\n"
        script += self.build_rules_script(rules)
        return script

    def preview_script(self, rules: Iterable[Rule], *, flush: bool = True) -> str:
        """The exact script that :meth:`apply_rules` would feed to ``nft -f``."""
        return self.build_full_script(rules, flush=flush)

    def apply_rules(self, rules: Sequence[Rule], *, flush: bool = True,
                    backup: bool = True, verify: bool = True) -> dict[str, Any]:
        """Apply ``rules`` to the kernel in a single atomic transaction.

        Steps, in order: root check -> backup -> ``nft -f`` -> verification.
        Nothing is executed when ``self.dry_run`` is set.
        """
        self.ensure_available(require_root=True)
        self.require_root("applying firewall rules")

        enabled = [r for r in rules if r.enabled]
        script = self.build_full_script(enabled, flush=flush)

        report: dict[str, Any] = {
            "dry_run": self.dry_run,
            "script": script,
            "rule_count": len(enabled),
            "backup": None,
            "verified": None,
            "command": f"{NFT_BINARY} -f -",
        }

        if backup:
            backup_path = self.backups.create(ruleset_text=None, note="pre-apply")
            report["backup"] = str(backup_path)
            log.info("Ruleset backed up to %s", backup_path)

        if self.dry_run:
            log.info("Dry run: not sending %d line(s) to nft", script.count("\n"))
            report["applied"] = False
            return report

        result = run_command([NFT_BINARY, "-f", "-"], input_text=script,
                             timeout=self.config.firewall.command_timeout,
                             logger=log, log_prefix="nft")
        if not result.ok:
            raise NftablesCommandError(
                "nftables rejected the ruleset; nothing was changed.",
                command=result.args,
                returncode=result.returncode,
                stderr=result.stderr,
                hint="Run 'sentinelfw firewall validate' to see the exact script.",
            )
        report["applied"] = True
        log.info("Applied %d rule(s) to %s", len(enabled), self.table_ref)

        if verify:
            live = self.list_managed_rules(require_root=False)
            # The chain also holds a `counter`-bearing rule per expression; a
            # port rule with protocol any contributes two expressions.
            expected = sum(
                len(r.to_nft(log_enabled=self.config.firewall.log_enabled,
                             log_level=self.config.firewall.log_level,
                             log_prefix=self.config.log_prefix,
                             family=self.family))
                for r in enabled
            )
            report["verified"] = (len(live) == expected)
            report["live_rules"] = len(live)
            report["expected_rules"] = expected
            if not report["verified"]:
                log.warning(
                    "Post-apply verification mismatch: %d live rule(s), expected %d",
                    len(live), expected,
                )
        return report

    def remove_rule_handle(self, handle: int, *, backup: bool = True) -> dict[str, Any]:
        """Delete a single live rule by handle (used by ``firewall sync``)."""
        self._assert_managed(self.table_ref)
        self.require_root("modifying firewall rules")
        args = [NFT_BINARY, "-a", "list", "table", self.family, self.table]
        listing = run_command(args, timeout=self.config.firewall.command_timeout,
                              logger=log, log_prefix="nft")
        if not listing.ok:
            raise NftablesCommandError(
                f"Could not list {self.table_ref}.",
                command=listing.args, returncode=listing.returncode,
                stderr=listing.stderr,
            )
        if self.dry_run:
            return {"dry_run": True, "removed": handle,
                    "command": f"{NFT_BINARY} delete rule {self.family} "
                               f"{self.table} handle {handle}"}

        script = f"delete rule {self.family} {self.table} handle {int(handle)}\n"
        if backup:
            self.backups.create(note=f"pre-delete-handle-{handle}")
        result = run_command([NFT_BINARY, "-f", "-"], input_text=script,
                             timeout=self.config.firewall.command_timeout,
                             logger=log, log_prefix="nft")
        if not result.ok:
            raise NftablesCommandError(
                f"Could not delete rule handle {handle}.",
                command=result.args, returncode=result.returncode,
                stderr=result.stderr,
            )
        return {"dry_run": False, "removed": handle}

    def enable_syn_logging(self, enabled: bool = True) -> dict[str, Any]:
        """Toggle the high-volume SYN logging rule.

        This is opt-in because logging every SYN can generate thousands of
        kernel messages per minute and fill ``/var/log`` quickly.
        """
        kind = RuleKind.SYN_LOG if enabled else None
        if enabled:
            rule = Rule(kind=RuleKind.SYN_LOG, action="log", origin="builtin",
                        comment="SentinelFW SYN visibility")
            script = (
                self.build_base_chain_script()
                + f"flush chain {self.family} {self.table} {self.chain}\n"
                + f"add rule {self.family} {self.table} {self.chain} "
                + rule.to_nft(log_prefix=self.config.log_prefix,
                              log_level=self.config.firewall.log_level)[0]
                + "\n"
            )
            self.require_root("enabling SYN logging")
            return self._run_script(script, description=f"enable SYN logging ({kind})")
        return self._run_script(
            f"flush chain {self.family} {self.table} {self.chain}\n",
            description="disable SYN logging (flushes chain - re-apply rules after)",
        )

    def _run_script(self, script: str, *, description: str) -> dict[str, Any]:
        report = {"dry_run": self.dry_run, "description": description, "script": script}
        if self.dry_run:
            log.info("Dry run: %s", description)
            return report
        result = run_command([NFT_BINARY, "-f", "-"], input_text=script,
                             timeout=self.config.firewall.command_timeout,
                             logger=log, log_prefix="nft")
        if not result.ok:
            raise NftablesCommandError(
                f"nftables rejected the change ({description}); nothing was changed.",
                command=result.args, returncode=result.returncode, stderr=result.stderr,
            )
        report["applied"] = True
        return report

    # ------------------------------------------------------------------
    # Validation & diff
    # ------------------------------------------------------------------
    def validate(self, rules: Sequence[Rule]) -> dict[str, Any]:
        """Ask the kernel to check a script without committing it (``nft -c``).

        This is the strongest guarantee available before applying: it uses the
        same parser the kernel uses, so a syntax error is caught here rather
        than halfway through a transaction.
        """
        script = self.build_full_script([r for r in rules if r.enabled])
        if self.dry_run:
            return {"valid": None, "dry_run": True, "script": script}
        self.require_root("validating a ruleset")
        result = run_command([NFT_BINARY, "-c", "-f", "-"], input_text=script,
                             timeout=self.config.firewall.command_timeout,
                             logger=log, log_prefix="nft-check")
        if result.ok:
            return {"valid": True, "script": script}
        return {"valid": False, "script": script,
                "error": result.stderr.strip() or "unknown error"}

    def diff_against_live(self, rules: Sequence[Rule]) -> dict[str, Any]:
        """Compare desired rules with what is currently live.

        Returns ``{"in_sync": bool, "live": int, "desired": int, "live_text": [...]}``.
        """
        live = self.list_managed_rules(require_root=False)
        desired_text: list[str] = []
        for rule in rules:
            if not rule.enabled:
                continue
            desired_text.extend(
                rule.to_nft(log_enabled=self.config.firewall.log_enabled,
                            log_level=self.config.firewall.log_level,
                            log_prefix=self.config.log_prefix,
                            family=self.family)
            )
        return {
            "in_sync": len(live) == len(desired_text),
            "live": len(live),
            "desired": len(desired_text),
            "live_text": [r.text for r in live],
            "desired_text": desired_text,
        }