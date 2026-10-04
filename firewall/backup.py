"""Ruleset backup, restore and pruning.

Why backups matter here
-----------------------
``nft`` has no undo stack. A malformed script or a mistaken flush is
immediately effective in the kernel, and on a headless box the recovery path is
"reboot, or get physical access". SentinelFW therefore snapshots the complete
ruleset *before* every change and keeps a bounded history.

Backup files are plain ``nft`` syntax, so restoring is trivially auditable:

.. code-block:: bash

    sudo nft -f backups/ruleset-20261004-031530.nft
"""

from __future__ import annotations

import difflib
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from exceptions import BackupError, RootRequiredError
from logsetup import get_logger
from utils import atomic_write_text, now_iso, run_command

log = get_logger("firewall.backup")

__all__ = ["BackupManager", "BackupEntry", "NFT_BINARY"]

NFT_BINARY = os.environ.get("SENTINELFW_NFT", "nft")
_BACKUP_RE = re.compile(
    r"^ruleset-(?P<stamp>\d{8}-\d{6})(?P<tag>-[A-Za-z0-9_-]+)?\.nft$"
)


@dataclass
class BackupEntry:
    """Metadata for one backup file."""

    path: Path
    stamp: str
    tag: str
    size: int

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def modified(self) -> str:
        return datetime.fromtimestamp(self.path.stat().st_mtime).isoformat(
            timespec="seconds"
        )


class BackupManager:
    """Create, list, restore and prune ``nft`` ruleset snapshots."""

    SUFFIX = ".nft"

    def __init__(self, directory: str | Path, *, keep: int = 20,
                 config: AppConfig | None = None) -> None:
        self.dir = Path(directory)
        self.keep = max(1, int(keep))
        self.config = config

    # ------------------------------------------------------------------
    def ensure_dir(self) -> Path:
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise BackupError(
                f"Cannot create backup directory {self.dir}: {exc}",
                hint="Check permissions on the project directory.",
            ) from exc
        return self.dir

    def _stamp(self) -> str:
        return datetime.now().strftime("%Y%m%d-%H%M%S")

    # ------------------------------------------------------------------
    def create(self, ruleset_text: str | None = None, *, note: str = "",
               tag: str | None = None) -> Path | None:
        """Write a new snapshot.

        Parameters
        ----------
        ruleset_text:
            Pre-captured ``nft list ruleset`` output. When ``None`` the current
            ruleset is captured live (requires root). If capture fails the
            backup is *skipped* rather than writing an empty file, and the
            caller is told via the return value.
        note:
            Free-text reason stored as a comment in the file header.

        Returns
        -------
        Path to the new file, or ``None`` when the snapshot could not be taken.
        """
        self.ensure_dir()
        safe_tag = re.sub(r"[^A-Za-z0-9_-]", "", tag) if tag else (
            re.sub(r"[^A-Za-z0-9_-]", "", note) or "manual"
        )
        target = self.dir / f"ruleset-{self._stamp()}-{safe_tag}{self.SUFFIX}"

        if ruleset_text is None:
            if os.geteuid() != 0:
                log.warning(
                    "Skipping backup %s: capturing the live ruleset needs root.",
                    target.name,
                )
                return None
            result = run_command([NFT_BINARY, "list", "ruleset"], timeout=20.0,
                                 logger=log, log_prefix="nft-backup")
            if not result.ok:
                log.warning(
                    "Skipping backup %s: 'nft list ruleset' failed (%s).",
                    target.name, result.stderr.strip() or result.returncode,
                )
                return None
            ruleset_text = result.stdout

        header = (
            f"# SentinelFW ruleset backup\n"
            f"# created: {now_iso()}\n"
            f"# reason : {note or 'manual'}\n"
            f"# restore: sudo nft -f {target}\n"
            f"# -------------------------------------------------------------------------\n"
        )
        atomic_write_text(target, header + ruleset_text, mode=0o600)
        log.info("Backup written: %s", target)
        self.prune()
        return target

    # ------------------------------------------------------------------
    def list(self) -> list[BackupEntry]:
        """All snapshots, newest first."""
        if not self.dir.is_dir():
            return []
        entries: list[BackupEntry] = []
        for path in self.dir.glob(f"*{self.SUFFIX}"):
            match = _BACKUP_RE.match(path.name)
            if not match:
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            entries.append(
                BackupEntry(
                    path=path,
                    stamp=match.group("stamp"),
                    tag=(match.group("tag") or "manual").lstrip("-"),
                    size=stat.st_size,
                )
            )
        entries.sort(key=lambda e: (e.stamp, e.name), reverse=True)
        return entries

    def latest(self) -> BackupEntry | None:
        entries = self.list()
        return entries[0] if entries else None

    def resolve(self, name_or_path: str) -> Path:
        """Turn a user-supplied name into an existing path inside ``dir``."""
        if not name_or_path:
            raise BackupError("No backup name given.")
        candidate = Path(name_or_path).expanduser()
        if candidate.is_file():
            return candidate
        target = self.dir / candidate.name
        if target.is_file():
            return target
        # Allow a short stamp such as 20261004-031530
        matches = [e for e in self.list() if e.stamp == name_or_path]
        if len(matches) == 1:
            return matches[0].path
        if not self.dir.is_dir():
            raise BackupError(f"No backup directory at {self.dir}.")
        raise BackupError(
            f"No backup named {name_or_path!r} in {self.dir}.",
            hint="List available backups with: sentinelfw firewall backups",
        )

    # ------------------------------------------------------------------
    def preview_restore(self, path: str | Path) -> list[str]:
        """The exact commands a restore would run, for confirmation display."""
        resolved = self.resolve(str(path))
        return [f"sudo {NFT_BINARY} flush ruleset", f"sudo {NFT_BINARY} -f {resolved}"]

    def restore(self, path: str | Path, *, dry_run: bool = False) -> dict[str, Any]:
        """Restore a snapshot, replacing the live ruleset.

        A snapshot contains the *whole* ruleset, so ``nft -f`` alone would fail
        with "File exists" for every table already present. The correct
        recovery sequence is therefore:

        1. snapshot the current state (so a bad restore is itself reversible),
        2. ``nft flush ruleset``,
        3. ``nft -f <backup>``.

        Step 2 is destructive to *every* table, including ones owned by other
        tools. That is unavoidable for a full-ruleset restore, which is why the
        CLI always shows these two commands and asks for confirmation.
        """
        resolved = self.resolve(str(path))
        if not resolved.is_file():
            raise BackupError(f"Backup file is missing: {resolved}")

        info: dict[str, Any] = {
            "path": str(resolved),
            "dry_run": dry_run,
            "commands": self.preview_restore(resolved),
            "size": resolved.stat().st_size,
        }

        # Snapshot the *current* state before overwriting it.
        info["pre_restore_backup"] = str(self.create(note="pre-restore") or "skipped")

        if dry_run:
            log.info("Dry run: would restore %s", resolved)
            info["applied"] = False
            return info

        if os.geteuid() != 0:
            raise RootRequiredError(
                "Restoring a ruleset requires root.",
                hint="Re-run with sudo: "
                     f"sudo sentinelfw firewall restore {resolved.name}",
            )

        flush = run_command([NFT_BINARY, "flush", "ruleset"], timeout=30.0,
                            logger=log, log_prefix="nft-restore")
        if not flush.ok:
            raise BackupError(
                "Could not flush the live ruleset; restore aborted.",
                hint=flush.stderr.strip() or None,
            )

        result = run_command([NFT_BINARY, "-f", str(resolved)], timeout=30.0,
                             logger=log, log_prefix="nft-restore")
        if not result.ok:
            raise BackupError(
                "Restore failed after flushing. Your previous ruleset is saved at "
                f"{info['pre_restore_backup']}",
                hint=result.stderr.strip() or "Check syntax with: "
                     f"sudo {NFT_BINARY} -c -f {resolved}",
            )
        info["applied"] = True
        log.info("Ruleset restored from %s", resolved)
        return info

    # ------------------------------------------------------------------
    def prune(self, keep: int | None = None) -> list[Path]:
        """Delete the oldest snapshots beyond ``keep``.

        Never deletes the single newest file, so there is always at least one
        recovery point on disk.
        """
        limit = self.keep if keep is None else max(1, int(keep))
        entries = self.list()
        if len(entries) <= limit:
            return []
        doomed = entries[limit:]
        removed: list[Path] = []
        for entry in doomed:
            try:
                entry.path.unlink()
                removed.append(entry.path)
            except OSError as exc:  # pragma: no cover - permissions
                log.warning("Could not remove old backup %s: %s", entry.name, exc)
        if removed:
            log.info("Pruned %d old backup(s)", len(removed))
        return removed

    def diff(self, left: str | Path, right: str | Path) -> str:
        """Unified diff between two snapshots (read-only, no nft needed)."""
        a = self.resolve(str(left))
        b = self.resolve(str(right))
        try:
            left_lines = a.read_text(encoding="utf-8").splitlines(keepends=True)
            right_lines = b.read_text(encoding="utf-8").splitlines(keepends=True)
        except OSError as exc:
            raise BackupError(f"Cannot read backup for diff: {exc}") from exc
        return "".join(
            difflib.unified_diff(
                left_lines, right_lines,
                fromfile=a.name, tofile=b.name, n=2,
            )
        ) or "(files are identical)"

    def total_size(self) -> int:
        return sum(e.size for e in self.list())