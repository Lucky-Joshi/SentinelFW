"""SentinelFW exception hierarchy.

Every failure mode that SentinelFW can anticipate is represented here so that
higher layers (``cli/interface.py``) can catch one base class and print a clean
message instead of dumping a traceback at the user.

Design rules
------------
* All exceptions inherit from :class:`SentinelFWError`.
* Exceptions that wrap an external tool (``nft``) keep the original command,
  return code and stderr so the CLI can *explain* exactly what went wrong.
* Nothing in this module ever touches the system; it is pure data.
"""

from __future__ import annotations

__all__ = [
    "ExitCode",
    "SentinelFWError",
    "ConfigurationError",
    "ConfigNotFoundError",
    "ConfigValidationError",
    "PrivilegeError",
    "RootRequiredError",
    "FirewallError",
    "NftablesNotAvailableError",
    "NftablesCommandError",
    "RuleValidationError",
    "RuleConflictError",
    "SafetyViolationError",
    "BackupError",
    "DatabaseError",
    "MonitoringError",
    "LogSourceError",
    "ReportError",
    "UserAbortError",
]


class ExitCode:
    """Process exit codes used by the CLI.

    Keeping them in one place makes the tool scriptable: a shell caller can
    branch on ``130`` to mean "the operator declined".
    """

    OK = 0
    ERROR = 1
    USAGE = 2
    PERMISSION = 3
    VALIDATION = 4
    ABORTED = 5
    DEPENDENCY = 6


class SentinelFWError(Exception):
    """Base class for every anticipated SentinelFW failure."""

    exit_code: int = ExitCode.ERROR

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
class ConfigurationError(SentinelFWError):
    """Raised when configuration cannot be read, written or trusted."""

    exit_code = ExitCode.ERROR


class ConfigNotFoundError(ConfigurationError):
    """The expected configuration file does not exist."""

    exit_code = ExitCode.USAGE


class ConfigValidationError(ConfigurationError):
    """A configuration value is present but not acceptable."""

    exit_code = ExitCode.VALIDATION


# --------------------------------------------------------------------------
# Privileges
# --------------------------------------------------------------------------
class PrivilegeError(SentinelFWError):
    """Base class for privilege problems."""

    exit_code = ExitCode.PERMISSION


class RootRequiredError(PrivilegeError):
    """An operation needs root, but the process is unprivileged."""


# --------------------------------------------------------------------------
# Firewall / nftables
# --------------------------------------------------------------------------
class FirewallError(SentinelFWError):
    """Base class for firewall-plane failures."""

    exit_code = ExitCode.ERROR


class NftablesNotAvailableError(FirewallError):
    """``nft`` is missing or the kernel/netfilter stack is unavailable."""

    exit_code = ExitCode.DEPENDENCY


class NftablesCommandError(FirewallError):
    """``nft`` ran but returned a non-zero exit status."""

    exit_code = ExitCode.ERROR

    def __init__(
        self,
        message: str,
        command: list[str] | None = None,
        returncode: int | None = None,
        stderr: str = "",
        hint: str | None = None,
    ) -> None:
        super().__init__(message, hint=hint)
        self.command = list(command or [])
        self.returncode = returncode
        self.stderr = stderr.strip()


class RuleValidationError(FirewallError):
    """A rule failed validation and would never be accepted by nftables."""

    exit_code = ExitCode.VALIDATION


class RuleConflictError(FirewallError):
    """The requested rule duplicates or contradicts an existing one."""

    exit_code = ExitCode.VALIDATION


class SafetyViolationError(FirewallError):
    """A safety guard refused the operation (e.g. touching a foreign table)."""

    exit_code = ExitCode.PERMISSION


class BackupError(FirewallError):
    """A ruleset backup could not be created, listed or restored."""

    exit_code = ExitCode.ERROR


# --------------------------------------------------------------------------
# Monitoring
# --------------------------------------------------------------------------
class DatabaseError(SentinelFWError):
    """SQLite layer failure."""

    exit_code = ExitCode.ERROR


class MonitoringError(SentinelFWError):
    """Base class for the monitoring plane."""

    exit_code = ExitCode.ERROR


class LogSourceError(MonitoringError):
    """A log source could not be opened, read or is unsupported."""

    exit_code = ExitCode.DEPENDENCY


class ReportError(SentinelFWError):
    """Report generation or export failed."""

    exit_code = ExitCode.ERROR


# --------------------------------------------------------------------------
# Operator interaction
# --------------------------------------------------------------------------
class UserAbortError(SentinelFWError):
    """The operator answered "no" to a confirmation prompt."""

    exit_code = ExitCode.ABORTED