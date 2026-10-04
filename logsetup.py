"""Logging bootstrap for SentinelFW.

Why this module exists
----------------------
Every component (firewall plane, monitoring plane, CLI) writes to the same
two sinks:

1. ``logs/sentinelfw.log`` - a rotating file, kept out of git.
2. stderr - only when the operator asked for it with ``--verbose`` / ``--debug``.

A rotating file matters on a machine that is left running a monitor: without
it, ``sentinelfw.log`` would grow until the disk fills.

Every log record produced by ``nft`` execution includes the exact command, so
the log doubles as an audit trail of what the tool did to the kernel firewall.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
from pathlib import Path

__all__ = ["setup_logging", "get_logger", "LOG_FORMAT", "DEBUG_FORMAT"]

LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)-22s %(message)s"
DEBUG_FORMAT = "%(asctime)s %(levelname)-8s %(name)-22s %(filename)s:%(lineno)d %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_ROOT_LOGGER_NAME = "sentinelfw"
_configured = False


def setup_logging(
    log_file: str | os.PathLike[str] | None,
    *,
    level: str = "INFO",
    verbose: bool = False,
    debug: bool = False,
    to_stderr: bool = True,
) -> logging.Logger:
    """Configure the ``sentinelfw`` logger tree.

    Parameters
    ----------
    log_file:
        Destination for the rotating file handler. ``None`` disables file
        logging (useful for tests and for ``--json`` machine output).
    level:
        Baseline level name (``"INFO"``, ``"WARNING"``, ...).
    verbose:
        Also log ``INFO`` and above to stderr.
    debug:
        Also log ``DEBUG`` and above to stderr, with file/line information.

    Returns
    -------
    The configured root logger for the tool.
    """
    global _configured

    logger = logging.getLogger(_ROOT_LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    # SentinelFW owns this tree; do not also push records to the interpreter
    # root logger, which would duplicate output in user applications.
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:  # pragma: no cover - defensive
            pass

    if debug:
        effective_level = logging.DEBUG
    elif level.upper() == "DEBUG":
        effective_level = logging.DEBUG
    else:
        effective_level = getattr(logging, str(level).upper(), logging.INFO)

    file_handler: logging.Handler | None = None
    if log_file:
        path = Path(log_file).expanduser()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                path,
                maxBytes=5 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8",
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(
                logging.Formatter(DEBUG_FORMAT if debug else LOG_FORMAT, DATE_FORMAT)
            )
            logger.addHandler(file_handler)
        except OSError:
            # A read-only home directory must not stop the CLI from working.
            # Surface the problem on stderr instead of raising.
            logging.getLogger(_ROOT_LOGGER_NAME).warning(
                "Could not open log file %s; continuing with stderr logging only", path
            )

    stderr_handler: logging.Handler | None = None
    if to_stderr and (verbose or debug):
        stderr_handler = logging.StreamHandler()
        stderr_handler.setLevel(logging.DEBUG if debug else logging.INFO)
        stderr_handler.setFormatter(
            logging.Formatter(DEBUG_FORMAT if debug else LOG_FORMAT, DATE_FORMAT)
        )
        logger.addHandler(stderr_handler)

    if logger.handlers:
        # Handlers expose ``.level``; only loggers have ``getEffectiveLevel``.
        logger.setLevel(min(h.level for h in logger.handlers))
    else:
        # Nothing to log to (e.g. pure --json mode): stay quiet, not broken.
        logger.addHandler(logging.NullHandler())
        logger.setLevel(logging.CRITICAL)

    _configured = True
    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger, e.g. ``get_logger("firewall.nft")``.

    Child names are namespaced under ``sentinelfw`` so a single
    :func:`setup_logging` call configures everything.
    """
    if name.startswith(_ROOT_LOGGER_NAME):
        return logging.getLogger(name)
    return logging.getLogger(f"{_ROOT_LOGGER_NAME}.{name}")


def is_configured() -> bool:  # pragma: no cover - introspection helper
    """Whether :func:`setup_logging` has already run in this process."""
    return _configured