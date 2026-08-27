"""
Structured audit logging for NWC wallet operations.

Writes append-only JSON lines to /var/log/sovran-nwc-audit.log.
Log file is owned by albyhub:albyhub with mode 0600.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

AUDIT_LOG_PATH = "/var/log/sovran-nwc-audit.log"
_AUDIT_LOCK = threading.Lock()
_initialized = False


def _ensure_log_file() -> None:
    """Ensure audit log file exists with correct permissions."""
    global _initialized
    if _initialized:
        return
    with _AUDIT_LOCK:
        if _initialized:
            return
        try:
            # Create directory if needed
            os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
            # Create file if it doesn't exist
            if not os.path.exists(AUDIT_LOG_PATH):
                with open(AUDIT_LOG_PATH, "w") as f:
                    pass
            # Set restrictive permissions
            os.chmod(AUDIT_LOG_PATH, 0o600)
            # Try to set ownership to albyhub user (best effort)
            try:
                import pwd
                import grp
                albyhub_uid = pwd.getpwnam("albyhub").pw_uid
                albyhub_gid = grp.getgrnam("albyhub").gr_gid
                os.chown(AUDIT_LOG_PATH, albyhub_uid, albyhub_gid)
            except Exception:
                pass  # Best effort; may not have permissions
            _initialized = True
        except Exception as exc:
            logger.warning("Failed to initialize audit log: %s", exc)


def audit_log(event: str, **fields: Any) -> None:
    """Write a structured audit log entry.

    Args:
        event: Event type identifier (e.g., "wallet_created", "invoice_issued")
        **fields: Additional key-value fields to include in the log entry
    """
    _ensure_log_file()

    entry = {
        "ts": time.time(),
        "event": event,
        **fields,
    }

    try:
        with _AUDIT_LOCK:
            with open(AUDIT_LOG_PATH, "a") as f:
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except Exception as exc:
        logger.error("Failed to write audit log: %s", exc)