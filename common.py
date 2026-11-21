__version__ = "2.0.0"

import subprocess
import os
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Union

logger = logging.getLogger("securitywizard")


STATUS_PASS = "PASS"
STATUS_WARNING = "WARNING"
STATUS_CRITICAL = "CRITICAL"
STATUS_INFO = "INFO"
STATUS_SKIPPED = "SKIPPED"

CATEGORIES = ["network", "ssh", "kernel", "privilege", "docker", "logs"]


@dataclass
class CmdResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    not_found: bool = False

    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.not_found


def run_cmd(args: List[str], timeout: float = 20.0) -> CmdResult:
    """Run a command with an argument list (no shell).

    Returns a CmdResult with returncode, stdout, stderr, timed_out, not_found.
    Expected failures (FileNotFoundError, TimeoutExpired) do not raise; unexpected
    exceptions are logged with the logger 'securitywizard' and returned as
    returncode=1 with the exception message in stderr.
    """
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return CmdResult(
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
    except FileNotFoundError:
        logger.warning("Command not found: %s", " ".join(args))
        return CmdResult(
            returncode=127,
            stdout="",
            stderr="command not found",
            not_found=True,
        )
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out after %.1fs: %s", timeout, " ".join(args))
        return CmdResult(
            returncode=124,
            stdout="",
            stderr="timeout",
            timed_out=True,
        )
    except Exception as exc:
        logger.exception("Unexpected error running command: %s", " ".join(args))
        return CmdResult(
            returncode=1,
            stdout="",
            stderr=str(exc),
        )


def read_text(path: str, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return default


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except Exception as exc:
        logger.warning("Failed to check euid: %s", exc)
        return False


def make_check(id: str, category: str, title: str, status: str, what_it_checks: str,
               risk: str, command: str, current_value: str = "", recommended_value: str = "",
               details=None, remediation_id: Optional[str] = None, manual_command: str = "") -> dict:
    if status not in (STATUS_PASS, STATUS_WARNING, STATUS_CRITICAL, STATUS_INFO, STATUS_SKIPPED):
        logger.warning("Unknown status %r for check %s, defaulting to INFO", status, id)
        status = STATUS_INFO
    return {
        "id": id,
        "category": category,
        "title": title,
        "status": status,
        "what_it_checks": what_it_checks,
        "risk": risk,
        "command": command,
        "current_value": current_value,
        "recommended_value": recommended_value,
        "details": details if details is not None else [],
        "remediation_id": remediation_id,
        "manual_command": manual_command
    }


def skipped_check(id: str, category: str, title: str, what_it_checks: str, risk: str,
                  command: str, reason: str, remediation_id: Optional[str] = None) -> dict:
    return {
        "id": id,
        "category": category,
        "title": title,
        "status": STATUS_SKIPPED,
        "what_it_checks": what_it_checks,
        "risk": risk,
        "command": command,
        "current_value": reason,
        "recommended_value": "",
        "details": [reason],
        "remediation_id": remediation_id,
        "manual_command": ""
    }
