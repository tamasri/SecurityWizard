import subprocess
import os
from datetime import datetime


STATUS_PASS = "PASS"
STATUS_WARNING = "WARNING"
STATUS_CRITICAL = "CRITICAL"
STATUS_INFO = "INFO"
STATUS_SKIPPED = "SKIPPED"

CATEGORIES = ["network", "ssh", "kernel", "privilege", "docker", "logs"]


def run_cmd(args, timeout=20):
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def read_text(path, default=""):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return default


def is_root():
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def make_check(id, category, title, status, what_it_checks, risk, command,
               current_value="", recommended_value="", details=None,
               remediation_id=None, manual_command=""):
    if status not in (STATUS_PASS, STATUS_WARNING, STATUS_CRITICAL, STATUS_INFO, STATUS_SKIPPED):
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


def skipped_check(id, category, title, what_it_checks, risk, command, reason, remediation_id=None):
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
