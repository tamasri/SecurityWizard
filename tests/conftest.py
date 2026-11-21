import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECURITYWIZARD_DRY_RUN_ONLY", "1")
# The dashboard is locked by default; the general test-suite runs it open and the auth tests switch it on explicitly.
os.environ.setdefault("SECURITYWIZARD_AUTH", "0")


@pytest.fixture(autouse=True)
def _isolated_data_dirs(tmp_path, monkeypatch):
    """Never let a test write credentials, history or audit files outside its temporary directory."""
    monkeypatch.setenv("SECURITYWIZARD_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SECURITYWIZARD_BACKUP_DIR", str(tmp_path / "backups"))
    yield
