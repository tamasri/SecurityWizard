"""Version consistency and documentation completeness."""

import pathlib
import re

from fastapi.testclient import TestClient

import auth
import common
import main

ROOT = pathlib.Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def test_version_is_semver_two_zero_zero():
    assert SEMVER.match(common.__version__)
    assert common.__version__ == "2.0.0"
    assert main.app.version == common.__version__


def test_version_is_served_and_shown():
    auth.reset_for_tests()
    with TestClient(main.app, base_url="http://127.0.0.1:8443") as client:
        assert client.get("/api/version").json() == {"version": common.__version__}
        footer = client.get("/").text
    assert "© 2026 SecurityWizard" in footer or "&copy; 2026 SecurityWizard" in footer
    assert 'id="app-version"' in footer
    auth.reset_for_tests()


def test_changelog_has_the_current_release():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert re.search(r"^## \[2\.0\.0\]", text, re.M)


def test_readme_documents_every_environment_variable_used_by_the_code():
    used = set()
    for path in list(ROOT.glob("*.py")) + [ROOT / "setup.sh", ROOT / "Dockerfile"]:
        used |= set(re.findall(r"SECURITYWIZARD_[A-Z_]+", path.read_text(encoding="utf-8")))
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    missing = sorted(name for name in used if name not in readme)
    assert not missing, missing
