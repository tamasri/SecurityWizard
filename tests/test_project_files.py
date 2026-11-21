"""The project metadata and tooling files must stay valid and consistent."""

import pathlib
import re

import pytest

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib

import common

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _toml(name):
    with open(ROOT / name, "rb") as handle:
        return tomllib.load(handle)


def test_pyproject_is_valid_and_matches_the_application_version():
    data = _toml("pyproject.toml")
    assert data["project"]["name"] == "securitywizard"
    assert data["project"]["version"] == common.__version__
    assert data["tool"]["ruff"]["line-length"] == 120


def test_every_python_module_is_listed_in_the_package_metadata():
    listed = set(_toml("pyproject.toml")["tool"]["setuptools"]["py-modules"])
    present = {p.stem for p in ROOT.glob("*.py")}
    assert present <= listed, sorted(present - listed)


def _requirement_blocks(name):
    """Split a pip-compile output into (requirement line, hash lines) blocks."""
    blocks, current = [], None
    for raw in (ROOT / name).read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw[0].isspace():
            if current is not None and raw.strip().startswith("--hash=sha256:"):
                current[1].append(raw.strip().rstrip("\\").strip())
            continue
        current = (raw.rstrip("\\").strip(), [])
        blocks.append(current)
    return blocks


@pytest.mark.parametrize("name", ["requirements.txt", "requirements-dev.txt"])
def test_lock_files_pin_every_package_with_hashes(name):
    blocks = _requirement_blocks(name)
    assert len(blocks) > 10
    for line, hashes in blocks:
        assert re.match(r"^[A-Za-z0-9._-]+==[0-9]", line), line
        assert hashes, "no hash for " + line


def test_lock_files_cover_the_direct_requirements():
    runtime = {line.split("==")[0].lower() for line, _ in _requirement_blocks("requirements.txt")}
    for direct in ("fastapi", "uvicorn", "pydantic", "argon2-cffi", "starlette"):
        assert direct in runtime, direct
    for name in ("requirements.in", "requirements-dev.in"):
        for line in (ROOT / name).read_text(encoding="utf-8").splitlines():
            if line and not line.startswith(("-", "#")):
                assert "==" in line, "%s must pin every direct requirement exactly: %s" % (name, line)


def test_ci_workflow_is_manual_only():
    yaml = pytest.importorskip("yaml")
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    triggers = workflow.get("on", workflow.get(True))  # YAML 1.1 reads a bare `on` as the boolean True
    assert list(triggers) == ["workflow_dispatch"]
    assert {"lint", "types", "test", "security"} <= set(workflow["jobs"])


def test_other_config_files_are_valid_yaml():
    yaml = pytest.importorskip("yaml")
    for name in (".pre-commit-config.yaml", "bandit.yaml"):
        assert yaml.safe_load((ROOT / name).read_text(encoding="utf-8")) is not None


def test_dockerfile_runs_as_a_non_root_user_with_a_healthcheck():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^USER\s+\S+", text, re.M) and "USER root" not in text
    assert "HEALTHCHECK" in text
    assert "SECURITYWIZARD_DRY_RUN_ONLY=1" in text
