"""The CI contract: a clean checkout must verify itself.

The audit's top recommendation was continuous integration, because every one
of the 17 findings it reported would have been caught by a workflow that
installs the dependencies, builds the C++ engine, runs the test suite and then
scans a directory of *known-good* files with ``--fail-on-findings``.

These tests keep that contract honest: the workflow file must exist and run
those four commands, and the fixture directory it scans must really be clean.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CIE = REPO_ROOT / "cie.py"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
FIXTURES = REPO_ROOT / "tests" / "fixtures"

REQUIRED_COMMANDS = (
    "pip install -r requirements.txt",
    "make cpp",
    "python3 -m pytest",
    "python3 cie.py --scan tests/fixtures --fail-on-findings",
)


def test_workflow_exists():
    assert WORKFLOW.is_file(), f"CI workflow missing: {WORKFLOW}"


def test_workflow_runs_the_four_verification_commands():
    text = WORKFLOW.read_text(encoding="utf-8")
    missing = [command for command in REQUIRED_COMMANDS if command not in text]
    assert not missing, f"workflow does not run: {missing}"


def test_workflow_runs_on_a_clean_checkout():
    """It must check the repository out and not inherit local state."""
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "actions/checkout@" in text
    assert "actions/setup-python@" in text
    assert "runs-on:" in text


def test_fixture_directory_is_committed():
    assert FIXTURES.is_dir(), "tests/fixtures is missing"
    names = {path.name for path in FIXTURES.iterdir() if path.is_file()}
    # Spread across the validated formats, so the scan exercises every
    # validator rather than a single code path.
    for expected in ("readme.txt", "logo.png", "photo.jpg", "report.pdf",
                     "contract.docx", "budget.xlsx", "slides.pptx", "bundle.zip"):
        assert expected in names, f"{expected} missing from tests/fixtures"


def test_fixtures_scan_clean_with_fail_on_findings(tmp_path):
    """The exact CI command, against the committed fixtures."""
    result = subprocess.run(
        [
            sys.executable, str(CIE),
            "--scan", str(FIXTURES),
            "--fail-on-findings",
            "--db-path", str(tmp_path / "ci.db"),
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert "Corrupted files    : 0" in result.stdout, combined
