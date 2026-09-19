"""End-to-end CLI tests: every command documented in the README must work.

Each test runs `cie.py` as a subprocess from the repository root, which is how
users invoke it. In v2.0 all of these except --version/--self-test exited 1.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CIE = REPO_ROOT / "cie.py"


def run(*args: str, cwd: Path | None = None, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CIE), *args],
        cwd=str(cwd or REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


@pytest.fixture
def cli_corpus(tmp_path: Path) -> Path:
    root = tmp_path / "cli_corpus"
    root.mkdir()
    (root / "notes.txt").write_text("ordinary text\n")
    (root / "fake.png").write_bytes(b"this is not a png")
    (root / "broken.pdf").write_bytes(b"%PDF-1.4\nno eof marker")
    return root


@pytest.fixture
def isolated_db(tmp_path: Path) -> Path:
    return tmp_path / "cli.db"


# ---------------------------------------------------------------------------
# informational commands
# ---------------------------------------------------------------------------

def test_version():
    result = run("--version")
    assert result.returncode == 0
    assert "Corruption Isolation Engine" in result.stdout


def test_self_test():
    result = run("--self-test")
    assert result.returncode == 0, result.stderr
    combined = result.stdout + result.stderr
    assert "OK" in combined or "ok" in combined


def test_library_status():
    result = run("--library-status")
    assert result.returncode == 0, result.stderr
    assert "Built-in Validator" in result.stdout


def test_help_lists_documented_flags():
    result = run("--help")
    assert result.returncode == 0
    for flag in ("--scan", "--modular-scan", "--fast-scan", "--gui",
                 "--library-status", "--self-test", "--strategy", "--restore"):
        assert flag in result.stdout


# ---------------------------------------------------------------------------
# scanning
# ---------------------------------------------------------------------------

def test_scan_reports_corruption(cli_corpus, isolated_db):
    result = run("--scan", str(cli_corpus), "--db-path", str(isolated_db))
    assert result.returncode == 0, result.stderr
    assert "Total files" in result.stdout
    assert "fake.png" in result.stdout
    assert "broken.pdf" in result.stdout


def test_scan_json_output(cli_corpus, isolated_db, tmp_path):
    output = tmp_path / "report.json"
    result = run("--scan", str(cli_corpus), "--json", "--output", str(output),
                 "--db-path", str(isolated_db))
    assert result.returncode == 0, result.stderr
    payload = json.loads(output.read_text())
    assert payload["application"] == "Corruption Isolation Engine"
    assert payload["summary"]["total_files"] == 3
    assert payload["summary"]["corrupted_files"] >= 2
    entry = next(r for r in payload["results"] if r["file_path"].endswith("fake.png"))
    assert entry["is_corrupted"] is True
    assert entry["status"] == "CORRUPTED_FORMAT"
    assert "warnings" in entry and "first_corrupted_at" in entry


def test_scan_summary_only(cli_corpus, isolated_db):
    result = run("--scan", str(cli_corpus), "--summary-only", "--db-path", str(isolated_db))
    assert result.returncode == 0, result.stderr
    assert "Detailed Results" not in result.stdout


def test_scan_no_recursive(cli_corpus, isolated_db, tmp_path):
    nested = cli_corpus / "nested"
    nested.mkdir()
    (nested / "deep.png").write_bytes(b"not a png either")
    result = run("--scan", str(cli_corpus), "--no-recursive", "--db-path", str(isolated_db))
    assert result.returncode == 0, result.stderr
    assert "deep.png" not in result.stdout


def test_scan_missing_directory_fails_cleanly(tmp_path):
    result = run("--scan", str(tmp_path / "nope"), "--db-path", str(tmp_path / "x.db"))
    assert result.returncode == 1
    assert "does not exist" in result.stderr


def test_fail_on_findings_exit_codes(cli_corpus, tmp_path):
    corrupt = run("--scan", str(cli_corpus), "--fail-on-findings",
                  "--db-path", str(tmp_path / "a.db"))
    assert corrupt.returncode == 2

    clean_dir = tmp_path / "clean"
    clean_dir.mkdir()
    (clean_dir / "ok.txt").write_text("fine")
    clean = run("--scan", str(clean_dir), "--fail-on-findings",
                "--db-path", str(tmp_path / "b.db"))
    assert clean.returncode == 0, clean.stdout + clean.stderr


def test_scan_twice_reports_persistent_corruption(cli_corpus, isolated_db):
    first = run("--scan", str(cli_corpus), "--summary-only", "--db-path", str(isolated_db))
    second = run("--scan", str(cli_corpus), "--summary-only", "--db-path", str(isolated_db))
    assert first.returncode == second.returncode == 0
    corrupt_first = next(l for l in first.stdout.splitlines() if "Corrupted files" in l)
    corrupt_second = next(l for l in second.stdout.splitlines() if "Corrupted files" in l)
    assert corrupt_first == corrupt_second, "corruption count changed between identical scans"


# ---------------------------------------------------------------------------
# modular scanning
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("strategy", ["fast", "balanced", "deep"])
def test_modular_scan_runs_each_strategy(cli_corpus, strategy):
    result = run("--modular-scan", str(cli_corpus), "--strategy", strategy)
    assert result.returncode == 0, result.stderr
    assert "Strategy" in result.stdout
    assert strategy in result.stdout


def test_fast_scan_alias_scans_instead_of_launching_gui(cli_corpus):
    result = run("--fast-scan", str(cli_corpus))
    assert result.returncode == 0, result.stderr
    assert "Modular Scanner" in result.stdout
    assert "Strategy            : fast" in result.stdout


def test_modular_scan_json(cli_corpus, tmp_path):
    output = tmp_path / "modular.json"
    result = run("--modular-scan", str(cli_corpus), "--json", "--output", str(output))
    assert result.returncode == 0, result.stderr
    payload = json.loads(output.read_text())
    assert payload["strategy"] == "fast"
    assert payload["stats"]["total_files"] >= 1


# ---------------------------------------------------------------------------
# quarantine lifecycle (CLI)
# ---------------------------------------------------------------------------

def test_quarantine_then_list_then_restore(tmp_path):
    root = tmp_path / "work"
    root.mkdir()
    target = root / "victim.bin"
    target.write_bytes(b"payload data")
    db = tmp_path / "q.db"
    quarantine = tmp_path / "quarantine"

    # corrupt-free scan first so we control what gets quarantined
    result = run("--scan", str(root), "--quarantine", "--db-path", str(db),
                 "--quarantine-dir", str(quarantine))
    assert result.returncode == 0, result.stderr

    listing = run("--list-quarantine", "--db-path", str(db), "--quarantine-dir", str(quarantine))
    assert listing.returncode == 0, listing.stderr
    assert "Quarantined Files" in listing.stdout


def test_quarantine_and_restore_end_to_end(tmp_path):
    import sys as _sys

    _sys.path.insert(0, str(REPO_ROOT))
    from src.python.core_analyzer import AnalyzerConfig, CorruptionDetector

    root = tmp_path / "work"
    root.mkdir()
    victim = root / "damaged.png"
    victim.write_bytes(b"not a png at all")
    db = tmp_path / "c.db"
    quarantine = tmp_path / "q"

    detector = CorruptionDetector(AnalyzerConfig(db_path=str(db), quarantine_dir=str(quarantine)))
    detector.scan_directory(root)                      # baseline
    assert victim.exists()
    assert detector.quarantine_file(str(victim), reason="CLI test") is True
    assert not victim.exists()

    listing = run("--list-quarantine", "--db-path", str(db), "--quarantine-dir", str(quarantine))
    assert "damaged" in listing.stdout

    entry = detector.list_quarantine()[0]
    restore = run("--restore", entry.quarantine_path, "--db-path", str(db),
                  "--quarantine-dir", str(quarantine))
    assert restore.returncode == 0, restore.stderr
    assert victim.exists()


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------

def test_config_file_is_used(tmp_path, cli_corpus):
    config = tmp_path / "cie_config.json"
    db_from_config = tmp_path / "configured.db"
    config.write_text(json.dumps({
        "database": {"path": str(db_from_config)},
        "scanning": {"chunk_size": 4096},
    }))
    result = run("--scan", str(cli_corpus), "--config", str(config))
    assert result.returncode == 0, result.stderr
    assert db_from_config.exists(), "the configured database path was ignored"


def test_cli_overrides_config_file(tmp_path, cli_corpus):
    config = tmp_path / "cie_config.json"
    config.write_text(json.dumps({"database": {"path": str(tmp_path / "ignored.db")}}))
    override = tmp_path / "override.db"
    result = run("--scan", str(cli_corpus), "--config", str(config), "--db-path", str(override))
    assert result.returncode == 0, result.stderr
    assert override.exists()
    assert not (tmp_path / "ignored.db").exists()


def test_no_config_flag(tmp_path, cli_corpus):
    config = tmp_path / "cie_config.json"
    config.write_text(json.dumps({"database": {"path": str(tmp_path / "ignored2.db")}}))
    result = run("--scan", str(cli_corpus), "--config", str(config), "--no-config",
                 "--db-path", str(tmp_path / "explicit.db"))
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "ignored2.db").exists()


def test_invalid_arguments_rejected(tmp_path, cli_corpus):
    for bad in (["--max-workers", "0"], ["--chunk-size", "0"],
                ["--entropy-threshold", "9.0"]):
        result = run("--scan", str(cli_corpus), *bad, "--db-path", str(tmp_path / "x.db"))
        assert result.returncode == 2, bad


def test_engine_never_quarantines_its_own_database(tmp_path):
    """Scanning the directory that holds the database must not move it."""
    root = tmp_path / "work"
    root.mkdir()
    (root / "file.txt").write_text("data")
    db = root / "cie.db"
    result = run("--scan", str(root), "--db-path", str(db),
                 "--quarantine-dir", str(root / "q"), "--json", "--output", str(tmp_path / "r.json"))
    assert result.returncode == 0, result.stderr
    assert db.exists(), "the CLI moved its own database"
    reported = {Path(entry["file_path"]).name for entry in json.loads((tmp_path / "r.json").read_text())["results"]}
    assert not [name for name in reported if name.startswith("cie.db")], reported
