"""Behavioural tests for the core engine, focused on the data-safety bugs the
audit reproduced: baseline amnesia, self-quarantine, misreported faults and
missing restore support."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from src.python.core_analyzer import (
    AnalyzerConfig,
    CorruptionDetector,
    FileStatus,
    config_from_mapping,
    load_config_file,
)
from tests.conftest import corrupt_byte, make_real_png


# ---------------------------------------------------------------------------
# status / baseline behaviour
# ---------------------------------------------------------------------------

def test_new_file_is_not_corrupt(detector, make_file):
    path = make_file("hello.txt", b"Hello, World!")
    result = detector.analyze_file(path)
    assert result.status is FileStatus.NEW_FILE
    assert result.is_corrupted is False
    assert result.file_size == 13
    assert result.checksum


def test_same_size_change_is_detected(detector, make_file):
    path = make_file("doc.txt", b"ABCDE")
    detector.analyze_file(path)
    path.write_bytes(b"12345")
    assert detector.analyze_file(path).status is FileStatus.CORRUPTED_CHECKSUM


def test_size_change_is_detected(detector, make_file):
    path = make_file("doc.txt", b"small")
    detector.analyze_file(path)
    path.write_bytes(b"a much longer body of content")
    assert detector.analyze_file(path).status is FileStatus.CORRUPTED_SIZE


def test_corruption_is_not_forgotten_on_later_scans(detector, workdir, make_file):
    """v2.0 re-baselined damaged files, so they looked healthy after one report."""
    path = make_file("important.txt", b"ORIGINAL CONTENT")
    detector.scan_directory(workdir)
    path.write_bytes(b"TAMPERED CONTENT")           # same length, new bytes

    assert detector.scan_directory(workdir)[0].is_corrupted is True
    for _ in range(3):                              # must stay flagged
        results = detector.scan_directory(workdir)
        assert results[0].is_corrupted is True, "corruption was forgotten"
        assert results[0].status is FileStatus.CORRUPTED_CHECKSUM


def test_baseline_is_preserved_while_damaged(detector, workdir, make_file):
    path = make_file("data.bin", b"A" * 100)
    detector.scan_directory(workdir)
    path.write_bytes(b"B" * 150)
    first = detector.scan_directory(workdir)[0]
    assert first.baseline_size_bytes == 100
    assert first.first_corrupt_at is not None
    second = detector.scan_directory(workdir)[0]
    assert second.baseline_size_bytes == 100, "baseline was overwritten by damaged content"


def test_format_corruption_detected(detector, make_file):
    path = make_file("fake.png", b"definitely not a png")
    result = detector.analyze_file(path)
    assert result.status is FileStatus.CORRUPTED_FORMAT
    assert result.format_validation is not None
    assert result.format_validation.is_valid is False


def test_empty_file_is_a_warning_not_corruption(detector, make_file):
    path = make_file("empty.txt", b"")
    result = detector.analyze_file(path)
    assert result.is_corrupted is False
    assert result.status is FileStatus.SUSPICIOUS_EMPTY
    assert result.is_warning is True


# ---------------------------------------------------------------------------
# quarantine safety
# ---------------------------------------------------------------------------

def test_engine_never_scans_its_own_database(detector, workdir, make_file):
    """The database and its -wal/-shm siblings must be excluded from scans."""
    make_file("report.txt", b"data")
    for _ in range(3):
        detector.scan_directory(workdir)
    names = {Path(r.file_path).name for r in detector.scan_directory(workdir)}
    assert not [n for n in names if n.startswith("cie.db")], names


def test_quarantine_refuses_the_engines_own_database(detector, workdir, make_file):
    make_file("report.txt", b"data")
    detector.scan_directory(workdir)
    db_path = Path(detector.database_path)
    assert detector.quarantine_file(str(db_path)) is False
    assert db_path.exists(), "the engine moved its own database"
    assert detector.scan_directory(workdir)          # still usable


def test_quarantine_and_restore_round_trip(detector, make_file):
    path = make_file("payload.bin", b"unique payload")
    assert detector.quarantine_file(str(path)) is True
    assert not path.exists()

    entries = detector.list_quarantine()
    assert len(entries) == 1
    assert entries[0].original_path == str(path.resolve())

    restored = detector.restore_file(entries[0].quarantine_path)
    assert Path(restored).read_bytes() == b"unique payload"
    assert detector.list_quarantine() == ()


def test_restore_does_not_overwrite_an_existing_file(detector, make_file):
    path = make_file("thing.bin", b"original")
    detector.quarantine_file(str(path))
    path.write_bytes(b"a newer file took this name")   # recreate at the old path

    entry = detector.list_quarantine()[0]
    restored = Path(detector.restore_file(entry.quarantine_path))
    assert restored != path, "restore overwrote an existing file"
    assert restored.read_bytes() == b"original"
    assert path.read_bytes() == b"a newer file took this name"


def test_restore_requires_a_log_entry(detector, workdir):
    orphan = workdir / "orphan.bin.quarantine"
    orphan.write_bytes(b"no log row for me")
    with pytest.raises(Exception):
        detector.restore_file(orphan)


def test_quarantine_directory_is_excluded_from_scans(detector, workdir, make_file):
    keep = make_file("keep.txt", b"keep me")
    quarantine = Path(detector.quarantine_dir)
    quarantine.mkdir(parents=True, exist_ok=True)
    (quarantine / "hidden.txt").write_bytes(b"do not scan")
    scanned = {r.file_path for r in detector.scan_directory(workdir)}
    assert str(keep.resolve()) in scanned
    assert str((quarantine / "hidden.txt").resolve()) not in scanned


# ---------------------------------------------------------------------------
# faults vs corruption
# ---------------------------------------------------------------------------

def _running_as_root() -> bool:
    import os

    return hasattr(os, "geteuid") and os.geteuid() == 0


@pytest.mark.skipif(_running_as_root(), reason="root ignores file permissions")
def test_unreadable_file_is_a_fault_not_corruption(detector, make_file):
    path = make_file("noperm.bin", b"\x00\x01\x02")
    path.chmod(0o000)
    try:
        result = detector.analyze_file(path)
    finally:
        path.chmod(0o644)
    assert result.status is FileStatus.UNREADABLE
    assert result.has_fault is True
    assert result.is_corrupted is False


def test_missing_file_reports_missing(detector, workdir):
    result = detector.analyze_file(workdir / "nope.bin")
    assert result.status is FileStatus.MISSING


def test_database_failure_is_reported_as_error(detector, monkeypatch, make_file):
    """A broken database used to look like an unreadable file (and exit 0)."""
    path = make_file("anything.txt", b"data")

    def explode(*_args, **_kwargs):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(detector._engine._repo, "get_record", explode)
    result = detector.analyze_file(path)
    assert result.status is FileStatus.ERROR
    assert result.has_fault is True
    assert "database" in (result.error_message or "").lower()


# ---------------------------------------------------------------------------
# storage
# ---------------------------------------------------------------------------

def test_in_memory_database_works(config, make_file, workdir):
    """`:memory:` used to lose its schema between per-operation connections."""
    memory_config = AnalyzerConfig(
        db_path=":memory:", quarantine_dir=str(workdir / "quarantine")
    )
    detector = CorruptionDetector(memory_config)
    make_file("a.txt", b"content")
    results = detector.scan_directory(workdir, recursive=True)
    assert results


def test_legacy_schema_is_migrated_in_place(tmp_path):
    legacy = tmp_path / "legacy.db"
    connection = sqlite3.connect(legacy)
    connection.execute(
        """CREATE TABLE file_metadata (
               file_path TEXT PRIMARY KEY, size_bytes INTEGER NOT NULL,
               checksum TEXT NOT NULL, last_modified REAL NOT NULL,
               is_corrupted INTEGER NOT NULL DEFAULT 0,
               shannon_entropy REAL NOT NULL DEFAULT 0.0,
               file_type TEXT, analysis_date TEXT NOT NULL)"""
    )
    connection.execute(
        """CREATE TABLE quarantine_log (
               id INTEGER PRIMARY KEY AUTOINCREMENT, original_path TEXT NOT NULL,
               quarantine_path TEXT NOT NULL, reason TEXT NOT NULL,
               action_date TEXT NOT NULL)"""
    )
    connection.commit()
    connection.close()

    detector = CorruptionDetector(
        AnalyzerConfig(db_path=str(legacy), quarantine_dir=str(tmp_path / "q"))
    )
    (tmp_path / "new.txt").write_text("hello")
    assert detector.scan_directory(tmp_path, recursive=True)

    columns = {
        row[1]
        for row in sqlite3.connect(legacy).execute("PRAGMA table_info(file_metadata)")
    }
    assert {"first_seen", "first_corrupt", "last_status", "last_seen"} <= columns


def test_config_file_is_loaded_and_cli_overrides_win(tmp_path):
    config_path = tmp_path / "cie_config.json"
    config_path.write_text(
        '{"database": {"path": "from_file.db"}, "scanning": {"chunk_size": 4096},'
        ' "detection": {"checksum_algorithm": "sha256"}}'
    )
    loaded = load_config_file(config_path)
    assert loaded["database"]["path"] == "from_file.db"

    merged = config_from_mapping(loaded, db_path="from_cli.db")
    assert merged.db_path == "from_cli.db"       # explicit override wins
    assert merged.chunk_size == 4096             # file value survives

    defaults = config_from_mapping({}, db_path=None, chunk_size=None)
    assert defaults.db_path == AnalyzerConfig().db_path


def test_missing_config_file_is_not_fatal(tmp_path):
    assert load_config_file(tmp_path / "nope.json") == {}


# ---------------------------------------------------------------------------
# ransomware heuristics
# ---------------------------------------------------------------------------

def test_encrypted_looking_file_with_ransomware_extension_is_flagged(detector, make_file):
    import os

    path = make_file("holiday.jpg.locked", os.urandom(8192))
    assert detector.analyze_file(path).status is FileStatus.SUSPECTED_RANSOMWARE


@pytest.mark.parametrize("suffix", ["docx", "pptx"])
def test_high_entropy_office_file_is_not_ransomware(detector, workdir, suffix):
    """A high-entropy *office document* must not be called ransomware.

    Office packages are compressed archives and legitimately contain
    high-entropy data, so entropy alone must never trigger the ransomware
    verdict. The fixtures are genuine documents (built with python-docx /
    python-pptx) with an incompressible blob added inside the package, which
    is exactly the shape of a false positive this rule exists to prevent.
    """
    import os
    import zipfile

    from conftest import make_real_docx, make_real_pptx

    if suffix == "docx":
        path = make_real_docx(workdir / "deck.docx")
    else:
        path = make_real_pptx(workdir / "deck.pptx")

    with zipfile.ZipFile(path, "a", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("docProps/high-entropy.bin", os.urandom(60000))

    result = detector.analyze_file(path)
    assert result.is_corrupted is False, result.error_message
    assert result.status is not FileStatus.SUSPECTED_RANSOMWARE


def test_entropy_jump_versus_baseline_is_flagged(detector, make_file):
    import os

    path = make_file("database.notes", b"readable text " * 500)
    detector.analyze_file(path)                  # baseline: low entropy
    path.write_bytes(os.urandom(7000))           # encrypted in place
    result = detector.analyze_file(path)
    assert result.status is FileStatus.SUSPECTED_RANSOMWARE
    assert "entropy jumped" in (result.error_message or "")


def test_ransomware_detection_can_be_disabled(make_file, workdir):
    import os

    detector = CorruptionDetector(
        AnalyzerConfig(
            db_path=str(workdir / "d.db"),
            quarantine_dir=str(workdir / "q"),
            detect_ransomware=False,
        )
    )
    path = make_file("payload.locked", os.urandom(4096))
    assert detector.analyze_file(path).status is not FileStatus.SUSPECTED_RANSOMWARE


# ---------------------------------------------------------------------------
# scanning
# ---------------------------------------------------------------------------

def test_scan_is_deterministic_and_sorted(detector, workdir, make_file):
    for index in range(12):
        make_file(f"files/f{index:02d}.txt", f"content-{index}".encode())
    results = detector.scan_directory(workdir, recursive=True)
    assert [r.file_path for r in results] == sorted(
        (r.file_path for r in results), key=str.casefold
    )


def test_non_recursive_scan_skips_subdirectories(detector, workdir, make_file):
    make_file("top.txt", b"top")
    make_file("nested/deep.txt", b"deep")
    names = {Path(r.file_path).name for r in detector.scan_directory(workdir, recursive=False)}
    assert names == {"top.txt"}


def test_empty_directory_returns_no_results(detector, workdir):
    empty = workdir / "empty"
    empty.mkdir()
    assert detector.scan_directory(empty) == ()


def test_scanning_a_missing_directory_raises(detector, workdir):
    with pytest.raises(Exception):
        detector.scan_directory(workdir / "does-not-exist")


def test_real_png_is_accepted(detector, make_file):
    path = make_file("real.png", make_real_png())
    assert detector.analyze_file(path).is_corrupted is False


def test_real_png_bit_rot_is_detected(detector, make_file):
    data = make_real_png()
    path = make_file("rot.png", corrupt_byte(data, len(data) // 2))
    assert detector.analyze_file(path).is_corrupted is True


# ---------------------------------------------------------------------------
# re-baselining: deliberately accepting a reviewed change
# ---------------------------------------------------------------------------

def test_rebaseline_accepts_a_reviewed_change(detector, workdir):
    """After a human reviews a finding, the new content becomes the baseline."""
    path = workdir / "notes.txt"
    path.write_text("original content\n" * 40)
    assert detector.analyze_file(path).status is FileStatus.NEW_FILE

    path.write_text("edited content, deliberately different\n" * 40)
    flagged = detector.analyze_file(path)
    assert flagged.status is FileStatus.CORRUPTED_SIZE
    assert flagged.is_corrupted is True

    outcomes = detector.rebaseline([path])
    assert [o.action for o in outcomes] == ["rebaselined"]
    assert outcomes[0].previous_status == "CORRUPTED_SIZE"

    after = detector.analyze_file(path)
    assert after.status is FileStatus.VALID
    assert after.is_corrupted is False


def test_rebaseline_clears_the_previous_finding_in_the_database(detector, workdir, config):
    path = workdir / "notes.txt"
    path.write_text("one\n" * 50)
    detector.analyze_file(path)
    path.write_text("two\n" * 50)
    detector.analyze_file(path)
    detector.rebaseline([path])

    with sqlite3.connect(config.db_path) as connection:
        row = connection.execute(
            "SELECT is_corrupted, first_corrupt FROM file_metadata WHERE file_path = ?",
            (str(path),),
        ).fetchone()
    assert row is not None
    assert row[0] == 0, "rebaseline left is_corrupted set"
    assert row[1] is None, "rebaseline left first_corrupt set"


def test_rebaseline_refuses_a_structurally_broken_file(detector, workdir):
    """It must not become a way to bless a file that fails validation."""
    path = workdir / "broken.png"
    path.write_bytes(b"this is not a png")
    outcomes = detector.rebaseline([path])
    assert outcomes[0].action == "refused"
    assert outcomes[0].reason
    assert outcomes[0].ok is False


def test_rebaseline_force_accepts_a_broken_file(detector, workdir):
    path = workdir / "broken.png"
    path.write_bytes(b"this is not a png")
    outcomes = detector.rebaseline([path], force=True)
    assert outcomes[0].action == "rebaselined"


def test_rebaseline_refuses_the_engines_own_database(detector, config):
    outcomes = detector.rebaseline([config.db_path])
    assert outcomes[0].action == "refused"
    assert "engine" in (outcomes[0].reason or "").lower()


def test_rebaseline_reports_missing_paths(detector, workdir):
    outcomes = detector.rebaseline([workdir / "gone.txt"])
    assert outcomes[0].action == "missing"
    assert outcomes[0].ok is False


def test_rebaseline_dry_run_does_not_change_anything(detector, workdir, config):
    path = workdir / "notes.txt"
    path.write_text("before\n" * 40)
    detector.analyze_file(path)
    path.write_text("after\n" * 60)
    detector.analyze_file(path)

    outcomes = detector.rebaseline([path], dry_run=True)
    assert outcomes[0].action == "rebaselined"      # it *would* be accepted
    assert detector.analyze_file(path).status is FileStatus.CORRUPTED_SIZE


def test_rebaseline_walks_a_directory(detector, workdir):
    root = workdir / "changed"
    root.mkdir()
    for name in ("a.txt", "b.txt"):
        path = root / name
        path.write_text("content\n" * 30)
        detector.analyze_file(path)
        path.write_text("changed content\n" * 30)
        detector.analyze_file(path)

    outcomes = detector.rebaseline([root])
    assert {o.action for o in outcomes} == {"rebaselined"}
    assert len(outcomes) == 2
    assert all(not r.is_corrupted for r in detector.scan_directory(root))


def test_rebaseline_keeps_first_seen_history(detector, workdir, config):
    path = workdir / "notes.txt"
    path.write_text("content\n" * 30)
    detector.analyze_file(path)
    with sqlite3.connect(config.db_path) as connection:
        first_seen = connection.execute(
            "SELECT first_seen FROM file_metadata WHERE file_path = ?", (str(path),)
        ).fetchone()[0]

    detector.rebaseline([path])
    with sqlite3.connect(config.db_path) as connection:
        after = connection.execute(
            "SELECT first_seen FROM file_metadata WHERE file_path = ?", (str(path),)
        ).fetchone()[0]
    assert after == first_seen, "rebaseline should not reset first_seen"
