"""The GUI's Rebaseline action, headless.

The CLI has had ``--rebaseline`` since the Phase-4 work: a reviewed file can be
accepted as its own new baseline, but a file the validators still reject is
refused unless the user explicitly forces it. The results table now offers the
same action, and these tests keep it honest:

* the pure helpers (summary text, result merging) are tested directly;
* the Tk-bound method is driven on an *uninitialised* window
  (``object.__new__``) with a stub detector and stub dialogs, so no display is
  needed — which matters because CI runs headless;
* one opt-in test builds a real menu when a display happens to exist.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import src.gui.main_window as gui  # noqa: E402
from src.python.core_analyzer import FileStatus, RebaselineOutcome  # noqa: E402


# ---------------------------------------------------------------------------
# test doubles
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FakeResult:
    """Stands in for core_analyzer.FileAnalysisResult."""

    file_path: str
    status: FileStatus = FileStatus.CORRUPTED_FORMAT

    @property
    def is_corrupted(self) -> bool:
        return self.status is FileStatus.CORRUPTED_FORMAT


class StubDetector:
    """Records what the window asks the engine to do."""

    def __init__(self, *, refuse_first: bool = False) -> None:
        self.refuse_first = refuse_first
        self.rebaseline_calls: list[dict[str, object]] = []
        self.analyzed: list[str] = []

    def rebaseline(
        self,
        targets,
        *,
        recursive: bool = True,
        force: bool = False,
        dry_run: bool = False,
    ):
        targets = tuple(str(target) for target in targets)
        self.rebaseline_calls.append(
            {"targets": targets, "force": force, "recursive": recursive, "dry_run": dry_run}
        )
        if self.refuse_first and not force:
            return tuple(
                RebaselineOutcome(path, "refused", previous_status="CORRUPTED_FORMAT",
                                  reason="format validation failed")
                for path in targets
            )
        return tuple(
            RebaselineOutcome(path, "rebaselined", previous_status="CORRUPTED_FORMAT")
            for path in targets
        )

    def analyze_file(self, path):
        self.analyzed.append(str(path))
        return FakeResult(str(path), FileStatus.VALID)


class StubDialogs:
    """messagebox replacement: scripted answers, recorded calls."""

    def __init__(self, *answers: bool) -> None:
        self.answers = list(answers)
        self.calls: list[tuple[str, str, str]] = []

    def _ask(self, kind: str, title: str, message: str, **_kwargs) -> bool:
        self.calls.append((kind, title, message))
        if not self.answers:
            return False
        return bool(self.answers.pop(0))

    def askyesno(self, title, message, **kwargs):
        return self._ask("askyesno", title, message, **kwargs)

    def showinfo(self, title, message, **kwargs):
        self._ask("showinfo", title, message, **kwargs)
        return "ok"

    def showwarning(self, title, message, **kwargs):
        self._ask("showwarning", title, message, **kwargs)
        return "ok"

    def showerror(self, title, message, **kwargs):
        self._ask("showerror", title, message, **kwargs)
        return "ok"


def make_window(monkeypatch, detector, results, selected, *answers):
    """An uninitialised CIEMainWindow with only what the action touches."""
    dialogs = StubDialogs(*answers)
    monkeypatch.setattr(gui, "messagebox", dialogs)

    window = object.__new__(gui.CIEMainWindow)
    window.detector = detector
    window.current_results = list(results)
    window.refresh_count = 0
    window.status_messages = []

    def refresh_views() -> None:
        window.refresh_count += 1

    def set_status(message: str) -> None:
        window.status_messages.append(message)

    window.refresh_views = refresh_views  # type: ignore[method-assign]
    window._set_status = set_status  # type: ignore[method-assign]
    window.get_selected_files = lambda: list(selected)  # type: ignore[method-assign]
    return window, dialogs


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def test_summary_reports_every_category():
    outcomes = [
        RebaselineOutcome("/data/a.bin", "rebaselined", previous_status="CORRUPTED_CHECKSUM"),
        RebaselineOutcome("/data/b.bin", "refused", reason="word/document.xml is not readable XML"),
        RebaselineOutcome("/data/gone.bin", "missing", reason="path does not exist"),
    ]

    text = gui.format_rebaseline_summary(outcomes)

    assert "Accepted as the new baseline (1)" in text
    assert "/data/a.bin  (was CORRUPTED_CHECKSUM)" in text
    assert "Refused - still failing format validation (1)" in text
    assert "word/document.xml is not readable XML" in text
    assert "Not found (1)" in text
    assert "Forced acceptance" not in text


def test_summary_says_nothing_to_do_for_an_empty_result():
    assert "Nothing to do" in gui.format_rebaseline_summary([])


def test_summary_discloses_forced_acceptance_and_dry_runs():
    outcomes = [RebaselineOutcome("/data/a.bin", "rebaselined")]

    text = gui.format_rebaseline_summary(outcomes, forced=True, dry_run=True)

    assert "Forced acceptance was used" in text
    assert "the next scan will flag them again" in text
    assert "Dry run" in text


def test_summary_caps_long_lists():
    outcomes = [RebaselineOutcome(f"/data/f{index:03d}.bin", "rebaselined") for index in range(40)]

    text = gui.format_rebaseline_summary(outcomes)

    assert "Accepted as the new baseline (40)" in text
    assert "... and 30 more" in text
    assert text.count("/data/f") == 10


def test_merge_replaces_accepted_results_and_drops_missing_ones(tmp_path):
    target = tmp_path / "accepted.bin"
    target.write_bytes(b"payload")
    gone = tmp_path / "gone.bin"
    untouched = tmp_path / "other.bin"

    results = [
        FakeResult(str(target)),
        FakeResult(str(gone)),
        FakeResult(str(untouched)),
    ]
    refreshed = {str(target): FakeResult(str(target), FileStatus.VALID)}

    merged = gui.merge_rebaselined_results(results, refreshed, {str(gone)})

    assert [result.file_path for result in merged] == [str(target), str(untouched)]
    assert merged[0].status is FileStatus.VALID
    assert merged[1].status is FileStatus.CORRUPTED_FORMAT


def test_merge_matches_paths_that_merely_spell_the_same_file(tmp_path):
    """The engine reports resolved paths; the table may hold unresolved ones."""
    nested = tmp_path / "sub" / ".." / "same.bin"
    (tmp_path / "same.bin").write_bytes(b"x")

    merged = gui.merge_rebaselined_results(
        [FakeResult(str(nested))],
        {str(tmp_path / "same.bin"): FakeResult(str(tmp_path / "same.bin"), FileStatus.VALID)},
    )

    assert merged[0].status is FileStatus.VALID


# ---------------------------------------------------------------------------
# the action itself
# ---------------------------------------------------------------------------

def test_accepting_a_reviewed_file_updates_the_table(monkeypatch, tmp_path):
    target = tmp_path / "reviewed.bin"
    target.write_bytes(b"reviewed payload")
    other = tmp_path / "still-broken.bin"
    detector = StubDetector()
    window, dialogs = make_window(
        monkeypatch,
        detector,
        [FakeResult(str(target)), FakeResult(str(other))],
        [str(target)],
        True,  # the confirmation
    )

    window.rebaseline_selected()

    assert len(detector.rebaseline_calls) == 1
    assert detector.rebaseline_calls[0]["force"] is False
    assert detector.rebaseline_calls[0]["dry_run"] is False
    assert detector.rebaseline_calls[0]["recursive"] is False
    assert detector.analyzed == [str(target)]
    assert window.refresh_count == 1
    assert window.status_messages[-1] == "Rebaselined 1 file(s)."

    by_path = {result.file_path: result for result in window.current_results}
    assert by_path[str(target)].status is FileStatus.VALID
    assert by_path[str(other)].is_corrupted  # untouched
    assert dialogs.calls[0][0] == "askyesno"
    assert "Accept today's content" in dialogs.calls[0][2]
    assert dialogs.calls[-1][0] == "showinfo"


def test_the_action_does_nothing_when_the_user_cancels(monkeypatch, tmp_path):
    target = tmp_path / "reviewed.bin"
    target.write_bytes(b"payload")
    detector = StubDetector()
    window, _dialogs = make_window(
        monkeypatch, detector, [FakeResult(str(target))], [str(target)], False
    )

    window.rebaseline_selected()

    assert detector.rebaseline_calls == []
    assert detector.analyzed == []
    assert window.refresh_count == 0
    assert window.current_results[0].is_corrupted


def test_an_empty_selection_warns_instead_of_asking(monkeypatch):
    detector = StubDetector()
    window, dialogs = make_window(monkeypatch, detector, [], [])

    window.rebaseline_selected()

    assert detector.rebaseline_calls == []
    assert dialogs.calls[0][0] == "showwarning"


def test_a_broken_file_needs_a_second_confirmation_to_force(monkeypatch, tmp_path):
    target = tmp_path / "damaged.bin"
    target.write_bytes(b"damaged")
    detector = StubDetector(refuse_first=True)
    window, dialogs = make_window(
        monkeypatch,
        detector,
        [FakeResult(str(target))],
        [str(target)],
        True,   # accept the re-baseline…
        True,   # …then force it past the refusal
    )

    window.rebaseline_selected()

    assert [call["force"] for call in detector.rebaseline_calls] == [False, True]
    kinds = [kind for kind, _title, _message in dialogs.calls]
    assert kinds[0] == "askyesno" and kinds[1] == "askyesno"
    assert "still fail format validation" in dialogs.calls[1][2]
    assert "Forced acceptance" in dialogs.calls[-1][2]
    assert window.current_results[0].status is FileStatus.VALID


def test_declining_the_force_leaves_the_finding_in_place(monkeypatch, tmp_path):
    target = tmp_path / "damaged.bin"
    target.write_bytes(b"damaged")
    detector = StubDetector(refuse_first=True)
    window, dialogs = make_window(
        monkeypatch,
        detector,
        [FakeResult(str(target))],
        [str(target)],
        True,    # accept the re-baseline
        False,   # refuse to force it
    )

    window.rebaseline_selected()

    assert len(detector.rebaseline_calls) == 1
    assert detector.analyzed == []
    assert window.current_results[0].is_corrupted
    assert "Refused - still failing format validation" in dialogs.calls[-1][2]


def test_a_missing_file_is_dropped_from_the_table(monkeypatch, tmp_path):
    gone = tmp_path / "gone.bin"

    class MissingDetector(StubDetector):
        def rebaseline(self, targets, **kwargs):
            self.rebaseline_calls.append({"targets": tuple(targets), "force": False})
            return tuple(RebaselineOutcome(str(path), "missing", reason="path does not exist")
                         for path in targets)

    detector = MissingDetector()
    window, _dialogs = make_window(
        monkeypatch, detector, [FakeResult(str(gone))], [str(gone)], True
    )

    window.rebaseline_selected()

    assert window.current_results == []
    assert detector.analyzed == []


def test_the_action_works_against_the_real_engine(monkeypatch, tmp_path):
    """The stub tests cannot catch an API mismatch; this one drives the engine.

    Scan a file, change its content behind the engine's back (structure still
    fine, checksum different), then use the window action and prove the stored
    baseline was really replaced: the file stops being reported as corrupted.
    """
    from src.python.core_analyzer import AnalyzerConfig, CorruptionDetector

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    target = data_dir / "notes.txt"
    target.write_text("first version\n")

    detector = CorruptionDetector(
        AnalyzerConfig(db_path=str(tmp_path / "cie.db"), quarantine_dir=str(tmp_path / "q"))
    )
    results = list(detector.scan_directory(data_dir))
    assert results and results[0].is_corrupted is False  # baseline established

    target.write_text("second version - different bytes\n")
    rescanned = list(detector.scan_directory(data_dir))
    assert rescanned[0].is_corrupted, "the changed file should now be flagged"

    window, dialogs = make_window(
        monkeypatch, detector, rescanned, [str(target)], True
    )
    window.rebaseline_selected()

    assert detector._engine is not None  # sanity: the real facade was used
    assert "Accepted as the new baseline (1)" in dialogs.calls[-1][2]
    assert window.current_results[0].is_corrupted is False
    assert window.status_messages[-1] == "Rebaselined 1 file(s)."

    # and the engine agrees on the next scan, too
    final = list(detector.scan_directory(data_dir))
    assert final[0].is_corrupted is False


# ---------------------------------------------------------------------------
# wiring (only when a display exists; CI is headless)
# ---------------------------------------------------------------------------

def _display_available() -> bool:
    try:
        import tkinter as tk

        root = tk.Tk()
        root.destroy()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _display_available(), reason="no display available (headless CI)")
def test_context_menu_offers_the_action():  # pragma: no cover - needs a display
    import tkinter as tk

    root = tk.Tk()
    try:
        window = object.__new__(gui.CIEMainWindow)
        window.root = root
        window._setup_context_menu()

        labels = []
        last = window.context_menu.index("end")
        for index in range(0 if last is None else last + 1):
            if window.context_menu.type(index) == "separator":
                continue
            labels.append(window.context_menu.entrycget(index, "label"))

        assert any(label.startswith("Rebaseline") for label in labels)
        assert "Quarantine" in labels and "Delete" in labels
    finally:
        root.destroy()
