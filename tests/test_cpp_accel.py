"""The C++ core must be *bound*, not decorative.

The audit found that `src/cpp/file_analyzer.cpp` compiled but was never called
by the Python application (0 call sites): every scan hashed and histogrammed
its bytes in Python at ~20 MB/s while the C++ implementation of the same work
sat unused.

These tests pin down the binding: the shared library exposes a versioned C ABI,
produces byte-identical results to the pure-Python implementation, is what the
engine actually uses when it is present, and disappears silently (with correct
results) when it is not.
"""

from __future__ import annotations

import hashlib
import math
import os
import random
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src" / "python"))

import cpp_accel  # noqa: E402
from src.python.core_analyzer import (  # noqa: E402
    AdvancedFileMetricsCalculator,
    AnalyzerConfig,
    CorruptionDetector,
    FileStatus,
)

BUILT = cpp_accel.available()
requires_library = pytest.mark.skipif(
    not BUILT, reason="C++ acceleration library not built - run `make cpp`"
)


# ---------------------------------------------------------------------------
# the library itself
# ---------------------------------------------------------------------------

def test_module_declares_the_api_version_it_expects():
    assert cpp_accel.EXPECTED_API_VERSION >= 1
    assert cpp_accel.LIBRARY_BASENAMES


@requires_library
def test_library_self_test_passes():
    assert cpp_accel.selftest() == 0


@requires_library
def test_library_path_is_reported():
    path = cpp_accel.library_path()
    assert path is not None and path.is_file()


@pytest.mark.parametrize("size", [0, 1, 63, 64, 65, 1023, 1024, 65536, 262144, 262145, 300000])
@requires_library
def test_digest_and_entropy_match_python(size):
    random.seed(size)
    block = bytes(random.getrandbits(8) for _ in range(4096))
    data = (block * (size // len(block) + 1))[:size]

    stats = cpp_accel.hash_bytes(data, chunk_size=4096)

    assert stats.size_bytes == len(data)
    assert stats.sha256 == hashlib.sha256(data).hexdigest()

    expected_entropy = 0.0
    if data:
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        for count in counts:
            if count:
                p = count / len(data)
                expected_entropy -= p * math.log2(p)
    assert stats.shannon_entropy == pytest.approx(expected_entropy, abs=1e-12)


@requires_library
def test_chunk_boundaries_do_not_change_the_result():
    data = os.urandom(200_000)
    one_shot = cpp_accel.hash_bytes(data, chunk_size=len(data))
    many = cpp_accel.hash_bytes(data, chunk_size=997)
    assert one_shot.sha256 == many.sha256
    assert one_shot.shannon_entropy == pytest.approx(many.shannon_entropy, abs=1e-12)


# ---------------------------------------------------------------------------
# the engine must actually use it
# ---------------------------------------------------------------------------

@requires_library
def test_engine_selects_the_cpp_backend(tmp_path):
    calculator = AdvancedFileMetricsCalculator(AnalyzerConfig())
    assert calculator.backend == "cpp"

    path = tmp_path / "file.bin"
    path.write_bytes(os.urandom(100_000))
    assert calculator.calculate(path).checksum == hashlib.sha256(path.read_bytes()).hexdigest()


@requires_library
@pytest.mark.parametrize("name", ["real.png", "real.docx", "real.xlsx"])
def test_engine_metrics_are_identical_with_and_without_acceleration(tmp_path, name):
    builder = {
        "real.png": lambda p: p.write_bytes(_png_bytes()),
        "real.docx": lambda p: _docx(p),
        "real.xlsx": lambda p: _xlsx(p),
    }[name]
    path = tmp_path / name
    builder(path)

    with_cpp = AdvancedFileMetricsCalculator(AnalyzerConfig(use_cpp_accel=True)).calculate(path)
    without = AdvancedFileMetricsCalculator(AnalyzerConfig(use_cpp_accel=False)).calculate(path)

    assert with_cpp.size_bytes == without.size_bytes
    assert with_cpp.checksum == without.checksum
    assert with_cpp.shannon_entropy == pytest.approx(without.shannon_entropy, abs=1e-12)
    assert with_cpp.checksum == hashlib.sha256(path.read_bytes()).hexdigest()


@requires_library
def test_scan_results_do_not_depend_on_the_backend(tmp_path):
    root = tmp_path / "corpus"
    root.mkdir()
    (root / "notes.txt").write_text("ordinary text\n" * 50)
    (root / "image.png").write_bytes(_png_bytes())
    (root / "broken.png").write_bytes(b"this is not a png")

    def scan(accel: bool):
        detector = CorruptionDetector(
            AnalyzerConfig(
                db_path=str(tmp_path / f"db-{accel}.sqlite"),
                quarantine_dir=str(tmp_path / "q"),
                use_cpp_accel=accel,
            )
        )
        return {
            result.path_obj.name: (
                result.status.name,
                result.is_corrupted,
                result.checksum,
                round(result.shannon_entropy, 12),
            )
            for result in detector.scan_directory(root)
        }

    assert scan(True) == scan(False)


@requires_library
def test_cancellation_still_works_with_the_cpp_backend(tmp_path):
    import threading

    calculator = AdvancedFileMetricsCalculator(AnalyzerConfig(use_cpp_accel=True))
    path = tmp_path / "big.bin"
    path.write_bytes(os.urandom(4_000_000))

    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(Exception) as excinfo:
        calculator.calculate(path, cancel_event=cancelled)
    assert "cancel" in str(excinfo.value).lower()


# ---------------------------------------------------------------------------
# and it must degrade gracefully
# ---------------------------------------------------------------------------

def test_engine_falls_back_when_the_library_is_missing(monkeypatch, tmp_path):
    """No library (or an unusable one) must never break a scan."""
    # The engine loads its own instance of the module by file path
    # (core_analyzer.load_sibling_module), so patch that one.
    from src.python import core_analyzer

    engine_module = core_analyzer.load_sibling_module("cpp_accel")
    monkeypatch.setattr(engine_module, "_LIBRARY", None)
    monkeypatch.setattr(engine_module, "_LIBRARY_LOADED", True)
    monkeypatch.setattr(engine_module, "_LIBRARY_ERROR", "disabled for this test")
    monkeypatch.setattr(cpp_accel, "_LIBRARY", None)
    monkeypatch.setattr(cpp_accel, "_LIBRARY_LOADED", True)
    monkeypatch.setattr(cpp_accel, "_LIBRARY_ERROR", "disabled for this test")

    path = tmp_path / "file.bin"
    path.write_bytes(os.urandom(50_000))

    calculator = AdvancedFileMetricsCalculator(AnalyzerConfig())
    assert calculator.backend == "python"

    metrics = calculator.calculate(path)
    assert metrics.checksum == hashlib.sha256(path.read_bytes()).hexdigest()
    assert metrics.size_bytes == 50_000


def test_acceleration_can_be_switched_off(tmp_path):
    calculator = AdvancedFileMetricsCalculator(AnalyzerConfig(use_cpp_accel=False))
    assert calculator.backend == "python"


def test_non_sha256_algorithms_stay_in_python():
    calculator = AdvancedFileMetricsCalculator(
        AnalyzerConfig(hash_algorithm="sha512", use_cpp_accel=True)
    )
    assert calculator.backend == "python"


def test_library_status_reports_the_cpp_core(tmp_path):
    detector = CorruptionDetector(
        AnalyzerConfig(db_path=str(tmp_path / "db.sqlite"), quarantine_dir=str(tmp_path / "q"))
    )
    status = detector.get_library_status()
    key = "C++ acceleration (hashes/metrics)"
    assert key in status
    assert status[key] is BUILT


def test_scan_of_a_corrupt_file_is_still_detected_with_the_cpp_backend(tmp_path):
    root = tmp_path / "scan"
    root.mkdir()
    path = root / "photo.png"
    data = _png_bytes()
    path.write_bytes(data[: len(data) // 2])

    detector = CorruptionDetector(
        AnalyzerConfig(
            db_path=str(tmp_path / "db.sqlite"),
            quarantine_dir=str(tmp_path / "q"),
            use_cpp_accel=True,
        )
    )
    result = detector.analyze_file(path)
    assert result.status is FileStatus.CORRUPTED_FORMAT
    assert result.is_corrupted is True


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _png_bytes() -> bytes:
    try:
        import io

        from PIL import Image

        buffer = io.BytesIO()
        Image.new("RGB", (24, 24), (12, 34, 56)).save(buffer, format="PNG")
        return buffer.getvalue()
    except ImportError:  # pragma: no cover - Pillow is in requirements
        from tests.conftest import make_real_png

        return make_real_png()


def _docx(path: Path) -> None:
    from tests.conftest import make_real_docx

    make_real_docx(path)


def _xlsx(path: Path) -> None:
    openpyxl = pytest.importorskip("openpyxl")
    workbook = openpyxl.Workbook()
    workbook.active["A1"] = "accel"
    workbook.save(path)
