"""Tests for cie_math (renamed from math.py, which shadowed the stdlib)."""

from __future__ import annotations

import hashlib
import math as stdlib_math
import os

import pytest

from src.python import cie_math
from src.python.cie_math import MathAnalyzer, MathematicalProcessor


def test_module_does_not_shadow_stdlib_math():
    assert cie_math.__file__.endswith("cie_math.py")
    assert stdlib_math.log2(8) == 3.0
    assert stdlib_math.__file__ is not None
    assert not stdlib_math.__file__.endswith("src/python/math.py")


@pytest.fixture
def analyzer():
    return MathAnalyzer(sample_size=4096, chunk_size=1024)


def test_entropy_bounds(analyzer):
    assert analyzer.calculate_entropy(b"\x00" * 512) == 0.0
    assert analyzer.calculate_entropy(bytes(range(256)) * 8) > 7.9
    assert analyzer.calculate_entropy(b"") == 0.0


def test_entropy_matches_reference(analyzer):
    data = bytes(range(256))
    expected = -sum(
        (data.count(byte) / len(data)) * stdlib_math.log2(data.count(byte) / len(data))
        for byte in set(data)
    )
    assert analyzer.calculate_entropy(data) == pytest.approx(expected, abs=1e-9)


def test_variance(analyzer):
    assert analyzer.calculate_variance(b"") == 0.0
    assert analyzer.calculate_variance(b"\x00" * 64) == 0.0
    assert analyzer.calculate_variance(bytes(range(256))) > 0


def test_chi_square_uniform(analyzer):
    uniform = bytes(range(256)) * 4
    skewed = b"\x00" * 1024
    assert analyzer.calculate_chi_square_uniform(uniform) < analyzer.calculate_chi_square_uniform(skewed)


def test_chi_square_length_mismatch_raises(analyzer):
    with pytest.raises(ValueError):
        analyzer.chi_square_test([1, 2], [1, 2, 3])


def test_repeating_pattern_detection(analyzer):
    result = analyzer.detect_repeating_patterns(b"ABCD" * 256)
    assert result.has_repeating_pattern is True
    assert result.pattern_length == 4

    assert analyzer.detect_repeating_patterns(os.urandom(1024)).has_repeating_pattern is False


def test_byte_statistics(analyzer):
    stats = analyzer.calculate_byte_statistics(b"\x00" * 100 + b"A" * 100)
    assert stats.total_bytes == 200
    assert stats.null_ratio == pytest.approx(0.5)
    assert stats.printable_ratio == pytest.approx(0.5)


def test_empty_file_flagged(analyzer, tmp_path):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    result = analyzer.analyze_file(path)
    assert result.is_corrupted is True
    assert result.error_message == "empty file"


def test_null_file_flagged(analyzer, tmp_path):
    path = tmp_path / "nulls.bin"
    path.write_bytes(b"\x00" * 4096)
    assert analyzer.analyze_file(path).is_corrupted is True


def test_text_file_with_binary_content_flagged(analyzer, tmp_path):
    path = tmp_path / "bad.txt"
    path.write_bytes(b"\x00\xff\x80" * 400)
    assert analyzer.analyze_file(path).is_corrupted is True


def test_missing_file_reported(analyzer, tmp_path):
    result = analyzer.analyze_file(tmp_path / "nope.bin")
    assert result.is_corrupted is True
    assert result.error_message == "file not found"


def test_checksum_and_size_cover_the_whole_file(analyzer, tmp_path):
    data = (b"A" * 5000) + (b"B" * 5000)
    path = tmp_path / "full.bin"
    path.write_bytes(data)
    result = analyzer.analyze_file(path)
    assert result.checksum == hashlib.sha256(data).hexdigest()
    assert result.file_size == len(data)


def test_processor_adapter(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"hello world")
    result = MathematicalProcessor(sample_size=512, chunk_size=128).process(path)
    assert result.file_path == str(path.resolve())
    assert result.processing_time_seconds >= 0


def test_numpy_and_python_paths_agree():
    data = os.urandom(2048)
    with_numpy = MathAnalyzer(sample_size=2048, use_numpy=True)
    without = MathAnalyzer(sample_size=2048, use_numpy=False)
    assert with_numpy.calculate_entropy(data) == pytest.approx(without.calculate_entropy(data), abs=1e-9)
    assert with_numpy.calculate_variance(data) == pytest.approx(without.calculate_variance(data), rel=1e-6)
