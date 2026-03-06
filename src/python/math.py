#!/usr/bin/env python3
"""
Mathematical analysis module for CIE.

This module provides:
- Streaming Shannon entropy calculation
- Variance and byte-distribution analysis
- Repeating-pattern detection on bounded samples
- Chi-square randomness testing
- Optional NumPy acceleration
- Processor integration for modular scanning
"""

from __future__ import annotations

import hashlib
import logging
import math
import tempfile
import time
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:  # pragma: no cover
    np = None  # type: ignore[assignment]
    NUMPY_AVAILABLE = False

LOGGER = logging.getLogger(__name__)

TEXT_EXTENSIONS = frozenset({
    ".txt",
    ".log",
    ".csv",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".conf",
    ".toml",
    ".py",
    ".js",
    ".html",
    ".css",
    ".md",
    ".rst",
})


@dataclass(frozen=True, slots=True)
class ByteStatistics:
    total_bytes: int = 0
    entropy: float = 0.0
    variance: float = 0.0
    null_ratio: float = 0.0
    unique_ratio: float = 0.0
    high_byte_ratio: float = 0.0
    low_byte_ratio: float = 0.0
    printable_ratio: float = 0.0
    chi_square_uniform: float = 0.0
    max_byte_run: int = 0


@dataclass(frozen=True, slots=True)
class PatternDetectionResult:
    has_repeating_pattern: bool = False
    pattern_length: int = 0
    repetitions: int = 0
    coverage_ratio: float = 0.0


@dataclass(frozen=True, slots=True)
class MathAnalysisResult:
    file_path: str
    file_size: int
    checksum: str
    is_corrupted: bool
    math_score: float
    confidence: float
    processing_time_seconds: float
    error_message: str | None = None

    entropy: float = 0.0
    variance: float = 0.0
    null_ratio: float = 0.0
    unique_ratio: float = 0.0
    high_byte_ratio: float = 0.0
    low_byte_ratio: float = 0.0
    printable_ratio: float = 0.0
    chi_square_uniform: float = 0.0
    has_repeating_pattern: bool = False
    pattern_length: int = 0
    max_byte_run: int = 0
    sample_size_used: int = 0

    @property
    def path(self) -> Path:
        return Path(self.file_path)


@dataclass(slots=True)
class _MetricAccumulator:
    sample_limit: int
    use_numpy: bool
    hasher: Any = field(default_factory=hashlib.sha256)
    total_bytes: int = 0
    sum_values: int = 0
    sum_squares: int = 0
    null_bytes: int = 0
    high_bytes: int = 0
    low_bytes: int = 0
    printable_bytes: int = 0
    max_byte_run: int = 0
    sample: bytearray = field(default_factory=bytearray)
    _last_byte: int | None = None
    _current_run: int = 0

    def __post_init__(self) -> None:
        if self.use_numpy:
            self.histogram = np.zeros(256, dtype=np.uint64)
        else:
            self.histogram = [0] * 256

    def update(self, chunk: bytes) -> None:
        if not chunk:
            return

        self.hasher.update(chunk)

        if len(self.sample) < self.sample_limit:
            remaining = self.sample_limit - len(self.sample)
            self.sample.extend(chunk[:remaining])

        if self.use_numpy:
            self._update_numpy(chunk)
        else:
            self._update_python(chunk)

        for byte_value in chunk:
            if self._last_byte is None or byte_value != self._last_byte:
                self._last_byte = byte_value
                self._current_run = 1
            else:
                self._current_run += 1

            if self._current_run > self.max_byte_run:
                self.max_byte_run = self._current_run

    def _update_numpy(self, chunk: bytes) -> None:
        assert np is not None

        view = np.frombuffer(chunk, dtype=np.uint8)
        self.histogram += np.bincount(view, minlength=256)

        self.total_bytes += int(view.size)
        self.sum_values += int(view.sum(dtype=np.uint64))
        self.sum_squares += int(np.multiply(view, view, dtype=np.uint64).sum(dtype=np.uint64))
        self.null_bytes += int(np.count_nonzero(view == 0))
        self.high_bytes += int(np.count_nonzero(view >= 128))
        self.low_bytes += int(np.count_nonzero((view >= 1) & (view <= 31)))

        printable_mask = ((view >= 32) & (view <= 126)) | (view == 9) | (view == 10) | (view == 13)
        self.printable_bytes += int(np.count_nonzero(printable_mask))

    def _update_python(self, chunk: bytes) -> None:
        for byte_value in chunk:
            self.histogram[byte_value] += 1
            self.total_bytes += 1
            self.sum_values += byte_value
            self.sum_squares += byte_value * byte_value

            if byte_value == 0:
                self.null_bytes += 1
            if byte_value >= 128:
                self.high_bytes += 1
            if 1 <= byte_value <= 31:
                self.low_bytes += 1
            if byte_value in (9, 10, 13) or 32 <= byte_value <= 126:
                self.printable_bytes += 1

    def checksum(self) -> str:
        return self.hasher.hexdigest()

    def sample_bytes(self) -> bytes:
        return bytes(self.sample)


class MathAnalyzer:
    """Streaming mathematical analyzer for file corruption heuristics."""

    def __init__(
        self,
        *,
        sample_size: int = 16 * 1024,
        chunk_size: int = 256 * 1024,
        score_threshold: float = 0.55,
        low_entropy_threshold: float = 1.0,
        high_null_threshold: float = 0.80,
        low_unique_threshold: float = 0.10,
        low_variance_threshold: float = 10.0,
        text_high_byte_threshold: float = 0.30,
        text_low_control_threshold: float = 0.10,
        min_pattern_length: int = 1,
        max_pattern_length: int = 32,
        min_pattern_repetitions: int = 3,
        min_pattern_coverage_ratio: float = 0.60,
        use_numpy: bool | None = None,
    ):
        self.sample_size = max(256, sample_size)
        self.chunk_size = max(1, chunk_size)
        self.score_threshold = max(0.0, min(1.0, score_threshold))
        self.low_entropy_threshold = low_entropy_threshold
        self.high_null_threshold = max(0.0, min(1.0, high_null_threshold))
        self.low_unique_threshold = max(0.0, min(1.0, low_unique_threshold))
        self.low_variance_threshold = max(0.0, low_variance_threshold)
        self.text_high_byte_threshold = max(0.0, min(1.0, text_high_byte_threshold))
        self.text_low_control_threshold = max(0.0, min(1.0, text_low_control_threshold))
        self.min_pattern_length = max(1, min_pattern_length)
        self.max_pattern_length = max(self.min_pattern_length, max_pattern_length)
        self.min_pattern_repetitions = max(2, min_pattern_repetitions)
        self.min_pattern_coverage_ratio = max(0.0, min(1.0, min_pattern_coverage_ratio))
        self.use_numpy = NUMPY_AVAILABLE if use_numpy is None else bool(use_numpy and NUMPY_AVAILABLE)

    def calculate_entropy(self, data: bytes) -> float:
        accumulator = _MetricAccumulator(sample_limit=len(data), use_numpy=self.use_numpy)
        accumulator.update(data)
        return self._entropy_from_histogram(accumulator.histogram, accumulator.total_bytes)

    def calculate_variance(self, data: bytes) -> float:
        if not data:
            return 0.0

        if self.use_numpy:
            assert np is not None
            view = np.frombuffer(data, dtype=np.uint8)
            return float(np.var(view, dtype=np.float64))

        total = len(data)
        sum_values = sum(data)
        sum_squares = sum(byte_value * byte_value for byte_value in data)
        return self._variance_from_moments(sum_values, sum_squares, total)

    def calculate_byte_statistics(self, data: bytes) -> ByteStatistics:
        accumulator = _MetricAccumulator(sample_limit=len(data), use_numpy=self.use_numpy)
        accumulator.update(data)
        return self._statistics_from_accumulator(accumulator)

    def chi_square_test(self, observed: Sequence[int], expected: Sequence[int]) -> float:
        if len(observed) != len(expected):
            raise ValueError("observed and expected must have the same length")

        if self.use_numpy:
            assert np is not None
            observed_array = np.asarray(observed, dtype=np.float64)
            expected_array = np.asarray(expected, dtype=np.float64)
            mask = expected_array > 0
            if not np.any(mask):
                return 0.0
            diff = observed_array[mask] - expected_array[mask]
            return float(np.sum((diff * diff) / expected_array[mask]))

        score = 0.0
        for observed_value, expected_value in zip(observed, expected):
            if expected_value > 0:
                delta = observed_value - expected_value
                score += (delta * delta) / expected_value
        return score

    def calculate_chi_square_uniform(self, data: bytes) -> float:
        if not data:
            return 0.0

        accumulator = _MetricAccumulator(sample_limit=len(data), use_numpy=self.use_numpy)
        accumulator.update(data)
        return self._chi_square_uniform_from_histogram(accumulator.histogram, accumulator.total_bytes)

    def detect_repeating_patterns(self, data: bytes) -> PatternDetectionResult:
        if len(data) < self.min_pattern_length * self.min_pattern_repetitions:
            return PatternDetectionResult()

        max_length = min(self.max_pattern_length, len(data) // self.min_pattern_repetitions)
        for pattern_length in range(self.min_pattern_length, max_length + 1):
            pattern = data[:pattern_length]
            repetitions = 1
            index = pattern_length

            while index + pattern_length <= len(data) and data[index:index + pattern_length] == pattern:
                repetitions += 1
                index += pattern_length

            coverage_ratio = (repetitions * pattern_length) / len(data)
            if (
                repetitions >= self.min_pattern_repetitions
                and coverage_ratio >= self.min_pattern_coverage_ratio
            ):
                return PatternDetectionResult(
                    has_repeating_pattern=True,
                    pattern_length=pattern_length,
                    repetitions=repetitions,
                    coverage_ratio=coverage_ratio,
                )

        return PatternDetectionResult()

    def analyze_bytes(self, data: bytes, *, file_name: str = "<memory>") -> MathAnalysisResult:
        started = time.perf_counter()

        accumulator = _MetricAccumulator(sample_limit=self.sample_size, use_numpy=self.use_numpy)
        accumulator.update(data)

        statistics = self._statistics_from_accumulator(accumulator)
        pattern = self.detect_repeating_patterns(accumulator.sample_bytes())
        math_score, reasons = self._score(file_name, statistics, pattern)

        return MathAnalysisResult(
            file_path=file_name,
            file_size=statistics.total_bytes,
            checksum=accumulator.checksum(),
            is_corrupted=math_score >= self.score_threshold,
            math_score=math_score,
            confidence=self._confidence(math_score),
            processing_time_seconds=time.perf_counter() - started,
            error_message="; ".join(reasons) if reasons else None,
            entropy=statistics.entropy,
            variance=statistics.variance,
            null_ratio=statistics.null_ratio,
            unique_ratio=statistics.unique_ratio,
            high_byte_ratio=statistics.high_byte_ratio,
            low_byte_ratio=statistics.low_byte_ratio,
            printable_ratio=statistics.printable_ratio,
            chi_square_uniform=statistics.chi_square_uniform,
            has_repeating_pattern=pattern.has_repeating_pattern,
            pattern_length=pattern.pattern_length,
            max_byte_run=statistics.max_byte_run,
            sample_size_used=len(accumulator.sample_bytes()),
        )

    def analyze_file(self, file_path: Path | str) -> MathAnalysisResult:
        path = Path(file_path).expanduser().resolve()
        started = time.perf_counter()

        try:
            if not path.exists():
                return MathAnalysisResult(
                    file_path=str(path),
                    file_size=0,
                    checksum="",
                    is_corrupted=True,
                    math_score=1.0,
                    confidence=1.0,
                    processing_time_seconds=time.perf_counter() - started,
                    error_message="file not found",
                )

            if not path.is_file():
                return MathAnalysisResult(
                    file_path=str(path),
                    file_size=0,
                    checksum="",
                    is_corrupted=True,
                    math_score=1.0,
                    confidence=1.0,
                    processing_time_seconds=time.perf_counter() - started,
                    error_message="target is not a regular file",
                )

            accumulator = _MetricAccumulator(sample_limit=self.sample_size, use_numpy=self.use_numpy)

            with path.open("rb") as handle:
                while True:
                    chunk = handle.read(self.chunk_size)
                    if not chunk:
                        break
                    accumulator.update(chunk)

            statistics = self._statistics_from_accumulator(accumulator)
            pattern = self.detect_repeating_patterns(accumulator.sample_bytes())
            math_score, reasons = self._score(path.name, statistics, pattern)

            return MathAnalysisResult(
                file_path=str(path),
                file_size=statistics.total_bytes,
                checksum=accumulator.checksum(),
                is_corrupted=math_score >= self.score_threshold,
                math_score=math_score,
                confidence=self._confidence(math_score),
                processing_time_seconds=time.perf_counter() - started,
                error_message="; ".join(reasons) if reasons else None,
                entropy=statistics.entropy,
                variance=statistics.variance,
                null_ratio=statistics.null_ratio,
                unique_ratio=statistics.unique_ratio,
                high_byte_ratio=statistics.high_byte_ratio,
                low_byte_ratio=statistics.low_byte_ratio,
                printable_ratio=statistics.printable_ratio,
                chi_square_uniform=statistics.chi_square_uniform,
                has_repeating_pattern=pattern.has_repeating_pattern,
                pattern_length=pattern.pattern_length,
                max_byte_run=statistics.max_byte_run,
                sample_size_used=len(accumulator.sample_bytes()),
            )

        except OSError as exc:
            return MathAnalysisResult(
                file_path=str(path),
                file_size=0,
                checksum="",
                is_corrupted=True,
                math_score=1.0,
                confidence=0.0,
                processing_time_seconds=time.perf_counter() - started,
                error_message=f"file access failed: {exc}",
            )
        except Exception:
            LOGGER.exception("unexpected mathematical analysis failure for %s", path)
            return MathAnalysisResult(
                file_path=str(path),
                file_size=0,
                checksum="",
                is_corrupted=True,
                math_score=1.0,
                confidence=0.0,
                processing_time_seconds=time.perf_counter() - started,
                error_message="internal mathematical analysis fault",
            )

    def _statistics_from_accumulator(self, accumulator: _MetricAccumulator) -> ByteStatistics:
        total = accumulator.total_bytes
        if total == 0:
            return ByteStatistics()

        unique_count = self._unique_count(accumulator.histogram)

        return ByteStatistics(
            total_bytes=total,
            entropy=self._entropy_from_histogram(accumulator.histogram, total),
            variance=self._variance_from_moments(accumulator.sum_values, accumulator.sum_squares, total),
            null_ratio=accumulator.null_bytes / total,
            unique_ratio=unique_count / min(256, total),
            high_byte_ratio=accumulator.high_bytes / total,
            low_byte_ratio=accumulator.low_bytes / total,
            printable_ratio=accumulator.printable_bytes / total,
            chi_square_uniform=self._chi_square_uniform_from_histogram(accumulator.histogram, total),
            max_byte_run=accumulator.max_byte_run,
        )

    def _entropy_from_histogram(self, histogram: Any, total: int) -> float:
        if total == 0:
            return 0.0

        if self.use_numpy:
            assert np is not None
            histogram_array = histogram.astype(np.float64, copy=False)
            non_zero = histogram_array[histogram_array > 0]
            probabilities = non_zero / float(total)
            return float(-np.sum(probabilities * np.log2(probabilities)))

        entropy = 0.0
        for count in histogram:
            if count > 0:
                probability = count / total
                entropy -= probability * math.log2(probability)
        return entropy

    def _variance_from_moments(self, sum_values: int, sum_squares: int, total: int) -> float:
        if total <= 1:
            return 0.0

        mean = sum_values / total
        variance = (sum_squares / total) - (mean * mean)
        if variance < 0.0 and variance > -1e-12:
            return 0.0
        return max(0.0, variance)

    def _chi_square_uniform_from_histogram(self, histogram: Any, total: int) -> float:
        if total == 0:
            return 0.0

        expected = total / 256.0

        if self.use_numpy:
            assert np is not None
            histogram_array = histogram.astype(np.float64, copy=False)
            diff = histogram_array - expected
            return float(np.sum((diff * diff) / expected))

        score = 0.0
        for count in histogram:
            delta = count - expected
            score += (delta * delta) / expected
        return score

    def _unique_count(self, histogram: Any) -> int:
        if self.use_numpy:
            assert np is not None
            return int(np.count_nonzero(histogram))
        return sum(1 for count in histogram if count > 0)

    def _score(
        self,
        file_name: str,
        statistics: ByteStatistics,
        pattern: PatternDetectionResult,
    ) -> tuple[float, list[str]]:
        if statistics.total_bytes == 0:
            return 1.0, ["empty file"]

        score = 0.0
        reasons: list[str] = []
        extension = Path(file_name).suffix.lower()

        if statistics.entropy <= self.low_entropy_threshold:
            score += 0.35
            reasons.append(f"low entropy ({statistics.entropy:.2f})")

        if statistics.null_ratio >= self.high_null_threshold:
            score += 0.45
            reasons.append(f"high null ratio ({statistics.null_ratio:.1%})")

        if statistics.unique_ratio <= self.low_unique_threshold:
            score += 0.25
            reasons.append(f"low unique ratio ({statistics.unique_ratio:.1%})")

        if pattern.has_repeating_pattern:
            score += 0.35
            reasons.append(
                f"repeating pattern length {pattern.pattern_length} "
                f"with {pattern.repetitions} repeats"
            )

        if statistics.variance <= self.low_variance_threshold and statistics.total_bytes >= 64:
            score += 0.15
            reasons.append(f"low variance ({statistics.variance:.2f})")

        if statistics.max_byte_run >= max(64, min(4096, statistics.total_bytes // 2)):
            score += 0.20
            reasons.append(f"long repeated byte run ({statistics.max_byte_run})")

        if extension in TEXT_EXTENSIONS:
            if (
                statistics.high_byte_ratio >= self.text_high_byte_threshold
                or statistics.low_byte_ratio >= self.text_low_control_threshold
                or statistics.null_ratio > 0.01
            ):
                score += 0.25
                reasons.append("binary-like byte distribution in text file")

        return min(1.0, score), reasons

    def _confidence(self, math_score: float) -> float:
        denominator = max(self.score_threshold, 1.0 - self.score_threshold, 1e-9)
        return min(1.0, 0.5 + abs(math_score - self.score_threshold) / denominator)


class MathematicalProcessor:
    """Processor adapter for modular processing."""

    def __init__(self, sample_size: int = 16 * 1024, chunk_size: int = 256 * 1024):
        self.analyzer = MathAnalyzer(sample_size=sample_size, chunk_size=chunk_size)

    def can_process(self, path: Path) -> bool:
        return path.is_file()

    def process(self, path: Path) -> MathAnalysisResult:
        return self.analyzer.analyze_file(path)


def benchmark_math_performance(iterations: int = 200) -> dict[str, float | bool]:
    data = bytes(range(256)) * 256
    analyzer = MathAnalyzer(sample_size=16 * 1024)

    entropy_start = time.perf_counter()
    for _ in range(iterations):
        analyzer.calculate_entropy(data)
    entropy_seconds = time.perf_counter() - entropy_start

    variance_start = time.perf_counter()
    for _ in range(iterations):
        analyzer.calculate_variance(data)
    variance_seconds = time.perf_counter() - variance_start

    full_start = time.perf_counter()
    for _ in range(max(1, iterations // 10)):
        analyzer.analyze_bytes(data, file_name="benchmark.bin")
    full_seconds = time.perf_counter() - full_start

    return {
        "entropy_ops_per_sec": iterations / entropy_seconds if entropy_seconds > 0 else 0.0,
        "variance_ops_per_sec": iterations / variance_seconds if variance_seconds > 0 else 0.0,
        "full_analysis_ops_per_sec": max(1, iterations // 10) / full_seconds if full_seconds > 0 else 0.0,
        "numpy_available": NUMPY_AVAILABLE,
    }


def create_math_processor(sample_size: int = 16 * 1024, chunk_size: int = 256 * 1024) -> MathematicalProcessor:
    return MathematicalProcessor(sample_size=sample_size, chunk_size=chunk_size)


def create_math_analyzer(sample_size: int = 16 * 1024, chunk_size: int = 256 * 1024) -> MathAnalyzer:
    return MathAnalyzer(sample_size=sample_size, chunk_size=chunk_size)


class TestMathAnalysis(unittest.TestCase):
    def setUp(self) -> None:
        self.analyzer = MathAnalyzer(sample_size=1024, chunk_size=256, use_numpy=False)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_entropy_of_zero_data_is_zero(self) -> None:
        self.assertEqual(self.analyzer.calculate_entropy(b"\x00" * 256), 0.0)

    def test_entropy_of_uniform_distribution_is_high(self) -> None:
        data = bytes(range(256)) * 4
        self.assertGreaterEqual(self.analyzer.calculate_entropy(data), 7.99)

    def test_repeating_pattern_detection(self) -> None:
        pattern = self.analyzer.detect_repeating_patterns(b"ABCD" * 128)
        self.assertTrue(pattern.has_repeating_pattern)
        self.assertEqual(pattern.pattern_length, 4)

    def test_analyze_empty_file(self) -> None:
        path = self._write("empty.bin", b"")
        result = self.analyzer.analyze_file(path)
        self.assertTrue(result.is_corrupted)
        self.assertEqual(result.error_message, "empty file")

    def test_text_file_with_binary_content_is_flagged(self) -> None:
        path = self._write("bad.txt", b"\x00\xff\x80" * 400)
        result = self.analyzer.analyze_file(path)
        self.assertTrue(result.is_corrupted)
        self.assertIn("text file", result.error_message or "")

    def test_full_file_checksum_is_used(self) -> None:
        data = (b"A" * 2048) + (b"B" * 2048)
        path = self._write("full.bin", data)
        result = self.analyzer.analyze_file(path)
        self.assertEqual(result.checksum, hashlib.sha256(data).hexdigest())
        self.assertEqual(result.file_size, len(data))

    def test_math_processor_contract(self) -> None:
        path = self._write("sample.bin", b"hello world")
        processor = MathematicalProcessor(sample_size=512, chunk_size=128)
        result = processor.process(path)
        self.assertEqual(result.file_path, str(path.resolve()))
        self.assertGreater(result.processing_time_seconds, 0.0)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    unittest.main(verbosity=2)