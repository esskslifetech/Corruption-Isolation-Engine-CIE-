#!/usr/bin/env python3
"""
Modular processing system for CIE.

Features:
- Deterministic and repeatable results
- Clear separation of concerns via protocols
- Strategy-based processing (fast, balanced, deep)
- Accurate per-file timing plus batch statistics
- Specialized validators layered on top of baseline hashing
- Graceful error handling
- Built-in unit tests
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

LOGGER = logging.getLogger(__name__)

_TEXT_EXTENSIONS = {
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
}


def _load_module(name: str) -> Any:
    """Import a sibling module regardless of how this file was imported."""
    import importlib
    import importlib.util

    for attempt in (
        lambda: importlib.import_module(name),
        lambda: importlib.import_module(f"src.python.{name}"),
        lambda: _load_module_by_path(name),
    ):
        try:
            return attempt()
        except Exception:
            continue
    raise ImportError(f"cannot import {name}")


def _load_module_by_path(name: str) -> Any:
    import importlib.util

    candidate = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"cie_{name}", candidate)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {candidate}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _read_prefix(path: Path, size: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(size)


def _unique_join(parts: Sequence[str]) -> str | None:
    seen: set[str] = set()
    ordered: list[str] = []

    for part in parts:
        cleaned = part.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            ordered.append(cleaned)

    return "; ".join(ordered) if ordered else None


def _detect_repeating_blocks(data: bytes, block_size: int, min_repeats: int = 3) -> bool:
    if block_size <= 0:
        return False

    full_blocks = len(data) // block_size
    if full_blocks < min_repeats:
        return False

    first_block = data[:block_size]
    repeats = 1

    for index in range(block_size, full_blocks * block_size, block_size):
        if data[index:index + block_size] != first_block:
            return False
        repeats += 1

    return repeats >= min_repeats


@dataclass(frozen=True, slots=True)
class FastResult:
    file_path: str
    file_size: int
    file_type: str
    checksum: str
    is_corrupted: bool
    processing_time_seconds: float
    error_message: str | None = None
    details: tuple[str, ...] = ()

    @property
    def path(self) -> Path:
        return Path(self.file_path)

    @property
    def processing_time(self) -> float:
        return self.processing_time_seconds


class FileProcessor(Protocol):
    def can_process(self, path: Path) -> bool: ...
    def process(self, path: Path) -> FastResult: ...


class BasicFileProcessor:
    """Baseline processor that computes file size and checksum."""

    def __init__(
        self,
        hash_algorithm: str = "sha256",
        chunk_size: int = 256 * 1024,
        max_hashed_bytes: int | None = None,
    ):
        self.hash_algorithm = hash_algorithm
        self.chunk_size = max(1, chunk_size)
        self.max_hashed_bytes = max_hashed_bytes
        hashlib.new(hash_algorithm)

    def can_process(self, path: Path) -> bool:
        return path.is_file()

    def process(self, path: Path) -> FastResult:
        started = time.perf_counter()

        try:
            file_size = path.stat().st_size
        except OSError as exc:
            return FastResult(
                file_path=str(path),
                file_size=0,
                file_type="",
                checksum="",
                is_corrupted=True,
                processing_time_seconds=time.perf_counter() - started,
                error_message=f"stat failed: {exc}",
            )

        hasher = hashlib.new(self.hash_algorithm)
        bytes_hashed = 0
        sampled_hash = False

        try:
            with path.open("rb") as handle:
                while True:
                    chunk = handle.read(self.chunk_size)
                    if not chunk:
                        break

                    if self.max_hashed_bytes is None:
                        hasher.update(chunk)
                        bytes_hashed += len(chunk)
                        continue

                    remaining = self.max_hashed_bytes - bytes_hashed
                    if remaining <= 0:
                        sampled_hash = True
                        break

                    partial_chunk = chunk[:remaining]
                    hasher.update(partial_chunk)
                    bytes_hashed += len(partial_chunk)

                    if len(partial_chunk) < len(chunk):
                        sampled_hash = True
                        break
        except OSError as exc:
            return FastResult(
                file_path=str(path),
                file_size=file_size,
                file_type=path.suffix.lower(),
                checksum="",
                is_corrupted=True,
                processing_time_seconds=time.perf_counter() - started,
                error_message=f"read failed: {exc}",
            )

        checksum = hasher.hexdigest()
        if sampled_hash:
            checksum = f"sampled:{checksum}"

        details: list[str] = []
        is_corrupted = False
        error_message: str | None = None

        if file_size == 0:
            # Warning, not corruption - empty placeholders are legitimate.
            details.append("empty file")

        if sampled_hash:
            details.append("checksum is sampled, not full-file")

        return FastResult(
            file_path=str(path),
            file_size=file_size,
            file_type=path.suffix.lower(),
            checksum=checksum,
            is_corrupted=is_corrupted,
            processing_time_seconds=time.perf_counter() - started,
            error_message=error_message,
            details=tuple(details),
        )


class NullBytePatternProcessor:
    """Detects excessive null bytes and simple repeating block corruption."""

    def __init__(
        self,
        null_ratio_threshold: float = 0.80,
        repeating_block_size: int = 16,
        max_sample_size: int = 16 * 1024,
    ):
        self.null_ratio_threshold = max(0.0, min(1.0, null_ratio_threshold))
        self.repeating_block_size = max(1, repeating_block_size)
        self.max_sample_size = max(self.repeating_block_size * 3, max_sample_size)

    def can_process(self, path: Path) -> bool:
        return path.is_file()

    def process(self, path: Path) -> FastResult:
        started = time.perf_counter()

        try:
            file_size = path.stat().st_size
        except OSError as exc:
            return FastResult(
                file_path=str(path),
                file_size=0,
                file_type="",
                checksum="",
                is_corrupted=True,
                processing_time_seconds=time.perf_counter() - started,
                error_message=f"stat failed: {exc}",
            )

        try:
            sample = _read_prefix(path, self.max_sample_size)
        except OSError as exc:
            return FastResult(
                file_path=str(path),
                file_size=file_size,
                file_type=path.suffix.lower(),
                checksum="",
                is_corrupted=True,
                processing_time_seconds=time.perf_counter() - started,
                error_message=f"read failed: {exc}",
            )

        if not sample:
            # Empty is a warning, never corruption.
            return FastResult(
                file_path=str(path),
                file_size=file_size,
                file_type=path.suffix.lower(),
                checksum="",
                is_corrupted=False,
                processing_time_seconds=time.perf_counter() - started,
                details=("empty file",),
            )

        null_ratio = sample.count(0) / len(sample)
        has_pattern = _detect_repeating_blocks(sample, self.repeating_block_size)

        error_message: str | None = None
        is_corrupted = False

        if null_ratio >= self.null_ratio_threshold:
            is_corrupted = True
            error_message = f"null ratio {null_ratio:.2%} >= {self.null_ratio_threshold:.0%}"
        elif has_pattern:
            is_corrupted = True
            error_message = f"repeating block pattern detected ({self.repeating_block_size}-byte blocks)"

        return FastResult(
            file_path=str(path),
            file_size=file_size,
            file_type=path.suffix.lower(),
            checksum="",
            is_corrupted=is_corrupted,
            processing_time_seconds=time.perf_counter() - started,
            error_message=error_message,
        )


class ImageHeaderProcessor:
    """Validates common image signatures with offset-aware checks."""

    _SIGNATURES: dict[str, tuple[tuple[int, bytes], ...]] = {
        ".jpg": ((0, b"\xff\xd8\xff"),),
        ".jpeg": ((0, b"\xff\xd8\xff"),),
        ".png": ((0, b"\x89PNG\r\n\x1a\n"),),
        ".gif": ((0, b"GIF87a"), (0, b"GIF89a")),
        ".bmp": ((0, b"BM"),),
        ".webp": ((0, b"RIFF"), (8, b"WEBP")),
    }

    def can_process(self, path: Path) -> bool:
        return path.suffix.lower() in self._SIGNATURES

    def process(self, path: Path) -> FastResult:
        started = time.perf_counter()
        extension = path.suffix.lower()

        try:
            file_size = path.stat().st_size
        except OSError as exc:
            return FastResult(
                file_path=str(path),
                file_size=0,
                file_type=extension,
                checksum="",
                is_corrupted=True,
                processing_time_seconds=time.perf_counter() - started,
                error_message=f"stat failed: {exc}",
            )

        signatures = self._SIGNATURES[extension]
        max_required = max(offset + len(signature) for offset, signature in signatures)

        try:
            prefix = _read_prefix(path, max_required)
        except OSError as exc:
            return FastResult(
                file_path=str(path),
                file_size=file_size,
                file_type=extension,
                checksum="",
                is_corrupted=True,
                processing_time_seconds=time.perf_counter() - started,
                error_message=f"read failed: {exc}",
            )

        valid = all(
            prefix[offset:offset + len(signature)] == signature
            for offset, signature in signatures
        ) if extension == ".webp" else any(
            prefix[offset:offset + len(signature)] == signature
            for offset, signature in signatures
        )

        return FastResult(
            file_path=str(path),
            file_size=file_size,
            file_type=extension,
            checksum="",
            is_corrupted=not valid,
            processing_time_seconds=time.perf_counter() - started,
            error_message=None if valid else f"invalid {extension[1:].upper()} header",
        )


def _looks_like_text(decoded: str, threshold: float = 0.95) -> bool:
    """True when nearly every character is printable (BOM/whitespace allowed)."""
    if not decoded:
        return False
    acceptable = sum(
        1 for char in decoded
        if char.isprintable() or char.isspace() or char == "\ufeff"
    )
    return acceptable / len(decoded) >= threshold


def decode_as_text(sample: bytes) -> str | None:
    """Return the encoding name if the sample decodes as text, else None.

    Replaces the old "non-ASCII byte ratio >= 70% means corrupt" heuristic,
    which flagged every CJK, Devanagari, Cyrillic, Arabic or emoji document as
    binary. UTF-16/32 are tried too, because files saved by Windows tools and
    exported CSVs are full of NUL bytes without being damaged.
    """
    if not sample:
        return None

    for encoding in ("utf-8-sig", "utf-8"):
        try:
            sample.decode(encoding)
            return encoding
        except UnicodeDecodeError:
            continue

    # BOM-less UTF-16/32. Random bytes can *decode* as UTF-16 by accident, so
    # require the structural fingerprint of real UTF-16 text: NUL bytes sitting
    # consistently in one byte position (the high byte of Latin/ASCII-range
    # code points), plus an all-printable result.
    for encoding, nul_positions in (("utf-16-le", {1}), ("utf-16-be", {0})):
        try:
            decoded = sample.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue

        nul_indices = [index for index, byte in enumerate(sample) if byte == 0]
        if not nul_indices:
            continue
        aligned = sum(1 for index in nul_indices if (index % 2) in nul_positions)
        if aligned / len(nul_indices) < 0.95:
            continue

        if decoded and _looks_like_text(decoded):
            return encoding

    for encoding in ("utf-32-le", "utf-32-be"):
        try:
            decoded = sample.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
        if decoded and _looks_like_text(decoded):
            return encoding

    return None


class TextEncodingProcessor:
    """Flags text-like files whose bytes are not decodable as text.

    Corruption is reported only when the content cannot be decoded as
    UTF-8/16/32 *and* shows binary markers (NUL runs or control characters).
    """

    def __init__(self, max_sample_size: int = 8192):
        self.max_sample_size = max(1, max_sample_size)

    def can_process(self, path: Path) -> bool:
        return path.suffix.lower() in _TEXT_EXTENSIONS

    def process(self, path: Path) -> FastResult:
        started = time.perf_counter()
        extension = path.suffix.lower()

        try:
            file_size = path.stat().st_size
        except OSError as exc:
            return FastResult(
                file_path=str(path),
                file_size=0,
                file_type=extension,
                checksum="",
                is_corrupted=True,
                processing_time_seconds=time.perf_counter() - started,
                error_message=f"stat failed: {exc}",
            )

        try:
            sample = _read_prefix(path, self.max_sample_size)
        except OSError as exc:
            return FastResult(
                file_path=str(path),
                file_size=file_size,
                file_type=extension,
                checksum="",
                is_corrupted=True,
                processing_time_seconds=time.perf_counter() - started,
                error_message=f"read failed: {exc}",
            )

        if not sample:
            # An empty file is a warning, not corruption: .gitkeep, touch'd
            # placeholders, rotated logs and lock files are legitimately empty.
            return FastResult(
                file_path=str(path),
                file_size=file_size,
                file_type=extension,
                checksum="",
                is_corrupted=False,
                processing_time_seconds=time.perf_counter() - started,
                error_message=None,
                details=("empty file",),
            )

        encoding = decode_as_text(sample)
        if encoding is not None:
            return FastResult(
                file_path=str(path),
                file_size=file_size,
                file_type=extension,
                checksum="",
                is_corrupted=False,
                processing_time_seconds=time.perf_counter() - started,
                details=(f"decoded as {encoding}",),
            )

        # Undecodable: only call it corruption when binary markers are present,
        # otherwise it is simply an unknown encoding.
        null_ratio = sample.count(0) / len(sample)
        control_ratio = sum(
            1 for byte in sample if byte < 9 or (13 < byte < 32)
        ) / len(sample)

        is_corrupted = null_ratio >= 0.30 or control_ratio >= 0.10
        error_message = (
            f"undecodable text with binary markers "
            f"(null {null_ratio:.1%}, control {control_ratio:.1%})"
            if is_corrupted
            else None
        )

        return FastResult(
            file_path=str(path),
            file_size=file_size,
            file_type=extension,
            checksum="",
            is_corrupted=is_corrupted,
            processing_time_seconds=time.perf_counter() - started,
            error_message=error_message,
            details=() if is_corrupted else ("unknown text encoding",),
        )


class StructureValidatorProcessor:
    """Validates file structure using the shared validators in format_validators.

    Without this, the modular scanner had no idea what a corrupt PDF or a fake
    PNG looked like (it only checked a handful of image headers), so its
    verdicts disagreed with the core engine on the same files.

    ``full=False`` performs signature-only checks (fast strategy);
    ``full=True`` additionally uses Pillow/PyPDF2/openpyxl/ffprobe when present.
    """

    def __init__(self, full: bool = True, allow_unchecked: bool = True):
        self.full = full
        self.allow_unchecked = allow_unchecked
        self._validator: Any | None = None

    def _load(self) -> Any | None:
        if self._validator is not None:
            return self._validator
        try:
            module = _load_module("format_validators")
        except Exception as exc:  # pragma: no cover - layout dependent
            LOGGER.warning("structure validation unavailable: %s", exc)
            return None

        self._factory = module.FactoryBackedFormatValidator()
        self._magic = module.MagicSignatureValidator()
        self._validator = self._factory if self.full else self._magic
        return self._validator

    def can_process(self, path: Path) -> bool:
        return path.is_file()

    def process(self, path: Path) -> FastResult:
        started = time.perf_counter()
        try:
            size = path.stat().st_size
        except OSError as exc:
            return FastResult(
                file_path=str(path), file_size=0, file_type=path.suffix.lower(),
                checksum="", is_corrupted=True,
                processing_time_seconds=time.perf_counter() - started,
                error_message=f"stat failed: {exc}",
            )

        validator = self._load()
        if validator is None:
            return FastResult(
                file_path=str(path), file_size=size, file_type=path.suffix.lower(),
                checksum="", is_corrupted=False,
                processing_time_seconds=time.perf_counter() - started,
                details=("structure validation unavailable",),
            )

        try:
            result = validator.validate(path)
        except Exception as exc:
            LOGGER.warning("structure validation failed for %s: %s", path, exc)
            return FastResult(
                file_path=str(path), file_size=size, file_type=path.suffix.lower(),
                checksum="", is_corrupted=False,
                processing_time_seconds=time.perf_counter() - started,
                details=(f"structure validation skipped: {exc}",),
            )

        details: list[str] = []
        if not result.checked:
            details.append(result.format_info.get("reason", "not inspected"))
        if result.is_valid and self.allow_unchecked:
            details.append(f"validated by {result.format_info.get('validator', 'validator')}")

        return FastResult(
            file_path=str(path),
            file_size=size,
            file_type=result.format_name or path.suffix.lower(),
            checksum="",
            is_corrupted=not result.is_valid,
            processing_time_seconds=time.perf_counter() - started,
            error_message=None if result.is_valid else (result.error_message or "invalid structure"),
            details=tuple(details),
        )


class ScanStrategy(Protocol):
    def processors(self) -> Sequence[FileProcessor]: ...
    def max_workers(self) -> int: ...
    def name(self) -> str: ...


@dataclass(frozen=True, slots=True)
class FastScanStrategy:
    def processors(self) -> Sequence[FileProcessor]:
        return (
            BasicFileProcessor(hash_algorithm="md5", chunk_size=64 * 1024),
            NullBytePatternProcessor(null_ratio_threshold=0.85, repeating_block_size=16),
            StructureValidatorProcessor(full=True),
        )

    def max_workers(self) -> int:
        return max(1, min(32, (os.cpu_count() or 1) * 4))

    def name(self) -> str:
        return "fast"


@dataclass(frozen=True, slots=True)
class BalancedScanStrategy:
    def processors(self) -> Sequence[FileProcessor]:
        return (
            BasicFileProcessor(hash_algorithm="sha256", chunk_size=256 * 1024),
            ImageHeaderProcessor(),
            TextEncodingProcessor(max_sample_size=8 * 1024),
            NullBytePatternProcessor(null_ratio_threshold=0.80, repeating_block_size=16),
            StructureValidatorProcessor(full=True),
        )

    def max_workers(self) -> int:
        return max(1, min(16, (os.cpu_count() or 1) * 2))

    def name(self) -> str:
        return "balanced"


@dataclass(frozen=True, slots=True)
class DeepScanStrategy:
    def processors(self) -> Sequence[FileProcessor]:
        return (
            BasicFileProcessor(hash_algorithm="sha256", chunk_size=512 * 1024),
            ImageHeaderProcessor(),
            TextEncodingProcessor(max_sample_size=32 * 1024),
            NullBytePatternProcessor(null_ratio_threshold=0.75, repeating_block_size=32, max_sample_size=32 * 1024),
            StructureValidatorProcessor(full=True),
        )

    def max_workers(self) -> int:
        return max(1, min(8, (os.cpu_count() or 1)))

    def name(self) -> str:
        return "deep"


@dataclass(slots=True)
class ModularProcessor:
    strategy: ScanStrategy
    _processors: tuple[FileProcessor, ...] = field(init=False, repr=False)
    _primary_processor: BasicFileProcessor = field(init=False, repr=False)
    _validator_processors: tuple[FileProcessor, ...] = field(init=False, repr=False)
    _last_wall_clock_seconds: float = field(default=0.0, init=False, repr=False)

    def __post_init__(self) -> None:
        processors = tuple(self.strategy.processors())
        if not processors:
            raise ValueError("strategy must provide at least one processor")

        primary = next((processor for processor in processors if isinstance(processor, BasicFileProcessor)), None)
        if primary is None:
            primary = BasicFileProcessor()
            processors = (primary, *processors)

        self._processors = processors
        self._primary_processor = primary
        self._validator_processors = tuple(processor for processor in processors if processor is not primary)

    @property
    def processors(self) -> Sequence[FileProcessor]:
        return self._processors

    @property
    def max_workers(self) -> int:
        return self.strategy.max_workers()

    @property
    def name(self) -> str:
        return self.strategy.name()

    def process_files(self, file_paths: Sequence[Path]) -> tuple[FastResult, ...]:
        normalized_paths = tuple(sorted((Path(path) for path in file_paths), key=lambda item: str(item).casefold()))
        if not normalized_paths:
            self._last_wall_clock_seconds = 0.0
            return ()

        started = time.perf_counter()
        results: list[FastResult] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._process_one, path): path for path in normalized_paths}

            for future in as_completed(futures):
                path = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    LOGGER.exception("processor failure for %s", path)
                    results.append(
                        FastResult(
                            file_path=str(path),
                            file_size=0,
                            file_type=path.suffix.lower(),
                            checksum="",
                            is_corrupted=True,
                            processing_time_seconds=0.0,
                            error_message=f"processing error: {exc}",
                        )
                    )

        self._last_wall_clock_seconds = time.perf_counter() - started
        return tuple(sorted(results, key=lambda item: item.file_path.casefold()))

    def _process_one(self, path: Path) -> FastResult:
        results = [self._primary_processor.process(path)]

        for processor in self._validator_processors:
            try:
                if processor.can_process(path):
                    results.append(processor.process(path))
            except Exception as exc:
                LOGGER.warning("validator failure for %s using %s: %s", path, type(processor).__name__, exc)
                results.append(
                    FastResult(
                        file_path=str(path),
                        file_size=0,
                        file_type=path.suffix.lower(),
                        checksum="",
                        is_corrupted=True,
                        processing_time_seconds=0.0,
                        error_message=f"{type(processor).__name__} failed: {exc}",
                    )
                )

        return self._merge_results(path, results)

    def _merge_results(self, path: Path, results: Sequence[FastResult]) -> FastResult:
        file_size = 0
        file_type = path.suffix.lower()
        checksum = ""
        is_corrupted = False
        total_processing_seconds = 0.0
        errors: list[str] = []
        details: list[str] = []

        for result in results:
            if file_size == 0 and result.file_size > 0:
                file_size = result.file_size
            if not checksum and result.checksum:
                checksum = result.checksum
            if result.file_type:
                file_type = result.file_type
            if result.is_corrupted:
                is_corrupted = True
            total_processing_seconds += result.processing_time_seconds
            if result.error_message:
                errors.append(result.error_message)
            details.extend(result.details)

        return FastResult(
            file_path=str(path),
            file_size=file_size,
            file_type=file_type,
            checksum=checksum,
            is_corrupted=is_corrupted,
            processing_time_seconds=total_processing_seconds,
            error_message=_unique_join(errors),
            details=tuple(dict.fromkeys(details)),
        )

    def get_performance_stats(self, results: Sequence[FastResult]) -> Mapping[str, Any]:
        if not results:
            return {}

        total_files = len(results)
        total_processing_time_seconds = sum(result.processing_time_seconds for result in results)
        corrupted_files = sum(1 for result in results if result.is_corrupted)
        total_size_bytes = sum(result.file_size for result in results)

        wall_clock_seconds = self._last_wall_clock_seconds
        effective_seconds = wall_clock_seconds if wall_clock_seconds > 0 else total_processing_time_seconds

        files_per_second = total_files / effective_seconds if effective_seconds > 0 else 0.0
        mb_per_second = (total_size_bytes / (1024 * 1024)) / effective_seconds if effective_seconds > 0 else 0.0
        corruption_rate_percent = (corrupted_files / total_files * 100.0) if total_files > 0 else 0.0

        return {
            "total_files": total_files,
            "corrupted_files": corrupted_files,
            "total_size": total_size_bytes,
            "total_size_bytes": total_size_bytes,
            "total_processing_time_seconds": total_processing_time_seconds,
            "wall_clock_seconds": wall_clock_seconds,
            "files_per_second": files_per_second,
            "mb_per_second": mb_per_second,
            "corruption_rate": corruption_rate_percent,
            "corruption_rate_percent": corruption_rate_percent,
            "processors_used": len(self.processors),
            "strategy": self.name,
        }


class ProcessorFactory:
    """Factory for pre-configured modular processors."""

    @staticmethod
    def create_fast_processor() -> ModularProcessor:
        return ModularProcessor(FastScanStrategy())

    @staticmethod
    def create_balanced_processor() -> ModularProcessor:
        return ModularProcessor(BalancedScanStrategy())

    @staticmethod
    def create_deep_processor() -> ModularProcessor:
        return ModularProcessor(DeepScanStrategy())

    @staticmethod
    def create_custom_processor(
        processors: Sequence[FileProcessor],
        *,
        max_workers: int | None = None,
        name: str = "custom",
    ) -> ModularProcessor:
        validated_processors = tuple(processors)
        if not validated_processors:
            raise ValueError("custom processor requires at least one processor")

        @dataclass(frozen=True, slots=True)
        class CustomStrategy:
            _processors: tuple[FileProcessor, ...]
            _max_workers: int
            _name: str

            def processors(self) -> Sequence[FileProcessor]:
                return self._processors

            def max_workers(self) -> int:
                return self._max_workers

            def name(self) -> str:
                return self._name

        return ModularProcessor(
            CustomStrategy(
                _processors=validated_processors,
                _max_workers=max(1, max_workers or min(16, (os.cpu_count() or 1) * 2)),
                _name=name,
            )
        )


class TestModularProcessor(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write(self, name: str, content: bytes) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_fast_processor_detects_null_files(self) -> None:
        path = self._write("null.bin", b"\x00" * 1024)
        processor = ProcessorFactory.create_fast_processor()
        results = processor.process_files((path,))

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].is_corrupted)
        self.assertIn("null", results[0].error_message or "")

    def test_balanced_processor_detects_bad_image_header(self) -> None:
        path = self._write("bad.jpg", b"not a jpeg")
        processor = ProcessorFactory.create_balanced_processor()
        results = processor.process_files((path,))

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].is_corrupted)
        self.assertIn("header", results[0].error_message or "")

    def test_balanced_processor_detects_binary_text(self) -> None:
        path = self._write("bad.txt", b"\x00\xff\x80" * 300)
        processor = ProcessorFactory.create_balanced_processor()
        results = processor.process_files((path,))

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].is_corrupted)
        self.assertIn("undecodable text", results[0].error_message or "")

    def test_result_order_is_deterministic(self) -> None:
        a = self._write("b.txt", b"bbb")
        b = self._write("a.txt", b"aaa")
        processor = ProcessorFactory.create_fast_processor()

        results = processor.process_files((a, b))
        self.assertEqual([result.file_path for result in results], sorted([str(a), str(b)]))

    def test_performance_stats_are_positive(self) -> None:
        path = self._write("text.txt", b"hello world")
        processor = ProcessorFactory.create_fast_processor()
        results = processor.process_files((path,))
        stats = processor.get_performance_stats(results)

        self.assertGreater(stats["total_files"], 0)
        self.assertGreaterEqual(stats["wall_clock_seconds"], 0.0)
        self.assertGreater(stats["files_per_second"], 0.0)

    def test_custom_processor_without_basic_still_works(self) -> None:
        processor = ProcessorFactory.create_custom_processor([TextEncodingProcessor()], name="text-only")
        path = self._write("sample.txt", b"hello")
        results = processor.process_files((path,))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].file_path, str(path))
        self.assertTrue(results[0].checksum)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    unittest.main(verbosity=2)