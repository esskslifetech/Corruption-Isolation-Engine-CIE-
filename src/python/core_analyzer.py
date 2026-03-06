#!/usr/bin/env python3
"""
Core analyzer for Corruption Isolation Engine (CIE).

This Project Is Made By Kanishk Soni

This module provides:
- Concurrent directory scanning
- Single-pass hashing and entropy calculation
- SQLite persistence with WAL mode and lock retry handling
- Built-in format validation for common file types
- Safe quarantine operations
- GUI-friendly result objects and contracts
"""

from __future__ import annotations

import hashlib
import importlib.util
import logging
import math
import os
import shutil
import sqlite3
import tempfile
import threading
import time
import unittest
import zipfile
from concurrent.futures import Future, ThreadPoolExecutor, as_completed, CancelledError
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Protocol, TypeVar

LOGGER = logging.getLogger(__name__)

FilePath = str | Path
ChecksumStr = str
T = TypeVar("T")


# ==============================================================================
# 1. CONFIGURATION
# ==============================================================================

@dataclass(frozen=True, slots=True)
class AnalyzerConfig:
    db_path: str = "cie_database.db"
    quarantine_dir: str = "quarantine"
    chunk_size: int = 256 * 1024
    hash_algorithm: str = "sha256"
    max_workers: int = max(1, min(32, (os.cpu_count() or 1) * 2))  # Doubled from *1 to *2
    detect_ransomware: bool = True
    entropy_threshold: float = 7.95
    db_busy_timeout_ms: int = 5_000
    db_retry_attempts: int = 6
    db_retry_backoff_seconds: float = 0.05
    exclude_quarantine_from_scans: bool = True
    follow_symlinks: bool = False
    include_hidden_files: bool = True


# ==============================================================================
# 2. EXCEPTIONS
# ==============================================================================

class AnalyzerBaseException(Exception):
    """Base exception for analyzer errors."""


class FileAccessError(AnalyzerBaseException):
    """Raised when a file cannot be read or inspected."""


class DatabaseConcurrencyError(AnalyzerBaseException):
    """Raised when SQLite remains locked after retries."""


class QuarantineError(AnalyzerBaseException):
    """Raised when quarantine fails."""


class ScanCancelledError(AnalyzerBaseException):
    """Raised when an in-progress scan is cancelled."""


# ==============================================================================
# 3. DOMAIN MODELS
# ==============================================================================

class FileStatus(Enum):
    VALID = auto()
    NEW_FILE = auto()
    CORRUPTED_SIZE = auto()
    CORRUPTED_CHECKSUM = auto()
    CORRUPTED_FORMAT = auto()
    MISSING = auto()
    UNREADABLE = auto()
    SUSPECTED_RANSOMWARE = auto()


@dataclass(frozen=True, slots=True)
class FileMetrics:
    size_bytes: int
    checksum: ChecksumStr
    shannon_entropy: float


@dataclass(frozen=True, slots=True)
class FileRecord:
    path_str: str
    size_bytes: int
    checksum: ChecksumStr
    last_modified_ts: float
    is_corrupted: bool
    shannon_entropy: float = 0.0
    file_type: str | None = None


@dataclass(frozen=True, slots=True)
class FormatValidationResult:
    is_valid: bool
    format_name: str | None = None
    error_message: str | None = None
    format_info: Mapping[str, Any] = field(default_factory=dict)
    corruption_details: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class FileAnalysisResult:
    file_path: str
    status: FileStatus
    metrics: FileMetrics | None = None
    file_type: str | None = None
    error_message: str | None = None
    format_validation: FormatValidationResult | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def file_size(self) -> int:
        return 0 if self.metrics is None else self.metrics.size_bytes

    @property
    def checksum(self) -> str:
        return "" if self.metrics is None else self.metrics.checksum

    @property
    def shannon_entropy(self) -> float:
        return 0.0 if self.metrics is None else self.metrics.shannon_entropy

    @property
    def is_corrupted(self) -> bool:
        return self.status in {
            FileStatus.CORRUPTED_SIZE,
            FileStatus.CORRUPTED_CHECKSUM,
            FileStatus.CORRUPTED_FORMAT,
            FileStatus.SUSPECTED_RANSOMWARE,
        }

    @property
    def path_obj(self) -> Path:
        return Path(self.file_path)


AnalysisResult = FileAnalysisResult


# ==============================================================================
# 4. PROTOCOLS
# ==============================================================================

class IMetadataRepository(Protocol):
    def initialize(self) -> None: ...
    def get_record(self, path: str) -> FileRecord | None: ...
    def upsert_record(self, record: FileRecord) -> None: ...
    def log_quarantine(self, original_path: str, quarantine_path: str, reason: str) -> None: ...


class IMetricsCalculator(Protocol):
    def calculate(self, path: Path, cancel_event: threading.Event | None = None) -> FileMetrics: ...


class IFormatValidator(Protocol):
    def validate(self, path: Path) -> FormatValidationResult: ...


# ==============================================================================
# 5. INFRASTRUCTURE
# ==============================================================================

class SQLiteMetadataRepo(IMetadataRepository):
    """SQLite repository with WAL mode and retry-on-lock behavior."""

    def __init__(self, config: AnalyzerConfig):
        self._db_path = str(Path(config.db_path).expanduser())
        self._busy_timeout_ms = max(1, config.db_busy_timeout_ms)
        self._retry_attempts = max(1, config.db_retry_attempts)
        self._retry_backoff_seconds = max(0.0, config.db_retry_backoff_seconds)
        self._schema_lock = threading.Lock()

        db_parent = Path(self._db_path).parent
        db_parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def _get_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._db_path,
            timeout=self._busy_timeout_ms / 1000.0,
            isolation_level=None,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL;")
        connection.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms};")
        connection.execute("PRAGMA synchronous=NORMAL;")
        connection.execute("PRAGMA foreign_keys=ON;")
        return connection

    def _run_with_retry(self, operation: Callable[[], T]) -> T:
        last_error: sqlite3.OperationalError | None = None

        for attempt in range(self._retry_attempts):
            try:
                return operation()
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                    raise DatabaseConcurrencyError(str(exc)) from exc

                last_error = exc
                if attempt + 1 < self._retry_attempts:
                    time.sleep(self._retry_backoff_seconds * (2 ** attempt))

        raise DatabaseConcurrencyError(
            f"database remained locked after {self._retry_attempts} attempts"
        ) from last_error

    def initialize(self) -> None:
        with self._schema_lock:
            def operation() -> None:
                with self._get_connection() as connection:
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS file_metadata (
                            file_path TEXT PRIMARY KEY,
                            size_bytes INTEGER NOT NULL,
                            checksum TEXT NOT NULL,
                            last_modified REAL NOT NULL,
                            is_corrupted INTEGER NOT NULL DEFAULT 0,
                            shannon_entropy REAL NOT NULL DEFAULT 0.0,
                            file_type TEXT,
                            analysis_date TEXT NOT NULL
                        )
                        """
                    )
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS quarantine_log (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            original_path TEXT NOT NULL,
                            quarantine_path TEXT NOT NULL,
                            reason TEXT NOT NULL,
                            action_date TEXT NOT NULL
                        )
                        """
                    )
                    connection.execute(
                        """
                        CREATE INDEX IF NOT EXISTS idx_quarantine_log_original_path
                        ON quarantine_log(original_path)
                        """
                    )

            self._run_with_retry(operation)

    def get_record(self, path: str) -> FileRecord | None:
        def operation() -> FileRecord | None:
            with self._get_connection() as connection:
                row = connection.execute(
                    """
                    SELECT
                        file_path,
                        size_bytes,
                        checksum,
                        last_modified,
                        is_corrupted,
                        shannon_entropy,
                        file_type
                    FROM file_metadata
                    WHERE file_path = ?
                    """,
                    (path,),
                ).fetchone()

                if row is None:
                    return None

                return FileRecord(
                    path_str=str(row["file_path"]),
                    size_bytes=int(row["size_bytes"]),
                    checksum=str(row["checksum"]),
                    last_modified_ts=float(row["last_modified"]),
                    is_corrupted=bool(row["is_corrupted"]),
                    shannon_entropy=float(row["shannon_entropy"]),
                    file_type=row["file_type"],
                )

        return self._run_with_retry(operation)

    def upsert_record(self, record: FileRecord) -> None:
        def operation() -> None:
            with self._get_connection() as connection:
                connection.execute(
                    """
                    INSERT INTO file_metadata (
                        file_path,
                        size_bytes,
                        checksum,
                        last_modified,
                        is_corrupted,
                        shannon_entropy,
                        file_type,
                        analysis_date
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(file_path) DO UPDATE SET
                        size_bytes = excluded.size_bytes,
                        checksum = excluded.checksum,
                        last_modified = excluded.last_modified,
                        is_corrupted = excluded.is_corrupted,
                        shannon_entropy = excluded.shannon_entropy,
                        file_type = excluded.file_type,
                        analysis_date = excluded.analysis_date
                    """,
                    (
                        record.path_str,
                        record.size_bytes,
                        record.checksum,
                        record.last_modified_ts,
                        int(record.is_corrupted),
                        record.shannon_entropy,
                        record.file_type,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )

        self._run_with_retry(operation)

    def log_quarantine(self, original_path: str, quarantine_path: str, reason: str) -> None:
        def operation() -> None:
            with self._get_connection() as connection:
                connection.execute(
                    """
                    INSERT INTO quarantine_log (
                        original_path,
                        quarantine_path,
                        reason,
                        action_date
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        original_path,
                        quarantine_path,
                        reason,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )

        self._run_with_retry(operation)


class AdvancedFileMetricsCalculator(IMetricsCalculator):
    """Calculates size, checksum, and Shannon entropy in one streaming pass."""

    def __init__(self, config: AnalyzerConfig):
        self._chunk_size = max(1, config.chunk_size)
        self._hash_algorithm = config.hash_algorithm
        hashlib.new(self._hash_algorithm)

    def calculate(self, path: Path, cancel_event: threading.Event | None = None) -> FileMetrics:
        histogram = [0] * 256
        total_bytes = 0
        hasher = hashlib.new(self._hash_algorithm)

        try:
            with path.open("rb") as handle:
                while True:
                    if cancel_event is not None and cancel_event.is_set():
                        raise ScanCancelledError(f"scan cancelled while reading {path}")

                    chunk = handle.read(self._chunk_size)
                    if not chunk:
                        break

                    hasher.update(chunk)
                    total_bytes += len(chunk)

                    for byte_value in chunk:
                        histogram[byte_value] += 1
        except OSError as exc:
            raise FileAccessError(f"failed to read file metrics for {path}: {exc}") from exc

        entropy = 0.0
        if total_bytes > 0:
            for count in histogram:
                if count == 0:
                    continue
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)

        return FileMetrics(
            size_bytes=total_bytes,
            checksum=hasher.hexdigest(),
            shannon_entropy=entropy,
        )


class BuiltinFormatValidator(IFormatValidator):
    """Built-in validator using signatures and light structural checks."""

    _FORMAT_NAMES: dict[str, str] = {
        ".pdf": "PDF",
        ".png": "PNG",
        ".jpg": "JPEG",
        ".jpeg": "JPEG",
        ".gif": "GIF",
        ".zip": "ZIP",
        ".docx": "DOCX",
        ".xlsx": "XLSX",
        ".exe": "PE",
        ".elf": "ELF",
        ".mp4": "MP4",
        ".txt": "Text",
        ".json": "JSON",
        ".xml": "XML",
        ".csv": "CSV",
    }

    _SIGNATURES: dict[str, tuple[tuple[int, bytes], ...]] = {
        ".png": ((0, b"\x89PNG\r\n\x1a\n"),),
        ".jpg": ((0, b"\xff\xd8\xff"),),
        ".jpeg": ((0, b"\xff\xd8\xff"),),
        ".gif": ((0, b"GIF87a"), (0, b"GIF89a")),
        ".zip": ((0, b"PK\x03\x04"), (0, b"PK\x05\x06"), (0, b"PK\x07\x08")),
        ".docx": ((0, b"PK\x03\x04"),),
        ".xlsx": ((0, b"PK\x03\x04"),),
        ".exe": ((0, b"MZ"),),
        ".elf": ((0, b"\x7fELF"),),
        ".mp4": ((4, b"ftyp"),),
    }

    def validate(self, path: Path) -> FormatValidationResult:
        extension = path.suffix.lower()
        format_name = self._FORMAT_NAMES.get(extension, extension[1:].upper() if extension else "Unknown")

        if extension in {".zip", ".docx", ".xlsx"}:
            return self._validate_zip_family(path, extension, format_name)

        if extension == ".pdf":
            return self._validate_pdf(path, format_name)

        if extension in {".jpg", ".jpeg"}:
            return self._validate_jpeg(path, format_name)

        if extension in self._SIGNATURES:
            return self._validate_magic(path, extension, format_name)

        return FormatValidationResult(
            is_valid=True,
            format_name=format_name,
            format_info={
                "extension": extension or "<none>",
                "validator": "builtin",
                "checked": False,
            },
        )

    def _read_prefix(self, path: Path, length: int) -> bytes:
        try:
            with path.open("rb") as handle:
                return handle.read(length)
        except OSError as exc:
            raise FileAccessError(f"failed to read prefix for {path}: {exc}") from exc

    def _read_suffix(self, path: Path, length: int) -> bytes:
        try:
            size = path.stat().st_size
            start = max(0, size - length)
            with path.open("rb") as handle:
                handle.seek(start)
                return handle.read()
        except OSError as exc:
            raise FileAccessError(f"failed to read suffix for {path}: {exc}") from exc

    def _validate_magic(
        self,
        path: Path,
        extension: str,
        format_name: str,
    ) -> FormatValidationResult:
        checks = self._SIGNATURES[extension]
        max_bytes_needed = max(offset + len(signature) for offset, signature in checks)
        prefix = self._read_prefix(path, max_bytes_needed)

        for offset, signature in checks:
            if prefix[offset:offset + len(signature)] == signature:
                return FormatValidationResult(
                    is_valid=True,
                    format_name=format_name,
                    format_info={
                        "extension": extension,
                        "validator": "magic",
                    },
                )

        return FormatValidationResult(
            is_valid=False,
            format_name=format_name,
            error_message=f"{format_name} signature mismatch",
            format_info={
                "extension": extension,
                "validator": "magic",
            },
            corruption_details=(f"expected valid {format_name} file signature",),
        )

    def _validate_pdf(self, path: Path, format_name: str) -> FormatValidationResult:
        prefix = self._read_prefix(path, 8)
        suffix = self._read_suffix(path, 2048)

        issues: list[str] = []
        if not prefix.startswith(b"%PDF-"):
            issues.append("missing PDF header")
        if b"%%EOF" not in suffix:
            issues.append("missing PDF EOF marker")

        if issues:
            return FormatValidationResult(
                is_valid=False,
                format_name=format_name,
                error_message="invalid PDF structure",
                format_info={"validator": "pdf", "extension": ".pdf"},
                corruption_details=tuple(issues),
            )

        return FormatValidationResult(
            is_valid=True,
            format_name=format_name,
            format_info={"validator": "pdf", "extension": ".pdf"},
        )

    def _validate_jpeg(self, path: Path, format_name: str) -> FormatValidationResult:
        prefix = self._read_prefix(path, 3)
        suffix = self._read_suffix(path, 2)

        issues: list[str] = []
        if not prefix.startswith(b"\xff\xd8\xff"):
            issues.append("missing JPEG SOI marker")
        if suffix != b"\xff\xd9":
            issues.append("missing JPEG EOI marker")

        if issues:
            return FormatValidationResult(
                is_valid=False,
                format_name=format_name,
                error_message="invalid JPEG structure",
                format_info={"validator": "jpeg", "extension": path.suffix.lower()},
                corruption_details=tuple(issues),
            )

        return FormatValidationResult(
            is_valid=True,
            format_name=format_name,
            format_info={"validator": "jpeg", "extension": path.suffix.lower()},
        )

    def _validate_zip_family(
        self,
        path: Path,
        extension: str,
        format_name: str,
    ) -> FormatValidationResult:
        try:
            with zipfile.ZipFile(path, "r") as archive:
                members = archive.namelist()
                bad_member = archive.testzip()
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            return FormatValidationResult(
                is_valid=False,
                format_name=format_name,
                error_message=f"invalid {format_name} container",
                format_info={"validator": "zip", "extension": extension},
                corruption_details=(str(exc),),
            )

        issues: list[str] = []
        if bad_member is not None:
            issues.append(f"CRC failed for archive member: {bad_member}")

        member_set = set(members)
        if extension == ".docx":
            if "[Content_Types].xml" not in member_set:
                issues.append("missing [Content_Types].xml")
            if not any(name.startswith("word/") for name in members):
                issues.append("missing word/ package entries")
        elif extension == ".xlsx":
            if "[Content_Types].xml" not in member_set:
                issues.append("missing [Content_Types].xml")
            if not any(name.startswith("xl/") for name in members):
                issues.append("missing xl/ package entries")

        if issues:
            return FormatValidationResult(
                is_valid=False,
                format_name=format_name,
                error_message=f"invalid {format_name} structure",
                format_info={
                    "validator": "zip",
                    "extension": extension,
                    "member_count": len(members),
                },
                corruption_details=tuple(issues),
            )

        return FormatValidationResult(
            is_valid=True,
            format_name=format_name,
            format_info={
                "validator": "zip",
                "extension": extension,
                "member_count": len(members),
            },
        )


# ==============================================================================
# 6. CORE APPLICATION SERVICE
# ==============================================================================

_HIGH_ENTROPY_SAFE_EXTENSIONS = {
    ".zip",
    ".docx",
    ".xlsx",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".pdf",
    ".gz",
    ".7z",
    ".rar",
    ".mp4",
    ".mov",
    ".avi",
    ".mp3",
    ".wav",
    ".flac",
    ".webp",
}

_SUSPICIOUS_RANSOMWARE_EXTENSIONS = {
    ".locked",
    ".encrypted",
    ".enc",
    ".crypt",
    ".cipher",
    ".locky",
}


class CorruptionEngine:
    """Coordinates file analysis, persistence, scanning, and quarantine."""

    def __init__(
        self,
        config: AnalyzerConfig,
        repo: IMetadataRepository,
        calculator: IMetricsCalculator,
        format_validator: IFormatValidator,
    ):
        self._config = config
        self._repo = repo
        self._calculator = calculator
        self._format_validator = format_validator
        self._logger = logging.getLogger(type(self).__name__)
        self._cancel_event = threading.Event()

    def request_stop(self) -> None:
        self._cancel_event.set()

    def cancel_scan(self) -> None:
        self.request_stop()

    def clear_stop_request(self) -> None:
        self._cancel_event.clear()

    def _guess_file_type(self, path: Path, validation: FormatValidationResult | None) -> str:
        if validation and validation.format_name:
            return validation.format_name
        extension = path.suffix.lower()
        if extension:
            return extension[1:].upper()
        return "Unknown"

    def _status_message(
        self,
        status: FileStatus,
        validation: FormatValidationResult | None = None,
    ) -> str | None:
        if status is FileStatus.CORRUPTED_FORMAT and validation is not None:
            return validation.error_message or "format validation failed"
        if status is FileStatus.CORRUPTED_SIZE:
            return "file size differs from the recorded baseline"
        if status is FileStatus.CORRUPTED_CHECKSUM:
            return "file checksum differs from the recorded baseline"
        if status is FileStatus.SUSPECTED_RANSOMWARE:
            return "file entropy is unusually high for this file type"
        if status is FileStatus.MISSING:
            return "file not found"
        if status is FileStatus.UNREADABLE:
            return "file is unreadable"
        return None

    def _is_probably_ransomware(self, path: Path, metrics: FileMetrics) -> bool:
        if not self._config.detect_ransomware:
            return False

        if metrics.size_bytes == 0 or metrics.shannon_entropy < self._config.entropy_threshold:
            return False

        extension = path.suffix.lower()
        if extension in _SUSPICIOUS_RANSOMWARE_EXTENSIONS:
            return True

        if extension in _HIGH_ENTROPY_SAFE_EXTENSIONS:
            return False

        return True

    def _determine_status(
        self,
        path: Path,
        metrics: FileMetrics,
        record: FileRecord | None,
        validation: FormatValidationResult,
    ) -> FileStatus:
        if not validation.is_valid:
            return FileStatus.CORRUPTED_FORMAT

        if self._is_probably_ransomware(path, metrics):
            return FileStatus.SUSPECTED_RANSOMWARE

        if record is None:
            return FileStatus.NEW_FILE

        if record.size_bytes != metrics.size_bytes:
            return FileStatus.CORRUPTED_SIZE

        if record.checksum != metrics.checksum:
            return FileStatus.CORRUPTED_CHECKSUM

        return FileStatus.VALID

    def analyze_file(self, target_path: FilePath) -> FileAnalysisResult:
        path = Path(target_path).expanduser().resolve()

        if self._cancel_event.is_set():
            raise ScanCancelledError(f"scan cancelled before analyzing {path}")

        if not path.exists():
            return FileAnalysisResult(
                file_path=str(path),
                status=FileStatus.MISSING,
                file_type=self._guess_file_type(path, None),
                error_message=self._status_message(FileStatus.MISSING),
            )

        if not path.is_file():
            return FileAnalysisResult(
                file_path=str(path),
                status=FileStatus.UNREADABLE,
                file_type=self._guess_file_type(path, None),
                error_message="target is not a regular file",
            )

        try:
            metrics = self._calculator.calculate(path, self._cancel_event)

            if self._cancel_event.is_set():
                raise ScanCancelledError(f"scan cancelled after reading metrics for {path}")

            validation = self._format_validator.validate(path)
            file_type = self._guess_file_type(path, validation)
            record = self._repo.get_record(str(path))
            status = self._determine_status(path, metrics, record, validation)

            new_record = FileRecord(
                path_str=str(path),
                size_bytes=metrics.size_bytes,
                checksum=metrics.checksum,
                last_modified_ts=path.stat().st_mtime,
                is_corrupted=status not in {FileStatus.VALID, FileStatus.NEW_FILE},
                shannon_entropy=metrics.shannon_entropy,
                file_type=file_type,
            )
            self._repo.upsert_record(new_record)

            return FileAnalysisResult(
                file_path=str(path),
                status=status,
                metrics=metrics,
                file_type=file_type,
                error_message=self._status_message(status, validation),
                format_validation=validation,
            )

        except ScanCancelledError:
            raise
        except FileAccessError as exc:
            self._logger.error("%s", exc)
            return FileAnalysisResult(
                file_path=str(path),
                status=FileStatus.UNREADABLE,
                file_type=self._guess_file_type(path, None),
                error_message=str(exc),
            )
        except DatabaseConcurrencyError as exc:
            self._logger.error("%s", exc)
            return FileAnalysisResult(
                file_path=str(path),
                status=FileStatus.UNREADABLE,
                file_type=self._guess_file_type(path, None),
                error_message=str(exc),
            )
        except Exception:
            self._logger.exception("unexpected failure while analyzing %s", path)
            return FileAnalysisResult(
                file_path=str(path),
                status=FileStatus.UNREADABLE,
                file_type=self._guess_file_type(path, None),
                error_message="internal analysis fault",
            )

    def _collect_files(self, directory: Path, recursive: bool) -> tuple[Path, ...]:
        quarantine_dir = Path(self._config.quarantine_dir).expanduser().resolve()

        def include_name(name: str) -> bool:
            return self._config.include_hidden_files or not name.startswith(".")

        files: list[Path] = []

        if recursive:
            def onerror(exc: OSError) -> None:
                self._logger.warning("skipping inaccessible path during scan: %s", exc)

            for root, dirnames, filenames in os.walk(
                directory,
                topdown=True,
                followlinks=self._config.follow_symlinks,
                onerror=onerror,
            ):
                root_path = Path(root)

                if self._config.exclude_quarantine_from_scans:
                    dirnames[:] = [
                        name for name in dirnames
                        if (root_path / name).resolve() != quarantine_dir
                    ]

                dirnames[:] = [name for name in dirnames if include_name(name)]

                for filename in filenames:
                    if not include_name(filename):
                        continue

                    candidate = (root_path / filename).resolve()
                    try:
                        if candidate.is_file():
                            files.append(candidate)
                    except OSError:
                        self._logger.warning("skipping inaccessible file: %s", candidate)
        else:
            for candidate in sorted(directory.iterdir(), key=lambda item: str(item).casefold()):
                if not include_name(candidate.name):
                    continue
                try:
                    if candidate.is_file():
                        files.append(candidate.resolve())
                except OSError:
                    self._logger.warning("skipping inaccessible file: %s", candidate)

        return tuple(sorted(files, key=lambda item: str(item).casefold()))

    def scan_directory(self, directory_path: FilePath, recursive: bool = True) -> tuple[FileAnalysisResult, ...]:
        directory = Path(directory_path).expanduser().resolve()
        if not directory.is_dir():
            raise FileAccessError(f"invalid directory: {directory}")

        self.clear_stop_request()
        files = self._collect_files(directory, recursive)
        if not files:
            return ()

        results: list[FileAnalysisResult] = []
        futures: dict[Future[FileAnalysisResult], Path] = {}

        executor = ThreadPoolExecutor(max_workers=max(1, self._config.max_workers))
        try:
            for file_path in files:
                if self._cancel_event.is_set():
                    break
                futures[executor.submit(self.analyze_file, file_path)] = file_path

            for future in as_completed(futures):
                if self._cancel_event.is_set():
                    # If cancellation was requested, break early
                    break
                    
                try:
                    result = future.result()
                except (ScanCancelledError, CancelledError):
                    # Handle both custom cancellation and standard cancellation
                    # Don't log these as errors - they're expected during cancellation
                    continue
                except Exception as exc:
                    file_path = futures[future]
                    # Only log as error if not cancelled
                    if not self._cancel_event.is_set():
                        self._logger.exception("executor failure while analyzing %s: %s", file_path, exc)
                else:
                    results.append(result)

            # Cancel any remaining futures if cancellation was requested
            if self._cancel_event.is_set():
                for pending_future in futures:
                    pending_future.cancel()
        finally:
            executor.shutdown(wait=True, cancel_futures=True)

        return tuple(sorted(results, key=lambda item: item.file_path.casefold()))

    def quarantine_file(self, target_path: FilePath) -> bool:
        path = Path(target_path).expanduser().resolve()
        quarantine_dir = Path(self._config.quarantine_dir).expanduser().resolve()

        if not path.exists() or not path.is_file():
            return False

        quarantine_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        destination = quarantine_dir / f"{path.stem}_{timestamp}{path.suffix}.quarantine"

        try:
            shutil.move(str(path), str(destination))
            self._repo.log_quarantine(str(path), str(destination), "Automated Quarantine")
            self._logger.info("quarantined %s -> %s", path.name, destination.name)
            return True
        except OSError as exc:
            self._logger.error("quarantine failed for %s: %s", path, exc)
            raise QuarantineError(f"failed to isolate {path}") from exc


# ==============================================================================
# 7. PUBLIC FACADE
# ==============================================================================

def create_analyzer(config: AnalyzerConfig | None = None) -> CorruptionEngine:
    cfg = config or AnalyzerConfig()
    repository = SQLiteMetadataRepo(cfg)
    calculator = AdvancedFileMetricsCalculator(cfg)
    format_validator = BuiltinFormatValidator()
    return CorruptionEngine(cfg, repository, calculator, format_validator)


class CorruptionDetector:
    """GUI-friendly facade."""

    def __init__(self, config: AnalyzerConfig | None = None):
        self._config = config or AnalyzerConfig()
        self._engine = create_analyzer(self._config)

    @property
    def database_path(self) -> str:
        return self._config.db_path

    @property
    def quarantine_dir(self) -> str:
        return self._config.quarantine_dir

    def _init_database(self) -> None:
        self._engine._repo.initialize()  # type: ignore[attr-defined]

    def analyze_file(self, target_path: FilePath) -> FileAnalysisResult:
        return self._engine.analyze_file(target_path)

    def scan_directory(self, directory_path: FilePath, recursive: bool = True) -> tuple[FileAnalysisResult, ...]:
        return self._engine.scan_directory(directory_path, recursive)

    def quarantine_file(self, target_path: FilePath) -> bool:
        return self._engine.quarantine_file(target_path)

    def request_stop(self) -> None:
        self._engine.request_stop()

    def cancel_scan(self) -> None:
        self._engine.cancel_scan()

    def stop_scan(self) -> None:
        self._engine.request_stop()

    def get_library_status(self) -> dict[str, bool]:
        return {
            "Built-in Validator": True,
            "Pillow (Images)": importlib.util.find_spec("PIL") is not None,
            "PyPDF2 (PDFs)": importlib.util.find_spec("PyPDF2") is not None,
            "FFmpeg (Media)": shutil.which("ffmpeg") is not None or shutil.which("ffprobe") is not None,
            "python-docx (Word)": importlib.util.find_spec("docx") is not None,
            "openpyxl (Excel)": importlib.util.find_spec("openpyxl") is not None,
        }


# ==============================================================================
# 8. TESTS
# ==============================================================================

class TestCoreAnalyzer(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root_dir = Path(self.temp_dir.name)

        self.db_path = self.root_dir / "test.db"
        self.quarantine_dir = self.root_dir / "quarantine"

        self.config = AnalyzerConfig(
            db_path=str(self.db_path),
            quarantine_dir=str(self.quarantine_dir),
            entropy_threshold=7.90,
            max_workers=max(1, min(32, (os.cpu_count() or 1) * 2)),  # Optimized thread count
        )
        self.detector = CorruptionDetector(self.config)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write_bytes(self, relative_path: str, content: bytes) -> Path:
        path = self.root_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_new_file_analysis(self) -> None:
        path = self._write_bytes("hello.txt", b"Hello, World!")
        result = self.detector.analyze_file(path)

        self.assertEqual(result.status, FileStatus.NEW_FILE)
        self.assertFalse(result.is_corrupted)
        self.assertEqual(result.file_size, 13)
        self.assertEqual(result.file_type, "Text")
        self.assertTrue(bool(result.checksum))

    def test_detect_checksum_change_same_size(self) -> None:
        path = self._write_bytes("same_size.txt", b"ABCDE")
        first_result = self.detector.analyze_file(path)
        self.assertEqual(first_result.status, FileStatus.NEW_FILE)

        path.write_bytes(b"12345")
        second_result = self.detector.analyze_file(path)

        self.assertEqual(second_result.status, FileStatus.CORRUPTED_CHECKSUM)
        self.assertTrue(second_result.is_corrupted)

    def test_detect_size_change(self) -> None:
        path = self._write_bytes("size_change.txt", b"small")
        self.detector.analyze_file(path)

        path.write_bytes(b"this content is longer")
        result = self.detector.analyze_file(path)

        self.assertEqual(result.status, FileStatus.CORRUPTED_SIZE)
        self.assertTrue(result.is_corrupted)

    def test_detect_format_corruption(self) -> None:
        path = self._write_bytes("fake.png", b"not a real png")
        result = self.detector.analyze_file(path)

        self.assertEqual(result.status, FileStatus.CORRUPTED_FORMAT)
        self.assertTrue(result.is_corrupted)
        self.assertIsNotNone(result.format_validation)
        self.assertFalse(result.format_validation.is_valid)

    def test_ransomware_entropy_detection(self) -> None:
        path = self._write_bytes("payload.locked", os.urandom(16 * 1024))
        result = self.detector.analyze_file(path)

        self.assertEqual(result.status, FileStatus.SUSPECTED_RANSOMWARE)
        self.assertTrue(result.is_corrupted)
        self.assertGreater(result.shannon_entropy, 7.90)

    def test_concurrent_directory_scan(self) -> None:
        for index in range(20):
            self._write_bytes(f"files/file_{index}.txt", f"content-{index}".encode("utf-8"))

        results = self.detector.scan_directory(self.root_dir, recursive=True)

        self.assertEqual(len(results), 20)
        self.assertTrue(all(result.status == FileStatus.NEW_FILE for result in results))
        self.assertEqual(list(results), sorted(results, key=lambda item: item.file_path.casefold()))

    def test_quarantine_file(self) -> None:
        path = self._write_bytes("danger.bin", b"payload")
        success = self.detector.quarantine_file(path)

        self.assertTrue(success)
        self.assertFalse(path.exists())

        quarantined_files = list(self.quarantine_dir.glob("danger_*.quarantine"))
        self.assertEqual(len(quarantined_files), 1)

    def test_database_record_persisted(self) -> None:
        path = self._write_bytes("persist.txt", b"persist me")
        self.detector.analyze_file(path)

        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute(
                "SELECT file_path, size_bytes, checksum, is_corrupted FROM file_metadata"
            ).fetchone()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], str(path.resolve()))
        self.assertEqual(row[1], len(b"persist me"))
        self.assertFalse(bool(row[3]))

    def test_get_library_status(self) -> None:
        status = self.detector.get_library_status()

        self.assertIn("Built-in Validator", status)
        self.assertTrue(status["Built-in Validator"])

    def test_empty_scan_result(self) -> None:
        empty_dir = self.root_dir / "empty"
        empty_dir.mkdir()

        results = self.detector.scan_directory(empty_dir)
        self.assertEqual(results, ())

    def test_excludes_quarantine_directory_from_scan(self) -> None:
        payload = self._write_bytes("keep.txt", b"keep me")
        self.assertTrue(payload.exists())

        quarantined = self.quarantine_dir / "hidden.txt"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        quarantined.write_bytes(b"do not scan")

        results = self.detector.scan_directory(self.root_dir)
        scanned_paths = {result.file_path for result in results}

        self.assertIn(str(payload.resolve()), scanned_paths)
        self.assertNotIn(str(quarantined.resolve()), scanned_paths)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    unittest.main(verbosity=2)