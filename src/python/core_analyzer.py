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
import json
import logging
import math
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from concurrent.futures import Future, ThreadPoolExecutor, as_completed, CancelledError
from dataclasses import dataclass, field
from datetime import datetime, timezone
from contextlib import contextmanager
from enum import Enum, auto
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Callable, Iterator, Mapping, Optional, Protocol, Sequence, TypeVar

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
    max_workers: int = max(1, min(32, (os.cpu_count() or 1) * 2))
    detect_ransomware: bool = True
    entropy_threshold: float = 7.95
    db_busy_timeout_ms: int = 5_000
    db_retry_attempts: int = 6
    db_retry_backoff_seconds: float = 0.05
    exclude_quarantine_from_scans: bool = True
    follow_symlinks: bool = False
    include_hidden_files: bool = True
    # Use the library-backed validators (Pillow / PyPDF2 / python-docx /
    # openpyxl / ffprobe) when importable. Far more accurate than header
    # checks; set False for a pure header/CRC pass.
    advanced_validators: bool = True
    # Treat a file's own entropy as suspicious only when it has *changed*
    # relative to the recorded baseline by at least this many bits/byte.
    entropy_jump_threshold: float = 2.0


# ------------------------------------------------------------------------------
# Optional configuration file support (config/cie_config.json)
# ------------------------------------------------------------------------------

DEFAULT_CONFIG_RELATIVE_PATH = Path("config") / "cie_config.json"


def load_config_file(path: FilePath | None = None) -> dict[str, Any]:
    """Read config/cie_config.json.

    Returns {} when the file is absent or unreadable: configuration is a
    convenience, never a hard requirement.
    """
    config_path = Path(path) if path is not None else DEFAULT_CONFIG_RELATIVE_PATH
    if not config_path.exists():
        return {}

    try:
        with config_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        LOGGER.warning("ignoring unreadable config file %s: %s", config_path, exc)
        return {}

    return payload if isinstance(payload, dict) else {}


def config_from_mapping(data: Mapping[str, Any] | None, **overrides: Any) -> "AnalyzerConfig":
    """Build an AnalyzerConfig from a config-file mapping plus explicit overrides.

    Explicit overrides (CLI flags) always win; entries set to None are ignored
    so callers can pass argparse defaults of None safely.
    """
    payload = dict(data or {})
    scanning = payload.get("scanning", {}) or {}
    database = payload.get("database", {}) or {}
    quarantine = payload.get("quarantine", {}) or {}
    detection = payload.get("detection", {}) or {}
    file_types = payload.get("file_types", {}) or {}

    defaults: dict[str, Any] = {}

    if database.get("path"):
        defaults["db_path"] = str(database["path"])
    if quarantine.get("directory"):
        defaults["quarantine_dir"] = str(quarantine["directory"])
    if scanning.get("chunk_size"):
        chunk_size = int(scanning["chunk_size"])
        if chunk_size > 0:
            defaults["chunk_size"] = chunk_size
        else:
            LOGGER.warning("ignoring non-positive chunk_size %s in config", chunk_size)
    if scanning.get("skip_hidden_files") is not None:
        defaults["include_hidden_files"] = not bool(scanning["skip_hidden_files"])
    if detection.get("checksum_algorithm"):
        defaults["hash_algorithm"] = str(detection["checksum_algorithm"])
    if detection.get("structure_validation_enabled") is not None:
        defaults["advanced_validators"] = bool(detection["structure_validation_enabled"])
    if detection.get("ransomware_detection_enabled") is not None:
        defaults["detect_ransomware"] = bool(detection["ransomware_detection_enabled"])
    if detection.get("entropy_threshold") is not None:
        defaults["entropy_threshold"] = float(detection["entropy_threshold"])
    if detection.get("entropy_jump_threshold") is not None:
        defaults["entropy_jump_threshold"] = float(detection["entropy_jump_threshold"])
    if scanning.get("follow_symlinks") is not None:
        defaults["follow_symlinks"] = bool(scanning["follow_symlinks"])
    if scanning.get("max_workers"):
        # 0 (or negative) means "pick automatically", never a zero-sized pool.
        max_workers = int(scanning["max_workers"])
        if max_workers > 0:
            defaults["max_workers"] = max_workers
        else:
            LOGGER.warning("ignoring max_workers=%s in config (using automatic)", max_workers)

    safe_overrides = {key: value for key, value in overrides.items() if value is not None}
    defaults.update(safe_overrides)

    # Unknown keys are ignored rather than blowing up on a hand-edited file.
    allowed = {field_name for field_name in AnalyzerConfig.__dataclass_fields__}
    return AnalyzerConfig(**{key: value for key, value in defaults.items() if key in allowed})


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
    # healthy
    VALID = auto()
    NEW_FILE = auto()
    # corruption (is_corrupted == True -> eligible for quarantine)
    CORRUPTED_SIZE = auto()
    CORRUPTED_CHECKSUM = auto()
    CORRUPTED_FORMAT = auto()
    SUSPECTED_RANSOMWARE = auto()
    # problems that are NOT corruption: reported, never auto-quarantined
    SUSPICIOUS_EMPTY = auto()
    SUSPICIOUS_HIGH_ENTROPY = auto()
    MISSING = auto()
    UNREADABLE = auto()
    ERROR = auto()


#: statuses that count as corruption and may be quarantined
CORRUPT_STATUSES = frozenset({
    FileStatus.CORRUPTED_SIZE,
    FileStatus.CORRUPTED_CHECKSUM,
    FileStatus.CORRUPTED_FORMAT,
    FileStatus.SUSPECTED_RANSOMWARE,
})

#: statuses that mean "we could not analyse this file" (scan is incomplete)
FAULT_STATUSES = frozenset({FileStatus.UNREADABLE, FileStatus.ERROR})

#: statuses worth surfacing as warnings without treating them as damage
WARNING_STATUSES = frozenset({FileStatus.SUSPICIOUS_EMPTY, FileStatus.SUSPICIOUS_HIGH_ENTROPY})


@dataclass(frozen=True, slots=True)
class FileMetrics:
    size_bytes: int
    checksum: ChecksumStr
    shannon_entropy: float


@dataclass(frozen=True, slots=True)
class FileRecord:
    """Baseline for one file.

    ``size_bytes``/``checksum``/``shannon_entropy`` are the *trusted baseline*
    captured before any damage was seen: they are never overwritten while the
    file is corrupted, which is what makes a detection stick across scans.
    """

    path_str: str
    size_bytes: int
    checksum: ChecksumStr
    last_modified_ts: float
    is_corrupted: bool
    shannon_entropy: float = 0.0
    file_type: str | None = None
    first_seen_ts: float | None = None
    first_corrupt_ts: float | None = None
    last_status: str | None = None
    last_seen_ts: float | None = None


@dataclass(frozen=True, slots=True)
class FormatValidationResult:
    is_valid: bool
    format_name: str | None = None
    error_message: str | None = None
    format_info: Mapping[str, Any] = field(default_factory=dict)
    corruption_details: tuple[str, ...] = field(default_factory=tuple)
    #: True when a validator actually inspected the content. False means the
    #: extension has no validator, so `is_valid` carries no information.
    checked: bool = False


@dataclass(frozen=True, slots=True)
class QuarantineEntry:
    """One row of the quarantine log."""

    entry_id: int
    original_path: str
    quarantine_path: str
    reason: str
    quarantined_at: datetime | None = None
    restored_at: datetime | None = None

    @property
    def is_restored(self) -> bool:
        return self.restored_at is not None


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_timestamp(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class FileAnalysisResult:
    file_path: str
    status: FileStatus
    metrics: FileMetrics | None = None
    file_type: str | None = None
    error_message: str | None = None
    format_validation: FormatValidationResult | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    #: when this file first entered a corrupted state (from the database)
    first_corrupt_at: datetime | None = None
    #: baseline the file is being compared against, when one is known
    baseline_size_bytes: int | None = None
    #: non-corrupt advisories (e.g. "empty file", "high entropy")
    warnings: tuple[str, ...] = ()

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
        return self.status in CORRUPT_STATUSES

    @property
    def has_fault(self) -> bool:
        """True when the file could not be analysed (scan is incomplete)."""
        return self.status in FAULT_STATUSES

    @property
    def is_warning(self) -> bool:
        return self.status in WARNING_STATUSES or bool(self.warnings)

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
    def upsert_record(self, record: FileRecord, *, update_baseline: bool = True) -> None: ...
    def log_quarantine(self, original_path: str, quarantine_path: str, reason: str) -> None: ...
    def list_quarantine(self, *, include_restored: bool = False) -> tuple[QuarantineEntry, ...]: ...
    def find_quarantine_entry(self, quarantine_path: str) -> QuarantineEntry | None: ...
    def mark_restored(self, entry_id: int, restored_path: str) -> None: ...


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

        # An in-memory database only survives as long as its connection, and
        # this repository opens a connection per operation. Keep one shared
        # connection alive for the lifetime of the instance.
        self._memory_connection: sqlite3.Connection | None = None
        self._memory_lock = threading.Lock()
        self._is_memory = self._db_path in {":memory:", ""} or self._db_path.startswith(
            "file::memory:"
        )

        if not self._is_memory:
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
        connection.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms};")
        if not self._is_memory:
            connection.execute("PRAGMA journal_mode=WAL;")
        connection.execute("PRAGMA synchronous=NORMAL;")
        connection.execute("PRAGMA foreign_keys=ON;")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection; for :memory: databases reuse one instance.

        A plain ``sqlite3.connect(":memory:")`` per call would hand every
        operation an empty database, so every statement after ``initialize()``
        failed with "no such table". Same effect under test fixtures.
        """
        if not self._is_memory:
            with self._get_connection() as connection:
                yield connection
            return

        with self._memory_lock:
            if self._memory_connection is None:
                self._memory_connection = self._get_connection()
            yield self._memory_connection

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
                with self._connection() as connection:
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
                            analysis_date TEXT NOT NULL,
                            first_seen REAL,
                            first_corrupt REAL,
                            last_status TEXT,
                            last_seen REAL
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
                            action_date TEXT NOT NULL,
                            restored_at TEXT
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

        # Not inside the lock above: _migrate() takes it itself, and
        # threading.Lock is not reentrant.
        self._migrate()

    #: columns added after the v2.0 schema; name -> DDL fragment
    _FILE_COLUMNS: Mapping[str, str] = {
        "first_seen": "REAL",
        "first_corrupt": "REAL",
        "last_status": "TEXT",
        "last_seen": "REAL",
    }

    _QUARANTINE_COLUMNS: Mapping[str, str] = {
        "restored_at": "TEXT",
    }

    def _migrate(self) -> None:
        """Add columns introduced after the original schema (existing DB files)."""
        with self._schema_lock:
            def operation() -> None:
                with self._connection() as connection:
                    for table, columns in (
                        ("file_metadata", self._FILE_COLUMNS),
                        ("quarantine_log", self._QUARANTINE_COLUMNS),
                    ):
                        existing = {
                            str(row["name"])
                            for row in connection.execute(f"PRAGMA table_info({table})")
                        }
                        for column, column_type in columns.items():
                            if column in existing:
                                continue
                            connection.execute(
                                f"ALTER TABLE {table} ADD COLUMN {column} {column_type}"
                            )
                            self._logger.debug("migrated %s: added %s", table, column)

            self._run_with_retry(operation)

    _logger = logging.getLogger("SQLiteMetadataRepo")

    def get_record(self, path: str) -> FileRecord | None:
        def operation() -> FileRecord | None:
            with self._connection() as connection:
                row = connection.execute(
                    """
                    SELECT
                        file_path,
                        size_bytes,
                        checksum,
                        last_modified,
                        is_corrupted,
                        shannon_entropy,
                        file_type,
                        first_seen,
                        first_corrupt,
                        last_status,
                        last_seen
                    FROM file_metadata
                    WHERE file_path = ?
                    """,
                    (path,),
                ).fetchone()

                if row is None:
                    return None

                keys = row.keys()
                return FileRecord(
                    path_str=str(row["file_path"]),
                    size_bytes=int(row["size_bytes"]),
                    checksum=str(row["checksum"]),
                    last_modified_ts=float(row["last_modified"]),
                    is_corrupted=bool(row["is_corrupted"]),
                    shannon_entropy=float(row["shannon_entropy"]),
                    file_type=row["file_type"],
                    first_seen_ts=_optional_float(row["first_seen"]) if "first_seen" in keys else None,
                    first_corrupt_ts=_optional_float(row["first_corrupt"]) if "first_corrupt" in keys else None,
                    last_status=row["last_status"] if "last_status" in keys else None,
                    last_seen_ts=_optional_float(row["last_seen"]) if "last_seen" in keys else None,
                )

        return self._run_with_retry(operation)

    def upsert_record(self, record: FileRecord, *, update_baseline: bool = True) -> None:
        """Persist a record.

        ``update_baseline=False`` keeps the stored size/checksum/entropy intact
        and only refreshes bookkeeping columns. The engine uses that when a file
        is damaged, so the original baseline survives and the damage is still
        detectable on the next scan.
        """
        def operation() -> None:
            with self._connection() as connection:
                now = datetime.now(timezone.utc).isoformat()
                connection.execute(
                    """
                    INSERT INTO file_metadata (
                        file_path, size_bytes, checksum, last_modified,
                        is_corrupted, shannon_entropy, file_type, analysis_date,
                        first_seen, first_corrupt, last_status, last_seen
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(file_path) DO UPDATE SET
                        size_bytes     = CASE WHEN ? THEN excluded.size_bytes     ELSE file_metadata.size_bytes     END,
                        checksum       = CASE WHEN ? THEN excluded.checksum       ELSE file_metadata.checksum       END,
                        shannon_entropy= CASE WHEN ? THEN excluded.shannon_entropy ELSE file_metadata.shannon_entropy END,
                        last_modified  = excluded.last_modified,
                        is_corrupted   = excluded.is_corrupted,
                        file_type      = excluded.file_type,
                        analysis_date  = excluded.analysis_date,
                        first_seen     = COALESCE(file_metadata.first_seen, excluded.first_seen),
                        first_corrupt  = COALESCE(excluded.first_corrupt, file_metadata.first_corrupt),
                        last_status    = excluded.last_status,
                        last_seen      = excluded.last_seen
                    """,
                    (
                        record.path_str,
                        record.size_bytes,
                        record.checksum,
                        record.last_modified_ts,
                        int(record.is_corrupted),
                        record.shannon_entropy,
                        record.file_type,
                        now,
                        record.first_seen_ts or time.time(),
                        record.first_corrupt_ts,
                        record.last_status,
                        record.last_seen_ts or time.time(),
                        int(update_baseline),
                        int(update_baseline),
                        int(update_baseline),
                    ),
                )

        self._run_with_retry(operation)

    def log_quarantine(self, original_path: str, quarantine_path: str, reason: str) -> None:
        def operation() -> None:
            with self._connection() as connection:
                connection.execute(
                    """
                    INSERT INTO quarantine_log (
                        original_path, quarantine_path, reason, action_date, restored_at
                    )
                    VALUES (?, ?, ?, ?, NULL)
                    """,
                    (
                        original_path,
                        quarantine_path,
                        reason,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )

        self._run_with_retry(operation)

    def list_quarantine(self, *, include_restored: bool = False) -> tuple[QuarantineEntry, ...]:
        def operation() -> tuple[QuarantineEntry, ...]:
            with self._connection() as connection:
                query = """
                    SELECT id, original_path, quarantine_path, reason, action_date, restored_at
                    FROM quarantine_log
                """
                if not include_restored:
                    query += " WHERE restored_at IS NULL"
                query += " ORDER BY action_date DESC, id DESC"

                return tuple(
                    QuarantineEntry(
                        entry_id=int(row["id"]),
                        original_path=str(row["original_path"]),
                        quarantine_path=str(row["quarantine_path"]),
                        reason=str(row["reason"]),
                        quarantined_at=_parse_timestamp(row["action_date"]),
                        restored_at=_parse_timestamp(row["restored_at"]),
                    )
                    for row in connection.execute(query)
                )

        return self._run_with_retry(operation)

    def find_quarantine_entry(self, quarantine_path: str) -> QuarantineEntry | None:
        target = str(Path(quarantine_path).expanduser().resolve())
        for entry in self.list_quarantine(include_restored=False):
            if str(Path(entry.quarantine_path).expanduser().resolve()) == target:
                return entry
        return None

    def mark_restored(self, entry_id: int, restored_path: str) -> None:
        """Record that a quarantined file was put back."""
        def operation() -> None:
            with self._connection() as connection:
                connection.execute(
                    """
                    UPDATE quarantine_log
                    SET restored_at = ?
                    WHERE id = ?
                    """,
                    (datetime.now(timezone.utc).isoformat(), int(entry_id)),
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


def _structural_validators() -> Any | None:
    """Load the stdlib-only validators from format_validators.py.

    Keeping one implementation of each structural check (and layering optional
    third-party libraries on top) instead of maintaining three divergent
    magic-byte tables.
    """
    try:
        module = load_sibling_module("format_validators")
        ArchiveValidator = module.ArchiveValidator
        DocumentValidator = module.DocumentValidator
        IsoBmffValidator = module.IsoBmffValidator
        JpegValidator = module.JpegValidator
        MagicSignatureValidator = module.MagicSignatureValidator
        PDFValidator = module.PDFValidator
    except Exception as exc:  # pragma: no cover - layout dependent
        LOGGER.warning("structural validators unavailable (%s)", exc)
        return None

    return SimpleNamespace(
        archive=ArchiveValidator(),
        document=DocumentValidator(),
        isobmff=IsoBmffValidator(),
        jpeg=JpegValidator(),
        magic=MagicSignatureValidator(),
        pdf=PDFValidator(),
    )


class BuiltinFormatValidator(IFormatValidator):
    """Dependency-free structural validation (signatures, headers, containers).

    Used when the library-backed validators are unavailable or disabled. It
    never returns a false "invalid" for a file it cannot inspect: unknown
    extensions are reported as unchecked.
    """

    _FORMAT_NAMES: dict[str, str] = {
        ".pdf": "PDF", ".png": "PNG", ".jpg": "JPEG", ".jpeg": "JPEG",
        ".gif": "GIF", ".zip": "ZIP", ".docx": "DOCX", ".xlsx": "XLSX",
        ".exe": "PE", ".elf": "ELF", ".mp4": "MP4", ".txt": "Text",
        ".json": "JSON", ".xml": "XML", ".csv": "CSV",
    }

    _ZIP_FAMILY = {".zip", ".docx", ".xlsx"}
    _ISOBMFF_FAMILY = {".mp4", ".m4a", ".m4v", ".mov", ".3gp", ".heic", ".heif", ".avif"}

    #: minimal fallback used only if format_validators.py cannot be imported
    _FALLBACK_SIGNATURES: dict[str, tuple[tuple[int, bytes], ...]] = {
        ".png": ((0, b"\x89PNG\r\n\x1a\n"),),
        ".jpg": ((0, b"\xff\xd8\xff"),),
        ".jpeg": ((0, b"\xff\xd8\xff"),),
        ".gif": ((0, b"GIF87a"), (0, b"GIF89a")),
        ".exe": ((0, b"MZ"),),
        ".elf": ((0, b"\x7fELF"),),
    }

    def __init__(self) -> None:
        self._structural = _structural_validators()

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def _to_result(result: Any, format_name: str, extension: str) -> FormatValidationResult:
        """Convert a format_validators.ValidationResult into our result type."""
        info = dict(getattr(result, "format_info", {}) or {})
        return FormatValidationResult(
            is_valid=bool(result.is_valid),
            format_name=getattr(result, "format_name", None) or format_name,
            error_message=getattr(result, "error_message", None),
            format_info=info,
            corruption_details=tuple(getattr(result, "corruption_details", ()) or ()),
            checked=bool(info.get("checked", False)),
        )

    def _unchecked(self, extension: str, format_name: str, reason: str) -> FormatValidationResult:
        return FormatValidationResult(
            is_valid=True,
            format_name=format_name,
            format_info={
                "extension": extension or "<none>",
                "validator": "none",
                "checked": False,
                "reason": reason,
            },
            checked=False,
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

    # -- public API ------------------------------------------------------

    def validate(self, path: Path) -> FormatValidationResult:
        extension = path.suffix.lower()
        format_name = self._FORMAT_NAMES.get(extension) or (
            extension.lstrip(".").upper() if extension else "Unknown"
        )

        if self._structural is not None:
            return self._validate_structural(path, extension, format_name)
        return self._validate_fallback(path, extension, format_name)

    def _validate_structural(
        self,
        path: Path,
        extension: str,
        format_name: str,
    ) -> FormatValidationResult:
        structural = self._structural
        try:
            if extension in self._ZIP_FAMILY:
                if extension == ".docx":
                    result = structural.document.validate_docx(path)
                elif extension == ".xlsx":
                    result = structural.document.validate_xlsx(path)
                else:
                    result = structural.archive.validate(path)
                return self._to_result(result, format_name, extension)

            if extension == ".pdf":
                return self._to_result(structural.pdf.validate(path), format_name, extension)

            if extension in {".jpg", ".jpeg"}:
                return self._to_result(structural.jpeg.validate(path), format_name, extension)

            if extension in self._ISOBMFF_FAMILY:
                return self._to_result(structural.isobmff.validate(path), format_name, extension)

            if extension in structural.magic._SIGNATURES:
                return self._to_result(structural.magic.validate(path), format_name, extension)

        except FileAccessError:
            raise
        except Exception as exc:
            LOGGER.exception("structural validation failed for %s", path)
            return FormatValidationResult(
                is_valid=True,
                format_name=format_name,
                format_info={"extension": extension, "validator": "structural", "checked": False},
                error_message=f"validation skipped: {exc}",
                checked=False,
            )

        return self._unchecked(extension, format_name, "no structural validator for this type")

    def _validate_fallback(
        self,
        path: Path,
        extension: str,
        format_name: str,
    ) -> FormatValidationResult:
        """Last-resort checks used only if format_validators.py is missing."""
        if extension == ".pdf":
            prefix = self._read_prefix(path, 8)
            suffix = self._read_suffix(path, 2048)
            issues = []
            if not prefix.startswith(b"%PDF-"):
                issues.append("missing PDF header")
            if b"%%EOF" not in suffix:
                issues.append("missing PDF EOF marker")
            return FormatValidationResult(
                is_valid=not issues,
                format_name=format_name,
                error_message="invalid PDF structure" if issues else None,
                format_info={"validator": "pdf", "extension": ".pdf", "checked": True},
                corruption_details=tuple(issues),
                checked=True,
            )

        if extension in self._FALLBACK_SIGNATURES:
            checks = self._FALLBACK_SIGNATURES[extension]
            needed = max(offset + len(sig) for offset, sig in checks)
            prefix = self._read_prefix(path, needed)
            for offset, signature in checks:
                if prefix[offset:offset + len(signature)] == signature:
                    return FormatValidationResult(
                        is_valid=True,
                        format_name=format_name,
                        format_info={"extension": extension, "validator": "magic", "checked": True},
                        checked=True,
                    )
            return FormatValidationResult(
                is_valid=False,
                format_name=format_name,
                error_message=f"{format_name} signature mismatch",
                format_info={"extension": extension, "validator": "magic", "checked": True},
                corruption_details=(f"expected valid {format_name} file signature",),
                checked=True,
            )

        return self._unchecked(extension, format_name, "no validator available")


# ==============================================================================
# 6. CORE APPLICATION SERVICE
# ==============================================================================

#: Formats that are legitimately high-entropy (compressed or already
#: encrypted). Entropy is not evidence of damage for any of these.
_HIGH_ENTROPY_SAFE_EXTENSIONS = {
    # archives / containers
    ".zip", ".zipx", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".zst", ".lz4", ".cab", ".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".qcow2",
    # office / OOXML / ODF (ZIP containers)
    ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".odt", ".ods", ".odp",
    # packages
    ".jar", ".apk", ".aab", ".war", ".nupkg", ".whl", ".deb", ".rpm", ".msi",
    # images / video / audio that are already compressed
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic", ".heif", ".avif",
    ".mp4", ".m4a", ".m4v", ".mov", ".mkv", ".webm", ".avi", ".wmv", ".flv",
    ".mp3", ".aac", ".ogg", ".opus", ".wav", ".flac", ".alac", ".wma",
    # already-encrypted material
    ".gpg", ".pgp", ".age", ".kdbx", ".kdb", ".p12", ".pfx", ".jks", ".keystore",
    ".pem", ".key", ".crt", ".cer", ".der", ".7z.aes",
    ".hc", ".tc", ".vera",
    # compiled / packaged binaries and data
    ".pyc", ".pyo", ".class", ".so", ".dll", ".exe", ".bin", ".dat", ".pak",
    ".sqlite", ".sqlite3", ".db", ".mdb", ".torrent", ".pdf", ".ps", ".eps",
}

#: Extensions used by ransomware families when they rename ciphertext.
_SUSPICIOUS_RANSOMWARE_EXTENSIONS = {
    ".locked", ".locky", ".encrypted", ".enc", ".crypt", ".cipher", ".crypto",
    ".wncry", ".wcry", ".wncrypt", ".zepto", ".cerber", ".ryk", ".ryuk",
    ".conti", ".lockbit", ".revil", ".phobos", ".djvu", ".stop", ".makop",
    ".blackcat", ".alphv", ".hive", ".ragnar", ".maze", ".egregor", ".basta",
    ".karma", ".vvv", ".ecc", ".ezz", ".exx", ".pzdc", ".zino", ".bip",
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
        reasons: Sequence[str] = (),
    ) -> str | None:
        """User-facing explanation for a status.

        ``reasons`` carries the detector's specific finding (e.g. "entropy
        jumped by 3.10 bits/byte versus baseline"); without it the report said
        "ransomware indicators matched" for what was really a baseline entropy
        comparison, which made the finding impossible to verify.
        """
        if status is FileStatus.CORRUPTED_FORMAT and validation is not None:
            return validation.error_message or "format validation failed"
        if status is FileStatus.CORRUPTED_SIZE:
            return "file size differs from the recorded baseline"
        if status is FileStatus.CORRUPTED_CHECKSUM:
            return "file checksum differs from the recorded baseline"
        if status is FileStatus.SUSPECTED_RANSOMWARE:
            if reasons:
                return f"file looks encrypted: {reasons[0]}"
            return "file looks encrypted: ransomware indicators matched"
        if status is FileStatus.SUSPICIOUS_EMPTY:
            return "file is empty"
        if status is FileStatus.SUSPICIOUS_HIGH_ENTROPY:
            if reasons:
                return f"high entropy (not a corruption finding): {reasons[0]}"
            return "file has high entropy; not a corruption finding on its own"
        if status is FileStatus.MISSING:
            return "file not found"
        if status is FileStatus.UNREADABLE:
            return "file is unreadable"
        if status is FileStatus.ERROR:
            return "analysis could not be completed"
        return None

    def _ransomware_signals(
        self,
        path: Path,
        metrics: FileMetrics,
        record: FileRecord | None,
        validation: FormatValidationResult,
    ) -> tuple[FileStatus, list[str]]:
        """Decide whether a file looks encrypted, and why.

        Deliberately conservative: entropy alone is *never* treated as
        corruption, because archives, media, Office packages, disk images and
        encrypted backups are legitimately high-entropy. Only two signals
        qualify as ransomware, and both are recorded in the findings:

        1. an extension used by ransomware families, or
        2. an entropy *jump* versus this file's own stored baseline (the actual
           signature of on-the-fly encryption), while format validation fails
           or the size stayed comparable.

        Anything else high-entropy is downgraded to a non-corrupt warning.
        """
        reasons: list[str] = []
        if not self._config.detect_ransomware or metrics.size_bytes == 0:
            return FileStatus.NEW_FILE, reasons

        extension = path.suffix.lower()

        if extension in _SUSPICIOUS_RANSOMWARE_EXTENSIONS:
            return FileStatus.SUSPECTED_RANSOMWARE, [
                f"extension {extension} is used by ransomware families"
            ]

        high_entropy = metrics.shannon_entropy >= self._config.entropy_threshold
        if not high_entropy:
            return FileStatus.NEW_FILE, reasons

        # Entropy jump against our own baseline for this exact file.
        if record is not None and record.size_bytes > 0:
            delta = metrics.shannon_entropy - record.shannon_entropy
            if delta >= self._config.entropy_jump_threshold:
                size_ratio = metrics.size_bytes / record.size_bytes
                if 0.5 <= size_ratio <= 2.0:
                    return FileStatus.SUSPECTED_RANSOMWARE, [
                        f"entropy jumped by {delta:.2f} bits/byte versus baseline "
                        f"({record.shannon_entropy:.2f} -> {metrics.shannon_entropy:.2f})"
                    ]

        if extension in _HIGH_ENTROPY_SAFE_EXTENSIONS:
            return FileStatus.NEW_FILE, reasons

        if validation.checked and validation.is_valid:
            # A recognised, structurally valid file is not ransomware.
            return FileStatus.NEW_FILE, reasons

        return FileStatus.SUSPICIOUS_HIGH_ENTROPY, [
            f"entropy {metrics.shannon_entropy:.2f} bits/byte with no format validator"
        ]

    def _determine_status(
        self,
        path: Path,
        metrics: FileMetrics,
        record: FileRecord | None,
        validation: FormatValidationResult,
    ) -> tuple[FileStatus, tuple[str, ...]]:
        """Return (status, extra reasons)."""
        if not validation.is_valid:
            return FileStatus.CORRUPTED_FORMAT, ()

        ransomware_status, reasons = self._ransomware_signals(path, metrics, record, validation)
        if ransomware_status is FileStatus.SUSPECTED_RANSOMWARE:
            return ransomware_status, tuple(reasons)

        if metrics.size_bytes == 0:
            return FileStatus.SUSPICIOUS_EMPTY, ("empty file",)

        if record is None:
            return FileStatus.NEW_FILE, ()

        # Comparison against the *stored baseline*. The baseline is never
        # overwritten while a file is damaged, so a finding is not lost on the
        # next scan the way it was in v2.0.
        if record.size_bytes != metrics.size_bytes:
            return FileStatus.CORRUPTED_SIZE, ()

        if record.checksum != metrics.checksum:
            return FileStatus.CORRUPTED_CHECKSUM, ()

        return FileStatus.VALID, tuple(reasons)

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
            status, reasons = self._determine_status(path, metrics, record, validation)

            is_corrupted = status in CORRUPT_STATUSES
            warnings = tuple(reasons) if status not in CORRUPT_STATUSES else ()

            # Corrupted files keep their original baseline. A damaged file that
            # was silently re-baselined (v2.0 behaviour) looked healthy forever
            # after the first report.
            baseline_known = record is not None
            new_record = FileRecord(
                path_str=str(path),
                size_bytes=metrics.size_bytes,
                checksum=metrics.checksum,
                last_modified_ts=path.stat().st_mtime,
                is_corrupted=is_corrupted,
                shannon_entropy=metrics.shannon_entropy,
                file_type=file_type,
                first_seen_ts=record.first_seen_ts if record else None,
                first_corrupt_ts=(
                    record.first_corrupt_ts
                    if record and record.first_corrupt_ts
                    else (time.time() if is_corrupted else None)
                ),
                last_status=status.name,
                last_seen_ts=time.time(),
            )
            self._repo.upsert_record(new_record, update_baseline=not is_corrupted)

            return FileAnalysisResult(
                file_path=str(path),
                status=status,
                metrics=metrics,
                file_type=file_type,
                error_message=self._status_message(status, validation, reasons),
                format_validation=validation,
                first_corrupt_at=(
                    datetime.fromtimestamp(
                        new_record.first_corrupt_ts, tz=timezone.utc
                    )
                    if new_record.first_corrupt_ts
                    else None
                ),
                baseline_size_bytes=record.size_bytes if baseline_known else None,
                warnings=warnings,
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
        except (DatabaseConcurrencyError, sqlite3.Error) as exc:
            self._logger.error("%s", exc)
            return FileAnalysisResult(
                file_path=str(path),
                status=FileStatus.ERROR,
                file_type=self._guess_file_type(path, None),
                error_message=f"database unavailable: {exc}",
            )
        except Exception:
            self._logger.exception("unexpected failure while analyzing %s", path)
            return FileAnalysisResult(
                file_path=str(path),
                status=FileStatus.ERROR,
                file_type=self._guess_file_type(path, None),
                error_message="internal analysis fault",
            )

    def internal_paths(self) -> frozenset[Path]:
        """Paths that belong to CIE itself and must never be scanned.

        The SQLite database and its WAL/SHM siblings change on every write, so
        treating them as user data produced two bugs: they were reported as
        corrupted on every scan after the first, and auto-quarantine could move
        the live database (reproducible data loss).
        """
        protected: set[Path] = set()
        db_path = Path(self._config.db_path).expanduser()
        if str(db_path) not in {":memory:", ""}:
            resolved = db_path.resolve()
            protected.add(resolved)
            for suffix in ("-wal", "-shm", "-journal"):
                protected.add(Path(f"{resolved}{suffix}"))

        if self._config.exclude_quarantine_from_scans:
            protected.add(Path(self._config.quarantine_dir).expanduser().resolve())
        return frozenset(protected)

    def _collect_files(self, directory: Path, recursive: bool) -> tuple[Path, ...]:
        quarantine_dir = Path(self._config.quarantine_dir).expanduser().resolve()
        protected = self.internal_paths()

        def include_name(name: str) -> bool:
            return self._config.include_hidden_files or not name.startswith(".")

        def is_internal(candidate: Path) -> bool:
            return candidate in protected or candidate.parent in protected

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
                    if is_internal(candidate):
                        self._logger.debug("skipping CIE's own file: %s", candidate)
                        continue

                    try:
                        if candidate.is_file():
                            files.append(candidate)
                    except OSError:
                        self._logger.warning("skipping inaccessible file: %s", candidate)
        else:
            for candidate in sorted(directory.iterdir(), key=lambda item: str(item).casefold()):
                if not include_name(candidate.name):
                    continue
                if is_internal(candidate.resolve()):
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

    def _is_internal_path(self, path: Path) -> bool:
        protected = self.internal_paths()
        return path in protected or path.parent in protected

    def quarantine_file(self, target_path: FilePath, reason: str = "Automated Quarantine") -> bool:
        path = Path(target_path).expanduser().resolve()
        quarantine_dir = Path(self._config.quarantine_dir).expanduser().resolve()

        if not path.exists() or not path.is_file():
            return False

        # Never move CIE's own database, its WAL/SHM siblings, or anything
        # already inside the quarantine directory.
        if self._is_internal_path(path):
            self._logger.error(
                "refusing to quarantine CIE's own file: %s (this would corrupt the database)",
                path,
            )
            return False

        if path.parent == quarantine_dir:
            self._logger.error("refusing to re-quarantine an already quarantined file: %s", path)
            return False

        quarantine_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        destination = quarantine_dir / f"{path.stem}_{timestamp}{path.suffix}.quarantine"
        try:
            shutil.move(str(path), str(destination))
            self._repo.log_quarantine(str(path), str(destination), reason)
            self._logger.info("quarantined %s -> %s", path.name, destination.name)
            return True
        except DatabaseConcurrencyError:
            # The file is already safely isolated; only the audit row failed.
            self._logger.error(
                "quarantined %s but could not write the audit log", path.name
            )
            return True
        except OSError as exc:
            self._logger.error("quarantine failed for %s: %s", path, exc)
            raise QuarantineError(f"failed to isolate {path}") from exc

    def list_quarantine(self, *, include_restored: bool = False) -> tuple[QuarantineEntry, ...]:
        return self._repo.list_quarantine(include_restored=include_restored)

    def restore_file(self, quarantine_path: FilePath, *, destination: FilePath | None = None) -> Path:
        """Move a quarantined file back to its original location.

        The original path is only used when it is still free; otherwise the file
        is restored alongside it with a ``_restored_<timestamp>`` suffix so an
        existing (possibly newer) file is never overwritten.
        """
        source = Path(quarantine_path).expanduser().resolve()
        if not source.exists() or not source.is_file():
            raise QuarantineError(f"no such quarantined file: {source}")

        entry = self._repo.find_quarantine_entry(str(source))
        if entry is None:
            raise QuarantineError(
                f"{source.name} is not in the quarantine log; refusing to guess its origin"
            )

        target = Path(destination).expanduser().resolve() if destination else Path(entry.original_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        if target.exists():
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            target = target.with_name(f"{target.stem}_restored_{timestamp}{target.suffix}")
            self._logger.warning(
                "original path was occupied; restoring to %s instead", target
            )

        try:
            shutil.move(str(source), str(target))
        except OSError as exc:
            raise QuarantineError(f"failed to restore {source}: {exc}") from exc

        self._repo.mark_restored(entry.entry_id, str(target))
        self._logger.info("restored %s -> %s", source.name, target)
        return target


# ==============================================================================
# 7. PUBLIC FACADE
# ==============================================================================

_SIBLING_MODULES: dict[str, ModuleType] = {}


def load_sibling_module(name: str) -> ModuleType:
    """Import a module that sits next to this file, by path.

    `import format_validators` only works when src/python happens to be on
    sys.path, which made the result depend on how the tool was launched. Loading
    by file path makes it deterministic.
    """
    if name in _SIBLING_MODULES:
        return _SIBLING_MODULES[name]

    candidate = Path(__file__).resolve().parent / f"{name}.py"
    if not candidate.exists():
        raise ImportError(f"{name}.py not found next to {Path(__file__).name}")

    spec = importlib.util.spec_from_file_location(f"cie_{name}", candidate)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load module from {candidate}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _SIBLING_MODULES[name] = module
    return module


def _load_advanced_validator() -> IFormatValidator | None:
    """Import the library-backed validator if it is available.

    `src/python/format_validators.py` shipped in v2.0 with an adapter written
    for exactly this purpose and was never wired up; as a result the shipped
    engine only ever looked at file headers.
    """
    try:
        module = load_sibling_module("format_validators")
        return module.FactoryBackedFormatValidator()
    except Exception as exc:  # pragma: no cover - depends on layout
        LOGGER.warning("advanced validators unavailable (%s); using built-in header checks", exc)
        return None


def create_analyzer(config: AnalyzerConfig | None = None) -> CorruptionEngine:
    cfg = config or AnalyzerConfig()
    repository = SQLiteMetadataRepo(cfg)
    calculator = AdvancedFileMetricsCalculator(cfg)

    format_validator: IFormatValidator = BuiltinFormatValidator()
    if cfg.advanced_validators:
        advanced = _load_advanced_validator()
        if advanced is not None:
            format_validator = advanced

    return CorruptionEngine(cfg, repository, calculator, format_validator)


class CorruptionDetector:
    """GUI-friendly facade."""

    def __init__(self, config: AnalyzerConfig | None = None):
        self._config = config or AnalyzerConfig()
        self._engine = create_analyzer(self._config)

    @property
    def config(self) -> AnalyzerConfig:
        return self._config

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

    def quarantine_file(self, target_path: FilePath, reason: str = "Automated Quarantine") -> bool:
        return self._engine.quarantine_file(target_path, reason)

    def list_quarantine(self, *, include_restored: bool = False) -> tuple[QuarantineEntry, ...]:
        return self._engine.list_quarantine(include_restored=include_restored)

    def restore_file(self, quarantine_path: FilePath, *, destination: FilePath | None = None) -> Path:
        return self._engine.restore_file(quarantine_path, destination=destination)

    def request_stop(self) -> None:
        self._engine.request_stop()

    def cancel_scan(self) -> None:
        self._engine.cancel_scan()

    def stop_scan(self) -> None:
        self._engine.request_stop()

    def get_library_status(self) -> dict[str, bool]:
        validator = self._engine._format_validator
        return {
            "Built-in Validator": True,
            "Advanced Validators Active": not isinstance(validator, BuiltinFormatValidator),
            "Pillow (Images)": importlib.util.find_spec("PIL") is not None,
            "pypdf/PyPDF2 (PDFs)": (
                importlib.util.find_spec("pypdf") is not None
                or importlib.util.find_spec("PyPDF2") is not None
            ),
            "FFmpeg (Media)": shutil.which("ffmpeg") is not None or shutil.which("ffprobe") is not None,
            "python-docx (Word)": importlib.util.find_spec("docx") is not None,
            "openpyxl (Excel)": importlib.util.find_spec("openpyxl") is not None,
            "numpy (Math acceleration)": importlib.util.find_spec("numpy") is not None,
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