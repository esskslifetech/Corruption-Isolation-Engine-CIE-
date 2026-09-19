# API Documentation

This document provides comprehensive API documentation for the Corruption Isolation Engine (CIE).

## Table of Contents

- [Core Classes](#core-classes)
- [Configuration](#configuration)
- [Data Models](#data-models)
- [Exception Handling](#exception-handling)
- [Module APIs](#module-apis)

## Core Classes

### CorruptionDetector

The main class for file corruption detection and analysis.

```python
from src.python.core_analyzer import CorruptionDetector, AnalyzerConfig

# Initialize with configuration
config = AnalyzerConfig(
    db_path="cie_database.db",
    quarantine_dir="quarantine",
    max_workers=8,
    entropy_threshold=7.95
)

detector = CorruptionDetector(config)
```

#### Methods

##### `scan_directory(directory: str, recursive: bool = True) -> List[FileAnalysisResult]`

Scans a directory for corrupted files.

**Parameters:**
- `directory` (str): Path to the directory to scan
- `recursive` (bool): Whether to scan subdirectories (default: True)

**Returns:**
- `List[FileAnalysisResult]`: List of analysis results for each file

**Example:**
```python
results = detector.scan_directory("/path/to/directory", recursive=True)
for result in results:
    if result.is_corrupted:
        print(f"Corrupted file: {result.file_path}")
```

##### `quarantine_file(file_path: str) -> bool`

Moves a corrupted file to the quarantine directory.

**Parameters:**
- `file_path` (str): Path to the file to quarantine

**Returns:**
- `bool`: True if successful, False otherwise

**Example:**
```python
if detector.quarantine_file("/path/to/corrupted/file.txt"):
    print("File successfully quarantined")
```

##### `rebaseline(targets, recursive: bool = True, force: bool = False, dry_run: bool = False) -> tuple[RebaselineOutcome, ...]`

Accepts the current content of one or more files as their new baseline, after
a human has reviewed a finding. Records today's size, checksum and entropy,
clears `is_corrupted` / `first_corrupt`, and keeps `first_seen`.

**Parameters:**
- `targets` (Sequence[str]): files or directories to re-baseline
- `recursive` (bool): walk subdirectories when a target is a directory (default: True)
- `force` (bool): also accept files that fail format validation (default: False)
- `dry_run` (bool): report what would happen without writing to the database

**Returns:**
- `tuple[RebaselineOutcome, ...]`: one entry per file, each with `path`,
  `action` (`rebaselined` | `refused` | `missing`), `previous_status` and
  `reason`, plus an `ok` convenience property

**Example:**
```python
for outcome in detector.rebaseline(["/path/to/reviewed.docx"], dry_run=True):
    print(outcome.action, outcome.path, outcome.reason or "")
```

Files that the validators reject are refused unless `force=True`; the engine's
own database and quarantine directory are always refused.

##### `get_library_status() -> Dict[str, bool]`

Returns the availability status of validation libraries.

**Returns:**
- `Dict[str, bool]`: Dictionary mapping library names to availability

**Example:**
```python
status = detector.get_library_status()
for library, available in status.items():
    print(f"{library}: {'Available' if available else 'Not Available'}")
```

### AnalyzerConfig

Configuration class for the analyzer.

#### Parameters

- `db_path` (str): Path to SQLite database (default: "cie_database.db")
- `quarantine_dir` (str): Quarantine directory path (default: "quarantine")
- `chunk_size` (int): Streaming read chunk size in bytes (default: 262144)
- `hash_algorithm` (str): Hash algorithm for checksums (default: "sha256")
- `max_workers` (int): Maximum worker threads (default: CPU count × 2)
- `detect_ransomware` (bool): Enable ransomware detection (default: True)
- `entropy_threshold` (float): High-entropy threshold (default: 7.95)
- `db_busy_timeout_ms` (int): Database busy timeout in milliseconds (default: 5000)
- `db_retry_attempts` (int): Database retry attempts (default: 6)
- `db_retry_backoff_seconds` (float): Database retry backoff (default: 0.05)
- `exclude_quarantine_from_scans` (bool): Exclude quarantine from scans (default: True)
- `follow_symlinks` (bool): Follow symbolic links (default: False)
- `include_hidden_files` (bool): Include hidden files (default: True)
- `advanced_validators` (bool): Use the format validators (default: True)
- `entropy_jump_threshold` (float): Entropy jump that marks a suspicion (default: 2.0)
- `use_cpp_accel` (bool): Use the C++ library for hashes/metrics when it is
  loaded (default: True). Ignored for non-`sha256` algorithms, which always use
  the pure-Python path. Check the active path with
  `AdvancedFileMetricsCalculator(config).backend` (`"cpp"` or `"python"`).

### C++ Acceleration

`src/python/cpp_accel.py` binds `build/libcie_accel.so` (built by `make cpp`):

```python
from cpp_accel import available, selftest, hash_bytes, AccelHasher

available()              # True when the shared library was found and loaded
selftest()               # 0 = the library's own SHA-256 entropy self-test passed
hash_bytes(b"payload")   # AccelStats(size_bytes, sha256, shannon_entropy, ...)

with AccelHasher() as hasher:
    hasher.update(b"chunk 1")
    hasher.update(b"chunk 2")
    stats = hasher.finish()      # same fields, streamed
```

`AccelStats` carries `size_bytes`, `sha256`, `shannon_entropy`, `null_bytes`,
`printable_bytes`, `unique_bytes` and `max_run_length`. Nothing here raises on
import: `available()` just returns `False` when the library is absent, and the
engine then falls back to the pure-Python implementation (logged once).
Environment overrides: `CIE_ACCEL_LIBRARY` (explicit path) and
`CIE_ACCEL_BUILD_DIR` (directory holding the library).

## Data Models

### FileAnalysisResult

Represents the result of file analysis.

#### Attributes

- `file_path` (str): Path to the analyzed file
- `file_size` (int): Size of the file in bytes
- `file_type` (str | None): Detected file type
- `checksum` (str | None): SHA-256 checksum of the file
- `error_message` (str | None): Error message if analysis failed
- `is_corrupted` (bool): Whether the file is detected as corrupted
- `status` (FileStatus): Analysis status
- `format_validation` (FormatValidation | None): Format-specific validation results
- `shannon_entropy` (float): Shannon entropy of the file content

### FileStatus

Enumeration of possible file statuses.

#### Values

- `VALID`: File is valid and not corrupted
- `NEW_FILE`: File is new (no previous record)
- `CORRUPTED_SIZE`: File has suspicious size
- `CORRUPTED_CHECKSUM`: File checksum mismatch
- `CORRUPTED_FORMAT`: File format validation failed
- `MISSING`: File is missing
- `UNREADABLE`: File cannot be read

### FormatValidation

Contains format-specific validation results.

#### Attributes

- `is_valid` (bool): Whether the format is valid
- `error_message` (str | None): Format-specific error message
- `format_info` (Any): Format-specific information
- `corruption_details` (List[str]): List of corruption details

## Exception Handling

### AnalyzerBaseException

Base exception for all analyzer errors.

### FileAccessError

Raised when a file cannot be read or inspected.

### DatabaseConcurrencyError

Raised when SQLite remains locked after retries.

### QuarantineError

Raised when quarantine operations fail.

### ScanCancelledError

Raised when an in-progress scan is cancelled.

## Module APIs

### Format Validators

#### ImageValidator

Validates image files using Pillow.

```python
from src.python.format_validators import ImageValidator

validator = ImageValidator()
result = validator.validate("/path/to/image.jpg")
```

#### PDFValidator

Validates PDF files using pypdf (pypdf-compatible API).

```python
from src.python.format_validators import PDFValidator

validator = PDFValidator()
result = validator.validate("/path/to/document.pdf")
```

#### ArchiveValidator

Validates archive files (ZIP, etc.).

```python
from src.python.format_validators import ArchiveValidator

validator = ArchiveValidator()
result = validator.validate("/path/to/archive.zip")
```

### Math Utilities

#### Entropy Calculation

```python
from src.python.math import calculate_shannon_entropy

entropy = calculate_shannon_entropy(file_data)
print(f"Shannon entropy: {entropy:.4f}")
```

#### Binary Pattern Analysis

```python
from src.python.math import detect_null_byte_patterns, detect_repeated_patterns

null_ratio = detect_null_byte_patterns(file_data)
repeated_patterns = detect_repeated_patterns(file_data)
```

### Processing Modules

#### File Processor

```python
from src.python.processing_modules import FileProcessor

processor = FileProcessor(config=config)
result = processor.analyze_file("/path/to/file")
```

## Command Line Interface

### Main Entry Point

```python
from cie import main

# Run with command line arguments
exit_code = main(["--scan", "/path/to/directory", "--json"])
```

### Argument Parsing

```python
from cie import build_parser

parser = build_parser()
args = parser.parse_args(["--scan", "/path/to/directory"])
```

## Configuration File

The application can be configured using `config/cie_config.json`:

```json
{
  "database": { "path": "cie_database.db" },
  "scanning": {
    "chunk_size": 262144,
    "skip_hidden_files": false,
    "follow_symlinks": false,
    "max_workers": 0,
    "cpp_acceleration": true
  },
  "quarantine": { "directory": "quarantine" },
  "detection": {
    "checksum_algorithm": "sha256",
    "structure_validation_enabled": true,
    "ransomware_detection_enabled": true,
    "entropy_threshold": 7.95,
    "entropy_jump_threshold": 2.0
  },
  "_advisory": { "gui": { "theme": "default" }, "logging": { "level": "INFO" } }
}
```

This mirrors `config/cie_config.json`, which is the file the engine actually
reads (`config_from_mapping`). Keys under `_advisory` are documentation only -
the engine has no theme or log-rotation support - and unknown keys are ignored
with a warning, so a hand-edited file cannot break a scan. `max_workers: 0`
means "choose automatically". Precedence: **CLI flag > config file > default**.

## Database Schema

### file_metadata Table

Stores file analysis results.

| Column | Type | Description |
|--------|------|-------------|
| file_path | TEXT | File path (primary key) |
| size_bytes | INTEGER | File size in bytes |
| checksum | TEXT | Checksum of the trusted baseline content |
| last_modified | REAL | mtime of the baseline |
| is_corrupted | INTEGER | 0/1 - whether the file is currently flagged |
| shannon_entropy | REAL | Entropy of the baseline content |
| file_type | TEXT | Detected file type |
| analysis_date | TEXT | Timestamp of the last analysis |
| first_seen | REAL | When the path was first scanned |
| first_corrupt | REAL | When it was first flagged as corrupted |
| last_status | TEXT | Last status string (e.g. `VALID`, `CORRUPTED_FORMAT`) |
| last_seen | REAL | When the path was last seen |

`size_bytes`, `checksum`, `last_modified` and `shannon_entropy` describe the
trusted baseline and are **not** overwritten while the file stays flagged, so a
damaged file keeps being reported on later scans. New columns are added by
`_migrate()` with `ALTER TABLE`, so existing databases keep working.

### quarantine_log Table

Tracks quarantined files.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| original_path | TEXT | Original file path |
| quarantine_path | TEXT | File path inside the quarantine directory |
| reason | TEXT | Why the file was quarantined |
| action_date | TEXT | When it was quarantined |
| restored_at | TEXT | When it was restored (`NULL` while quarantined) |

## Performance Considerations

### Concurrent Processing

The analyzer uses multi-threading for improved performance:

- Default worker count: CPU count × 2
- Configurable via `max_workers` parameter
- Thread-safe database operations with retry mechanisms

### Memory Usage

- Streaming analysis with configurable chunk sizes
- Default chunk size: 256KB
- Memory-efficient for large files

### Database Optimization

- WAL mode for better concurrency
- Connection pooling
- Configurable timeouts and retry logic

## Error Handling Best Practices

```python
try:
    results = detector.scan_directory("/path/to/directory")
except FileAccessError as e:
    print(f"File access error: {e}")
except DatabaseConcurrencyError as e:
    print(f"Database error: {e}")
except ScanCancelledError as e:
    print(f"Scan cancelled: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Thread Safety

The `CorruptionDetector` class is designed to be thread-safe:

- Database connections are thread-local
- File operations use proper locking
- Quarantine operations are atomic

## Extending the API

### Custom Validators

```python
from src.python.format_validators import BaseValidator

class CustomValidator(BaseValidator):
    def validate(self, file_path: str) -> FormatValidation:
        # Custom validation logic
        pass
```

### Custom Processors

```python
from src.python.processing_modules import BaseProcessor

class CustomProcessor(BaseProcessor):
    def process(self, file_path: str) -> FileAnalysisResult:
        # Custom processing logic
        pass
```
