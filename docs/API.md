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
  "database": {
    "path": "cie_database.db",
    "backup_enabled": true,
    "backup_interval_hours": 24
  },
  "scanning": {
    "default_recursive": true,
    "chunk_size": 4096,
    "max_file_size_mb": 1024,
    "skip_hidden_files": true,
    "skip_system_files": true
  },
  "quarantine": {
    "directory": "quarantine",
    "auto_cleanup_days": 30,
    "max_quarantine_size_gb": 10,
    "compression_enabled": false
  },
  "detection": {
    "checksum_algorithm": "sha256",
    "binary_analysis_enabled": true,
    "structure_validation_enabled": true,
    "null_byte_threshold": 0.5,
    "pattern_detection_enabled": true
  },
  "gui": {
    "theme": "default",
    "window_width": 1000,
    "window_height": 700,
    "auto_refresh": false,
    "show_hidden_files": false
  },
  "logging": {
    "level": "INFO",
    "file": "cie.log",
    "max_size_mb": 10,
    "backup_count": 5
  },
  "file_types": {
    "image_extensions": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"],
    "document_extensions": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".rtf"],
    "archive_extensions": [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"],
    "database_extensions": [".db", ".sqlite", ".sqlite3", ".mdb"],
    "binary_extensions": [".exe", ".dll", ".so", ".dylib", ".bin"]
  }
}
```

## Database Schema

### file_metadata Table

Stores file analysis results.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| file_path | TEXT | File path |
| file_size | INTEGER | File size in bytes |
| file_type | TEXT | Detected file type |
| checksum | TEXT | SHA-256 checksum |
| is_corrupted | BOOLEAN | Whether file is corrupted |
| status | TEXT | Analysis status |
| error_message | TEXT | Error message |
| shannon_entropy | REAL | Shannon entropy |
| created_at | TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP | Last update timestamp |

### quarantine_log Table

Tracks quarantined files.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| original_path | TEXT | Original file path |
| quarantine_path | TEXT | Quarantine file path |
| file_size | INTEGER | File size in bytes |
| checksum | TEXT | File checksum |
| quarantine_reason | TEXT | Reason for quarantine |
| created_at | TIMESTAMP | Quarantine timestamp |

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
