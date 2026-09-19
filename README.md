# Corruption Isolation Engine (CIE)

A powerful software tool for detecting, isolating, and separating corrupted files from target directories and databases. Built with Python for the core functionality and GUI, and C++ for high-performance file analysis.

**Version 2.0** | **This Project Is Made By Kanishk Soni**

> **Status note (audit revision).** The v2.0 tree shipped with a stdlib-shadowing
> module name that broke every `cie.py` command, unit tests that called functions
> which did not exist, and a requirements file that `pip` refused to install.
> Those defects are fixed in this revision; `python3 -m pytest tests/` (158
> tests) and the CLI matrix in `docs/USER_GUIDE.md` pass. Measured detection
> limits and the remaining known gaps are listed under
> [Verification status](#verification-status) - please read that section before
> relying on a "healthy" verdict.

## Features

- **Fast Corruption Detection**: Advanced algorithms to quickly identify corrupted files
- **Multiple Scanning Strategies**: Fast, balanced, and deep analysis modes
- **Modular Processing System**: Deterministic file collection and reporting
- **Format-Specific Validation**: Deep analysis using specialized libraries:
  - **Images**: Pillow for JPEG, PNG, GIF, BMP, TIFF, WebP validation
  - **PDFs**: pypdf (pypdf-compatible API) for PDF structure and content validation
  - **Archives**: ZIP file integrity testing
  - **Media**: FFmpeg for video/audio file validation
  - **Documents**: python-docx for Word, openpyxl for Excel files
- **Binary File Analysis**: Deep analysis of file structures and binary patterns
- **Ransomware Detection**: Entropy-based heuristics for encrypted file detection
- **Automatic Quarantine**: Option to automatically move corrupted files to quarantine
- **Dual-Language Architecture**: Python for GUI and core logic, C++ for performance-critical operations
- **Comprehensive Reporting**: Detailed reports and statistics about file corruption in JSON or text format
- **SQLite Database**: Persistent storage of file metadata and analysis history with WAL mode
- **Cross-Platform Support**: Works on Linux, macOS, and Windows
- **Concurrent Processing**: Multi-threaded scanning with configurable worker threads
- **Self-Testing**: `python3 cie.py --self-test`, per-module self-tests, and 158 pytest tests
- **Quarantine with restore**: quarantined files are logged and can be restored, never
  silently deleted, and the engine's own database is never scanned or quarantined

## Architecture

### Python Components
- **Core Analyzer** (`src/python/core_analyzer.py`): Main corruption detection logic with concurrent processing
- **Format Validators** (`src/python/format_validators.py`): Specialized file format validation
- **Modular Scanner** (`src/python/modular_scanner.py`): Advanced scanning with multiple strategies
- **Processing Modules** (`src/python/processing_modules.py`): File processing pipeline
- **Math Utilities** (`src/python/cie_math.py`): Mathematical utilities for entropy and analysis
- **GUI Interface** (`src/gui/main_window.py`): User-friendly tkinter interface

### C++ Components
- **File Analyzer** (`src/cpp/file_analyzer.cpp`): High-performance binary file analysis

## Installation

### Prerequisites
- Python 3.7 or higher
- g++ compiler (for C++ module)
- tkinter (usually included with Python)
- FFmpeg (optional but recommended for media file validation)

### Setup

1. Clone or download the project
2. Install Python dependencies:
   ```bash
   # Using the installation script (recommended; verifies the install)
   ./install_dependencies.sh

   # Or manually with pip
   python3 -m pip install -r requirements.txt
   ```
   The engine itself runs with **no** third-party packages; Pillow/pypdf/
   python-docx/openpyxl/numpy only deepen the checks.

3. Install FFmpeg for media file validation (optional but recommended):
   ```bash
   # Ubuntu/Debian
   sudo apt-get install ffmpeg
   
   # CentOS/RHEL
   sudo yum install ffmpeg
   
   # macOS
   brew install ffmpeg
   
   # Windows
   # Download from https://ffmpeg.org/download.html
   ```

4. Compile the C++ module:
   ```bash
   make cpp
   ```

5. Verify installation:
   ```bash
   # Check library status
   python3 cie.py --library-status
   
   # Run self-tests
   python3 cie.py --self-test
   ```

## Usage

### GUI Application

Launch the graphical interface:
```bash
python3 cie.py --gui
# or
make gui
```

Features:
- Select target directory for scanning
- Choose recursive or non-recursive scanning
- Enable auto-quarantine for corrupted files
- View detailed results and statistics
- Export reports to text files
- Manage quarantined files
- Configure scanning parameters
- Real-time progress tracking

### Command Line Interface

#### Basic Scanning
```bash
# Scan a directory with default settings
python3 cie.py --scan /path/to/directory

# Scan with JSON output
python3 cie.py --scan /path/to/directory --json --output report.json

# Scan with automatic quarantine
python3 cie.py --scan /path/to/directory --quarantine

# Summary-only output
python3 cie.py --scan /path/to/directory --summary-only
```

#### Advanced Scanning Modes
```bash
# Modular scanning with different strategies
python3 cie.py --modular-scan /path/to/directory

# Fast scan mode (optimized for speed)
python3 cie.py --fast-scan /path/to/directory

# Non-recursive scanning
python3 cie.py --scan /path/to/directory --no-recursive
```

#### Utility Commands
```bash
# Check library availability
python3 cie.py --library-status

# Run self-tests
python3 cie.py --self-test

# Enable verbose output
python3 cie.py --scan /path/to/directory --verbose

# Fail on corruption detection (useful for CI/CD)
python3 cie.py --scan /path/to/directory --fail-on-findings

# List and restore quarantined files
python3 cie.py --list-quarantine
python3 cie.py --restore quarantine/<name>

# Use a configuration file (CLI flags always win)
python3 cie.py --scan /path/to/directory --config config/cie_config.json
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0    | Scan completed, nothing corrupted |
| 1    | Usage error (bad arguments, missing directory, unreadable config) |
| 2    | Scan completed and corruption / ransomware-like findings were found (`--fail-on-findings`) |
| 3    | Scan incomplete: at least one file could not be analysed |

## File Corruption Detection Methods

The CIE uses multiple methods to detect file corruption:

1. **Format-Specific Validation**: magic bytes plus real decoders - Pillow
   (images), pypdf (PDF), zip CRCs, tar header checksums, 7z/gzip CRCs,
   python-docx / openpyxl (OOXML parts), ffprobe (media when installed)
2. **Binary Pattern Analysis**: null-byte and control-character ratios,
   binary junk in text files
3. **Size Anomaly Detection**: zero-byte files (reported as a warning, never
   auto-quarantined)
4. **Historical Comparison**: size/checksum against the recorded baseline, so
   in-place damage that keeps the file size is still found on the next scan
5. **Entropy Analysis**: high entropy is only *suspicious*; it is treated as
   ransomware-like when a file's entropy jumps by >= 2 bits/byte versus its own
   recorded baseline or when the name matches a known ransomware extension
6. **Concurrent Processing**: parallel analysis for improved performance

Corruption, warnings (empty / high entropy) and faults (unreadable files) are
separate categories: only corruption is eligible for quarantine, and a fault
makes the scan "incomplete" rather than "clean".

### What a single scan can and cannot see

Measured on the audit corpus (18 damaged files + 12 healthy files):

- **Formats that carry integrity metadata** (PNG, WebP, ZIP/DOCX/XLSX, PDF, gzip,
  tar, 7z): damage is caught immediately, 9/9 in testing.
- **Formats without any checksum** (JPEG, BMP, TIFF, MP4, RAR, EXE, ELF, TXT):
  a one-shot scan sees only header/structure damage. Damage hidden inside the
  payload is found on the *second* scan, by comparison with the stored baseline
  (12/12 in testing). If you need first-scan certainty for such files, scan the
  intact set once to establish baselines before the damage occurs.
- **Pure random noise** (.bin/.txt) is deliberately *not* called corrupted; it
  is reported as high entropy / unknown, not as damage.

## Supported File Types

- **Images**: JPEG, PNG, GIF, BMP, TIFF, WebP (Pillow; CRC-checked for PNG/WebP)
- **Documents**: PDF, DOCX, XLSX, PPTX, TXT, CSV, JSON, XML, Markdown
- **Archives**: ZIP, JAR/APK (CRCs), TAR (checksums), 7Z (start-header CRC), GZ
- **Media**: MP4/MKV/MP3 and friends (needs `ffprobe` for content checks;
  container signatures are checked without it)
- **Databases**: SQLite, MySQL files (basic structure checks)
- **Binary Files**: Executables and other binary formats
- **Custom Files**: Any file type can be analyzed (unchecked formats are labelled
  `not inspected`, never silently assumed to be fine)

## Quarantine System

Corrupted files can be moved to a `quarantine/` directory with:
- Timestamp-based naming to prevent conflicts
- A `quarantine_log` row recording the original path and reason
- Restore support: `python3 cie.py --restore <quarantined file>` or the GUI's
  Quarantine Viewer. A restore never overwrites a file that now exists at the
  original path; it writes `<name>_restored_<timestamp>` alongside it instead.
- Safety rails: the engine's own database (`*.db`, `-wal`, `-shm`) and the
  quarantine directory are never flagged and never quarantined, so a scan can no
  longer disable the engine it is part of.

## Project Structure

```
Corruption_isolation_engine/
├── src/
│   ├── python/
│   │   ├── core_analyzer.py          # Main detection logic
│   │   ├── format_validators.py      # File format validation
│   │   ├── modular_scanner.py        # Advanced scanning strategies
│   │   ├── processing_modules.py     # File processing pipeline
│   │   └── cie_math.py               # Mathematical utilities
│   ├── cpp/
│   │   └── file_analyzer.cpp         # Optional high-performance analysis
│   └── gui/
│       └── main_window.py            # Tkinter GUI
├── config/
│   └── cie_config.json               # Configuration file
├── tests/                            # pytest suite (flat: no unit/integration split)
├── docs/                             # Documentation
├── quarantine/                       # Quarantined files (created at runtime)
├── cie.py                            # Main entry point
├── pytest.ini                        # Test configuration
├── requirements.txt                  # Python dependencies
├── install_dependencies.sh           # Installation script
├── Makefile                          # Build automation
├── LICENSE                           # MIT
└── README.md                         # This file
```

`cie_database.db` is **not** part of the repository: it is created on first run
and is deliberately excluded (see `.gitignore`). The v2.0 tarball shipped one
with 81,782 rows of another machine's paths.
```

## Build Commands

`make all` checks the engine (it does **not** launch the GUI); use `make gui`
for that.

```bash
# Check everything is ready to run
make all

# Build only C++ module
make cpp

# Run GUI
make gui

# Run C++ analyzer interactively
make run-cpp

# Install dependencies
make install

# Clean build artifacts
make clean

# Clean quarantine directory
make clean-quarantine

# Full clean (including databases)
make clean-all

# Run tests (pytest, 158 tests)
make test

# Run the self-tests embedded in each module (no pytest needed)
make test-selftest

# Build the optional C++ helper
make test-cpp

# Quick scan helpers
make scan DIR=/path/to/data
make scan-fast DIR=/path/to/data

# Create distribution package (excludes .db / quarantine / caches)
make dist

# Show all available commands
make help
```

## Configuration

The application can be configured through:
- Command-line arguments
- Configuration file (`config/cie_config.json`)
- GUI options during runtime
- SQLite database settings
- File type detection rules
- Quarantine directory location

### Key Configuration Options (actually honoured)

| JSON key | Effect |
|----------|--------|
| `database.path` | SQLite database location |
| `quarantine.directory` | where quarantined files are moved |
| `scanning.chunk_size` | read/streaming chunk size in bytes |
| `scanning.skip_hidden_files` | inverse of `include_hidden_files` |
| `scanning.follow_symlinks` | follow symlinks during collection |
| `scanning.max_workers` | worker threads |
| `detection.checksum_algorithm` | `sha256` / `sha512` / `md5` / `blake2b` |
| `detection.structure_validation_enabled` | enable library-backed validators |
| `detection.ransomware_detection_enabled` | enable the entropy/extension heuristics |
| `detection.entropy_threshold`, `detection.entropy_jump_threshold` | detection thresholds |

Precedence: **CLI flag > config file > built-in default**. Unknown keys are
ignored with a warning, so a hand-edited file cannot break a scan. The GUI
theme/logging keys in `config/cie_config.json` are advisory only - the engine
has no theme or log-rotation settings.

## Database Schema

The application uses SQLite with two main tables:

1. **file_metadata**: Stores file analysis results
2. **quarantine_log**: Tracks quarantined files

## Performance

Measured by the audit (20.04 MB/s for the Python engine on a 10,000-file
corpus; the C++ helper reached 107.3 MB/s but is not wired into the engine):

- **Modular Scanner**: fast / balanced / deep strategies, same verdicts on the
  same files; "fast" reduces *file collection* work, not validation depth
- **Parallel Processing**: configurable worker threads (default: CPU count × 2).
  On I/O-bound local scans throughput did **not** improve with more threads
  (20.88 / 20.13 / 19.86 MB/s at 1 / 4 / 8 workers)
- **Memory Efficient**: streaming analysis with configurable chunk sizes
- **Database Optimization**: WAL mode, retries with backoff, schema migration
- **Entropy Calculation**: single-pass Shannon entropy (numpy-accelerated when
  numpy is installed, identical results without it)

## Security

- No network access required; all processing is local
- Quarantine prevents accidental execution of corrupted files, and the
  quarantine directory is excluded from subsequent scans so a scan can never
  re-quarantine its own quarantine
- The engine's own database files are never scanned or moved (this used to
  disable the tool itself)
- Detailed logging for audit trails; expected corruption is logged at warning
  level so a genuine traceback still stands out

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Verification status

All numbers below were measured by the audit harness (`/home/user/audit/`) on
Linux with Python 3.13.14, Pillow 12.3, pypdf 6.19, python-docx 1.1.2,
openpyxl 3.1.5, numpy 2.3.5 and pytest 9.0.3 installed, **ffmpeg absent**:

| Check | Result |
|-------|--------|
| pytest suite | 158 passed |
| CLI commands (`--version`, `--library-status`, `--self-test`, `--scan`, `--modular-scan`, `--fast-scan`, `--list-quarantine`, `--restore`) | all exit 0 |
| Recall, formats with integrity metadata | 9/9 |
| Recall, same-size damage found on a *second* scan (baseline) | 12/12 |
| Recall, formats without checksums, first scan | 0/9 (documented) |
| False positives on 12 real-world healthy files (GPG, KDBX, disk image, OPUS, MKV, JAR, padded JPEG, MP4 with leading `free` box, ...) | 0 |
| Self-quarantine (engine's own DB / WAL / quarantine dir) | refused |
| Restore round-trip | pass |

Known limitations, stated rather than hidden:

- A file whose payload changed without changing the size or the format structure
  is only detectable against a baseline (see above).
- Text in non-UTF-8 legacy encodings (e.g. `Big5`, `KOI8-R`, `Latin-1` bytes)
  can still be reported as undecodable text - it is reported as a warning, not
  quarantined automatically.
- The C++ helper (`src/cpp/file_analyzer.cpp`) is not called by the Python
  engine; it remains a standalone experimental tool.
- Multi-threaded scanning does not measurably speed up I/O-bound scans.

## License

MIT - see [LICENSE](LICENSE). (The upstream repository referenced a LICENSE file
that did not exist; MIT was added during the audit. Replace it if a different
license is intended.)

## Troubleshooting

### Common Issues

1. **Tkinter not found**: Install tkinter for your distribution
   - Ubuntu: `sudo apt-get install python3-tk`
   - Fedora: `sudo dnf install python3-tkinter`

2. **C++ compilation errors**: Ensure g++ supports C++20
   - Update compiler: `sudo apt-get install g++`

3. **Permission errors**: Ensure read access to target directories

### Debug Mode

Enable debug logging by modifying the logging level in `core_analyzer.py`:
```python
logging.basicConfig(level=logging.DEBUG)
```

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the code documentation
3. Create an issue with detailed information

## Version History

- **v2.0 (audit revision)**: repairs for the defects found by the independent
  audit - import shadowing, phantom tests, destructive self-quarantine,
  false positives on valid text/encodings, installable requirements, working
  Makefile targets, restore support, and honest detection limits.

- **v2.0**: Major update with enhanced features
  - Modular scanning system with multiple strategies
  - Ransomware detection via entropy analysis
  - Concurrent processing with configurable workers
  - Enhanced command-line interface
  - Self-testing capabilities
  - Improved database handling with WAL mode
  - JSON and text reporting options
  - Configuration file support

- **v1.0**: Initial release with core functionality
  - Python corruption detection
  - C++ high-performance analyzer
  - Tkinter GUI interface
  - SQLite database integration
  - Quarantine system
