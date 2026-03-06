# Corruption Isolation Engine (CIE)

A powerful software tool for detecting, isolating, and separating corrupted files from target directories and databases. Built with Python for the core functionality and GUI, and C++ for high-performance file analysis.

**Version 2.0** | **This Project Is Made By Kanishk Soni**

## Features

- **Fast Corruption Detection**: Advanced algorithms to quickly identify corrupted files
- **Multiple Scanning Strategies**: Fast, balanced, and deep analysis modes
- **Modular Processing System**: Deterministic file collection and reporting
- **Format-Specific Validation**: Deep analysis using specialized libraries:
  - **Images**: Pillow for JPEG, PNG, GIF, BMP, TIFF, WebP validation
  - **PDFs**: PyPDF2/PyPDF4 for PDF structure and content validation
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
- **Self-Testing**: Built-in test suite for validation

## Architecture

### Python Components
- **Core Analyzer** (`src/python/core_analyzer.py`): Main corruption detection logic with concurrent processing
- **Format Validators** (`src/python/format_validators.py`): Specialized file format validation
- **Modular Scanner** (`src/python/modular_scanner.py`): Advanced scanning with multiple strategies
- **Processing Modules** (`src/python/processing_modules.py`): File processing pipeline
- **Math Utilities** (`src/python/math.py`): Mathematical utilities for entropy and analysis
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
   # Using the installation script (recommended)
   ./install_dependencies.sh
   
   # Or manually with pip
   pip3 install -r requirements.txt
   ```

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
```

## File Corruption Detection Methods

The CIE uses multiple methods to detect file corruption:

1. **Checksum Verification**: SHA-256 checksums to detect changes
2. **Binary Pattern Analysis**: Detects null byte patterns and repeated patterns
3. **File Structure Validation**: Validates file headers for common formats (JPEG, PNG, PDF, ZIP)
4. **Size Anomaly Detection**: Identifies suspicious file sizes (empty files)
5. **Historical Comparison**: Compares with stored metadata from previous scans
6. **Entropy Analysis**: Detects high-entropy files characteristic of ransomware encryption
7. **Format-Specific Validation**: Deep validation using specialized libraries
8. **Concurrent Processing**: Parallel analysis for improved performance

## Supported File Types

- **Images**: JPEG, PNG, GIF, BMP, TIFF
- **Documents**: PDF, DOCX, XLSX, TXT
- **Archives**: ZIP, RAR, 7Z, TAR
- **Databases**: SQLite, MySQL files (basic structure checks)
- **Binary Files**: Executables and other binary formats
- **Custom Files**: Any file type can be analyzed

## Quarantine System

Corrupted files are automatically moved to a `quarantine/` directory with:
- Timestamp-based naming to prevent conflicts
- Detailed logging in SQLite database
- Original path preservation for recovery

## Project Structure

```
Corruption_isolation_engine/
├── src/
│   ├── python/
│   │   ├── core_analyzer.py          # Main detection logic
│   │   ├── format_validators.py      # File format validation
│   │   ├── modular_scanner.py        # Advanced scanning strategies
│   │   ├── processing_modules.py     # File processing pipeline
│   │   └── math.py                   # Mathematical utilities
│   ├── cpp/
│   │   └── file_analyzer.cpp         # High-performance analysis
│   └── gui/
│       └── main_window.py            # Tkinter GUI
├── config/
│   └── cie_config.json               # Configuration file
├── tests/                            # Test files
├── docs/                             # Documentation
├── .qodo/                            # Agent workflows
├── quarantine/                       # Quarantined files
├── cie.py                            # Main entry point
├── requirements.txt                  # Python dependencies
├── install_dependencies.sh           # Installation script
├── Makefile                          # Build automation
├── cie_database.db                   # SQLite database (created)
└── README.md                         # This file
```

## Build Commands

```bash
# Build everything
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

# Run tests
make test

# Test C++ compilation
make test-cpp

# Test Python module
make test-python

# Create distribution package
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

### Key Configuration Options
- **Database**: SQLite path, backup settings
- **Scanning**: Chunk size, max file size, hidden file handling
- **Quarantine**: Directory, auto-cleanup, size limits
- **Detection**: Checksum algorithm, binary analysis, thresholds
- **GUI**: Theme, window dimensions, refresh settings
- **Logging**: Level, file rotation, backup count

## Database Schema

The application uses SQLite with two main tables:

1. **file_metadata**: Stores file analysis results
2. **quarantine_log**: Tracks quarantined files

## Performance

- **C++ Module**: Optimized for fast binary analysis of large directories
- **Python Module**: Feature-rich with database integration and concurrent processing
- **Modular Scanner**: Multiple strategies (fast, balanced, deep) for different use cases
- **Parallel Processing**: Configurable multi-threaded scanning (default: CPU count × 2)
- **Memory Efficient**: Streaming analysis for large files with configurable chunk sizes
- **Database Optimization**: WAL mode, connection pooling, retry mechanisms
- **Entropy Calculation**: Single-pass Shannon entropy computation

## Security

- No network access required
- All processing done locally
- Quarantine prevents accidental execution of corrupted files
- Detailed logging for audit trails

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is open source. Please check the LICENSE file for details.

## Troubleshooting

### Common Issues

1. **Tkinter not found**: Install tkinter for your distribution
   - Ubuntu: `sudo apt-get install python3-tk`
   - Fedora: `sudo dnf install python3-tkinter`

2. **C++ compilation errors**: Ensure g++ supports C++17
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
