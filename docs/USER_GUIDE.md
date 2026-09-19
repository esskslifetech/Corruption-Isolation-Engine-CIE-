# User Guide

This guide helps users get the most out of the Corruption Isolation Engine (CIE) for detecting and managing corrupted files.

## Table of Contents

- [Getting Started](#getting-started)
- [GUI Usage](#gui-usage)
- [Command Line Usage](#command-line-usage)
- [Understanding Results](#understanding-results)
- [Quarantine Management](#quarantine-management)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

## Getting Started

### First Time Setup

1. **Install Dependencies**
   ```bash
   ./install_dependencies.sh
   ```

2. **Compile C++ Module** (optional but recommended; builds the standalone
   analyzer *and* the shared library the Python engine hashes with)
   ```bash
   make cpp
   ```

3. **Verify Installation**
   ```bash
   python3 cie.py --library-status
   python3 cie.py --self-test
   ```

### Quick Start - GUI

Launch the graphical interface:
```bash
python3 cie.py --gui
```

### Quick Start - Command Line

Scan your first directory:
```bash
python3 cie.py --scan ~/Documents
```

## GUI Usage

### Main Interface

The GUI provides an intuitive interface for file corruption detection:

#### 1. Directory Selection
- Click "Browse" to select a target directory
- Or enter the path directly in the input field

#### 2. Scan Options
- **Recursive Scan**: Include subdirectories (recommended)
- **Auto-Quarantine**: Automatically move corrupted files
- **Verbose Output**: Show detailed information during scan

#### 3. Starting a Scan
- Click "Start Scan" to begin analysis
- Progress bar shows scan completion
- Real-time results appear in the results panel

#### 4. Results Panel
- **Green**: Valid files
- **Red**: Corrupted files
- **Yellow**: Files with warnings
- **Gray**: Unreadable files

#### 5. Actions Menu
- **Export Results**: Save scan results to file
- **Quarantine Selected**: Move selected corrupted files
- **View Details**: Show detailed file information
- **Refresh**: Rescan the directory

### Advanced GUI Features

#### Library Status
Check which validation libraries are available:
- Go to `Tools > Library Status`
- Green checkmarks indicate available libraries
- Red X marks indicate missing dependencies

#### Configuration
Access advanced settings:
- Go to `Tools > Settings`
- Configure database paths, quarantine options
- Adjust scanning parameters
- Set file type preferences

#### Quarantine Management
Manage quarantined files:
- Go to `Tools > Quarantine Manager`
- View quarantined files list
- Restore files if needed
- Clean up old quarantines

## Command Line Usage

### Basic Commands

#### Simple Scan
```bash
python3 cie.py --scan /path/to/directory
```

#### JSON Output
```bash
python3 cie.py --scan /path/to/directory --json --output report.json
```

#### Automatic Quarantine
```bash
python3 cie.py --scan /path/to/directory --quarantine
```

#### Summary Only
```bash
python3 cie.py --scan /path/to/directory --summary-only
```

### Advanced Scanning

#### Non-Recursive Scan
```bash
python3 cie.py --scan /path/to/directory --no-recursive
```

#### Modular Scanning with Strategies
```bash
# Fast strategy (quick analysis)
python3 cie.py --modular-scan /path/to/directory --strategy fast

# Balanced strategy (recommended)
python3 cie.py --modular-scan /path/to/directory --strategy balanced

# Deep strategy (thorough analysis)
python3 cie.py --modular-scan /path/to/directory --strategy deep
```

#### Fast Scan Mode
```bash
python3 cie.py --fast-scan /path/to/directory
```

### Utility Commands

#### Check Library Status
```bash
python3 cie.py --library-status
```
The listing includes a **C++ acceleration (hashes/metrics)** row: `Available`
when `build/libcie_accel.so` was found and loaded, otherwise the tool runs the
pure-Python implementation with no loss of accuracy.

#### Disable C++ Acceleration
```bash
python3 cie.py --scan /path/to/directory --no-cpp-accel
```
Useful when comparing backends or debugging; equivalent config key:
`"scanning": {"cpp_acceleration": false}`.

#### Run Self-Tests
```bash
python3 cie.py --self-test
```

#### Verbose Output
```bash
python3 cie.py --scan /path/to/directory --verbose
```

#### CI/CD Integration
```bash
# Exit with code 2 if corruption found
python3 cie.py --scan /path/to/directory --fail-on-findings
```

#### Accept a Reviewed File as the New Baseline

After you look at a finding and decide the file is fine (a document that was
edited on purpose, a file restored from backup, a download you verified), tell
the engine so it stops reporting it:

```bash
# Show what would change, without touching the database
python3 cie.py --rebaseline /path/to/file --dry-run

# Accept the file (or every changed file under a directory)
python3 cie.py --rebaseline /path/to/file-or-directory
```

Re-baselining records today's size, checksum and entropy as the trusted values
and clears the previous finding. It refuses files whose structure the
validators reject (so it cannot be used to bless a broken file by accident);
`--rebaseline-force` overrides that, and should only be used when you have
checked the file yourself. `--json` prints the accepted / refused / missing
lists in machine-readable form.

Exit codes: `0` everything accepted, `1` nothing accepted (missing paths or
refused files), `3` partially accepted.

#### The same action from the GUI

1. Scan the directory that holds the file.
2. Right-click the finding in the *Corrupted* (or *All Files*) tab.
3. Choose **Rebaseline (accept current content)**.
4. Confirm. The dialog lists the files it is about to accept and warns that they
   will stop being reported on later scans.
5. If a file still fails format validation, it is **refused** and you are asked
   again; only a second confirmation accepts it (the equivalent of
   `--rebaseline-force`), and the summary says so afterwards.

Accepted files are re-analysed immediately, so the table keeps showing what the
engine reports now rather than what it reported before.

### Configuration Options

#### Database Settings
```bash
python3 cie.py --scan /path/to/directory --db-path custom.db
```

#### Quarantine Settings
```bash
python3 cie.py --scan /path/to/directory --quarantine-dir custom_quarantine
```

#### Performance Tuning
```bash
python3 cie.py --scan /path/to/directory --max-workers 16 --chunk-size 512000
```

#### Ransomware Detection
```bash
# Disable ransomware detection
python3 cie.py --scan /path/to/directory --disable-ransomware-detection

# Custom entropy threshold
python3 cie.py --scan /path/to/directory --entropy-threshold 7.5
```

## Understanding Results

### Scan Summary

After each scan, you'll see a summary like:

```
Corruption Isolation Engine Report
==================================
Generated at       : 2024-01-15T10:30:45.123456+00:00
Total files        : 1,234
Corrupted files    : 5
Healthy files      : 1,229
Unreadable files   : 0
Total bytes        : 1,234,567,890 (1.15 GB)
Largest file       : 123,456,789 (117.74 MB)
Corruption rate    : 0.41%
```

### File Status Types

#### VALID
- File passes all validation checks
- No corruption detected
- Safe to use

#### CORRUPTED_CHECKSUM
- File checksum differs from stored value
- Content has changed unexpectedly
- May indicate data corruption

#### CORRUPTED_FORMAT
- File format validation failed
- Structure is invalid or damaged
- File may be partially corrupted

#### CORRUPTED_SIZE
- File size is suspicious (0 bytes or unusually large)
- May indicate incomplete writes or filesystem issues

#### NEW_FILE
- File hasn't been scanned before
- No baseline for comparison
- Status will be updated on future scans

#### UNREADABLE
- File cannot be accessed or read
- Permission issues or filesystem errors
- Check file permissions

### Detailed File Information

For corrupted files, you'll see detailed information:

```
[CORRUPTED_FORMAT] /path/to/corrupted/file.pdf
  Size           : 1,234,567 bytes
  Type           : PDF
  Checksum       : a1b2c3d4e5f6...
  Entropy        : 7.8234
  Format Status  : Invalid
  Error          : Invalid PDF structure - missing EOF marker
  Validation Notes:
    - Missing EOF marker
    - Invalid cross-reference table
    - Corrupted object stream
```

### Entropy Analysis

Shannon entropy helps detect encrypted or corrupted files:

- **Normal files**: 0.0 - 6.0 (typical text, images, documents)
- **Compressed files**: 6.0 - 7.5 (ZIP, compressed formats)
- **Encrypted files**: 7.5 - 8.0 (possible ransomware encryption)
- **Default threshold**: 7.95 (configurable)

## Quarantine Management

### What is Quarantine?

Quarantine safely isolates corrupted files to prevent accidental use or further damage.

### Automatic Quarantine

Enable automatic quarantine during scans:

#### GUI
- Check "Auto-Quarantine" before scanning
- Corrupted files are automatically moved

#### Command Line
```bash
python3 cie.py --scan /path/to/directory --quarantine
```

### Manual Quarantine

#### GUI
1. Select corrupted files in results
2. Right-click and choose "Quarantine Selected"
3. Confirm the action

#### Command Line
```python
from src.python.core_analyzer import CorruptionDetector

detector = CorruptionDetector()
detector.quarantine_file("/path/to/corrupted/file")
```

### Quarantine Directory Structure

```
quarantine/
├── 2024-01-15/
│   ├── document_20240115_103045.pdf
│   ├── image_20240115_103046.jpg
│   └── ...
├── 2024-01-14/
│   └── ...
└── quarantine.log
```

### Restoring Files

#### GUI
1. Go to `Tools > Quarantine Manager`
2. Select files to restore
3. Click "Restore to Original Location"

#### Command Line
```bash
# Manual restore (copy file back)
cp quarantine/2024-01-15/file_20240115_103045.pdf /original/path/file.pdf
```

### Quarantine Cleanup

#### Automatic Cleanup
- Files older than 30 days are automatically deleted
- Configurable via settings

#### Manual Cleanup
```bash
# Clean entire quarantine
make clean-quarantine

# Remove old files (older than 7 days)
find quarantine/ -type f -mtime +7 -delete
```

## Configuration

### Configuration File

Edit `config/cie_config.json` for persistent settings:

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
  }
}
```

### Environment Variables

Set environment variables for runtime configuration:

```bash
export CIE_DB_PATH="/custom/path/database.db"
export CIE_QUARANTINE_DIR="/custom/path/quarantine"
export CIE_LOG_LEVEL="DEBUG"
python3 cie.py --scan /path/to/directory
```

### Performance Tuning

#### CPU Usage
```bash
# Use more CPU cores for faster scanning
python3 cie.py --scan /path/to/directory --max-workers 16
```

#### Memory Usage
```bash
# Use larger chunks for faster processing (more memory)
python3 cie.py --scan /path/to/directory --chunk-size 1048576
```

#### I/O Optimization
```bash
# Reduce database timeout for faster operations
python3 cie.py --scan /path/to/directory --db-timeout 1000
```

## Troubleshooting

### Common Issues

#### Permission Denied
```bash
Error: Permission denied: /path/to/file
```
**Solution**: Run with appropriate permissions or choose accessible directories.

#### Library Not Available
```bash
Library Status
==============
Pillow                    Not Available
```
**Solution**: Install missing dependencies:
```bash
pip3 install Pillow pypdf python-docx openpyxl
```

#### Database Locked
```bash
Error: Database is locked
```
**Solution**: Close other instances or increase timeout:
```bash
python3 cie.py --scan /path/to/directory --db-timeout 10000
```

#### Out of Memory
```bash
Error: Memory allocation failed
```
**Solution**: Reduce chunk size or workers:
```bash
python3 cie.py --scan /path/to/directory --chunk-size 65536 --max-workers 2
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
python3 cie.py --scan /path/to/directory --verbose
```

Check log files:
```bash
tail -f cie.log
```

### Performance Issues

#### Slow Scanning
- Increase `--max-workers` (up to CPU count × 2)
- Increase `--chunk-size` for large files
- Use `--fast-scan` for quick analysis

#### High Memory Usage
- Decrease `--chunk-size`
- Decrease `--max-workers`
- Use `--summary-only` to reduce output

#### Database Issues
- Run `make clean-all` to reset database
- Check disk space
- Verify write permissions

## Best Practices

### Regular Scanning

#### Automated Scans
Set up cron jobs for regular scanning:

```bash
# Daily scan of Documents directory
0 2 * * * /usr/bin/python3 /path/to/cie.py --scan ~/Documents --summary-only --output /var/log/cie_daily.log

# Weekly scan with quarantine
0 3 * * 0 /usr/bin/python3 /path/to/cie.py --scan ~/Documents --quarantine --json --output /var/log/cie_weekly.json
```

#### Critical Directories
Prioritize scanning:
- User documents and files
- Database files
- Configuration files
- Media files

### Quarantine Management

#### Regular Cleanup
Schedule regular quarantine cleanup:
```bash
# Weekly cleanup of old quarantined files
0 4 * * 0 find /path/to/quarantine -type f -mtime +30 -delete
```

#### Monitor Quarantine Size
Monitor quarantine directory size to prevent disk space issues.

### Performance Optimization

#### Large Directories
For large directories (>100,000 files):
- Use `--fast-scan` for initial analysis
- Increase `--max-workers`
- Consider splitting into smaller scans

#### Network Storage
For network drives:
- Reduce `--max-workers` to avoid overwhelming network
- Increase `--chunk-size` for better throughput
- Use `--no-recursive` for targeted scans

### Security Considerations

#### Sensitive Files
Be careful with sensitive files:
- Review quarantine contents before deletion
- Use encrypted storage for quarantine if needed
- Audit quarantine logs regularly

#### System Files
Avoid scanning system directories:
- Exclude `/proc`, `/sys`, `/dev` on Linux
- Exclude `C:\Windows\System32` on Windows
- Use `--skip-system-files` when available

### Backup Integration

#### Before Quarantine
Consider backing up files before quarantine:
```bash
# Create backup before quarantine
cp -r /path/to/important/files /backup/location/$(date +%Y%m%d)
python3 cie.py --scan /path/to/important/files --quarantine
```

#### After Detection
After detecting corruption:
- Restore from backup if available
- Investigate cause of corruption
- Implement preventive measures

### Integration with Other Tools

#### Antivirus Software
CIE complements antivirus software:
- CIE detects file corruption, not malware
- Use both for comprehensive protection
- Coordinate quarantine actions

#### Backup Systems
Integrate with backup systems:
- Scan backup archives for corruption
- Validate backup integrity regularly
- Use CIE results for backup planning

#### Monitoring Systems
Integrate with monitoring:
- Use `--fail-on-findings` for alerts
- Parse JSON output for metrics
- Set up notifications for corruption detection
