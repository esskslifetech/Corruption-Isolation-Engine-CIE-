# Developer Guide

This guide is for developers who want to contribute to, extend, or integrate with the Corruption Isolation Engine (CIE).

## Table of Contents

- [Development Setup](#development-setup)
- [Architecture Overview](#architecture-overview)
- [Code Organization](#code-organization)
- [Adding New Features](#adding-new-features)
- [Testing](#testing)
- [Debugging](#debugging)
- [Performance Optimization](#performance-optimization)
- [Contributing Guidelines](#contributing-guidelines)
- [API Extensions](#api-extensions)

## Development Setup

### Prerequisites

- Python 3.7+
- g++ (C++20 support)
- Git
- Make
- FFmpeg (for media file testing)

### Clone and Setup

```bash
git clone <repository-url>
cd Corruption_isolation_engine
./install_dependencies.sh
make cpp
python3 cie.py --self-test
```

### Development Environment

#### IDE Configuration

**VS Code:**
```json
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.flake8Enabled": true,
    "python.formatting.provider": "black"
}
```

**PyCharm:**
- Set project interpreter to virtual environment
- Configure code style with Black
- Enable type checking

#### Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows
pip install -r requirements.txt
pip install pytest pytest-cov black flake8 mypy
```

### Development Tools

```bash
# Code formatting
black src/ tests/ --line-length 100

# Linting
flake8 src/ tests/ --max-line-length=100

# Type checking
mypy src/python/

# Testing with coverage
pytest tests/ --cov=src/python --cov-report=term-missing
```

## Architecture Overview

### System Design

CIE follows a modular architecture with clear separation of concerns:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI/GUI       │    │   Core Engine   │    │   Validators    │
│                 │    │                 │    │                 │
│ • Argument      │◄──►│ • Scanning      │◄──►│ • Image         │
│   parsing       │    │ • Analysis      │    │ • PDF           │
│ • Output        │    │ • Database      │    │ • Archive       │
│ • GUI logic     │    │ • Quarantine    │    │ • Media         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Storage       │
                    │                 │
                    │ • SQLite DB     │
                    │ • File System   │
                    │ • Quarantine    │
                    └─────────────────┘
```

### Key Components

#### 1. Core Engine (`src/python/core_analyzer.py`)
- Main orchestration logic
- Concurrent processing
- Database operations
- Result aggregation

#### 2. Validators (`src/python/format_validators.py`)
- Format-specific validation
- Extensible validator system
- Plugin architecture

#### 3. Processing Pipeline (`src/python/processing_modules.py`)
- File processing stages
- Streaming analysis
- Memory management

#### 4. Mathematical Utilities (`src/python/cie_math.py`)
- Entropy calculations
- Binary pattern analysis
- Statistical operations

#### 5. C++ Module (`src/cpp/file_analyzer.cpp`)
- High-performance binary analysis
- Low-level file operations
- Performance-critical algorithms

## Code Organization

### Directory Structure

```
src/
├── python/
│   ├── __init__.py
│   ├── core_analyzer.py          # Main engine
│   ├── format_validators.py      # File validators
│   ├── processing_modules.py     # Processing pipeline
│   ├── cie_math.py                # Math utilities
│   └── modular_scanner.py        # Advanced scanning
├── cpp/
│   ├── file_analyzer.cpp         # C++ analyzer
│   └── (future C++ modules)
└── gui/
    ├── __init__.py
    └── main_window.py            # Tkinter GUI
```

### Module Dependencies

```
cie.py (entry point)
├── core_analyzer.py
│   ├── format_validators.py
│   ├── processing_modules.py
│   └── cie_math.py
├── modular_scanner.py
│   ├── core_analyzer.py
│   └── processing_modules.py
└── main_window.py
    └── core_analyzer.py
```

### Design Patterns

#### 1. Strategy Pattern
Used for different scanning strategies:

```python
class ScanStrategy(ABC):
    @abstractmethod
    def scan(self, directory: str) -> List[FileAnalysisResult]:
        pass

class FastScanStrategy(ScanStrategy):
    def scan(self, directory: str) -> List[FileAnalysisResult]:
        # Fast implementation
        pass

class DeepScanStrategy(ScanStrategy):
    def scan(self, directory: str) -> List[FileAnalysisResult]:
        # Deep implementation
        pass
```

#### 2. Factory Pattern
Used for creating validators:

```python
class ValidatorFactory:
    @staticmethod
    def create_validator(file_type: str) -> BaseValidator:
        if file_type == "PDF":
            return PDFValidator()
        elif file_type == "JPEG":
            return ImageValidator()
        # ... other validators
```

#### 3. Observer Pattern
Used for progress reporting:

```python
class ProgressObserver(ABC):
    @abstractmethod
    def on_progress(self, progress: float, message: str):
        pass

class ScanProgress:
    def __init__(self):
        self.observers: List[ProgressObserver] = []
    
    def add_observer(self, observer: ProgressObserver):
        self.observers.append(observer)
    
    def notify_progress(self, progress: float, message: str):
        for observer in self.observers:
            observer.on_progress(progress, message)
```

## Adding New Features

### Adding a New File Validator

1. **Create Validator Class**

```python
# src/python/format_validators.py

class CustomValidator(BaseValidator):
    """Custom file format validator."""
    
    SUPPORTED_EXTENSIONS = ['.custom']
    
    def validate(self, file_path: str) -> FormatValidation:
        try:
            # Custom validation logic
            with open(file_path, 'rb') as f:
                header = f.read(4)
                
            if not self._is_valid_header(header):
                return FormatValidation(
                    is_valid=False,
                    error_message="Invalid custom file header",
                    corruption_details=["Header validation failed"]
                )
            
            # Additional validation steps
            format_info = self._extract_format_info(file_path)
            
            return FormatValidation(
                is_valid=True,
                format_info=format_info
            )
            
        except Exception as e:
            return FormatValidation(
                is_valid=False,
                error_message=str(e)
            )
    
    def _is_valid_header(self, header: bytes) -> bool:
        # Implement header validation
        return header == b'CSF\x00'
    
    def _extract_format_info(self, file_path: str) -> dict:
        # Extract format-specific information
        return {"version": "1.0", "type": "custom"}
```

2. **Register Validator**

```python
# Update ValidatorFactory

class ValidatorFactory:
    _validators = {
        'PDF': PDFValidator,
        'JPEG': ImageValidator,
        'CUSTOM': CustomValidator,  # Add new validator
        # ... other validators
    }
```

3. **Add Tests**

```python
# tests/test_custom_validator.py

import unittest
from src.python.format_validators import CustomValidator

class TestCustomValidator(unittest.TestCase):
    def setUp(self):
        self.validator = CustomValidator()
    
    def test_valid_file(self):
        # Test with valid custom file
        result = self.validator.validate('test_data/valid.custom')
        self.assertTrue(result.is_valid)
    
    def test_invalid_file(self):
        # Test with invalid custom file
        result = self.validator.validate('test_data/invalid.custom')
        self.assertFalse(result.is_valid)
```

### Adding a New Scanning Strategy

1. **Create Strategy Class**

```python
# src/python/strategies/custom_strategy.py

from src.python.core_analyzer import ScanStrategy

class CustomScanStrategy(ScanStrategy):
    """Custom scanning strategy for specific use cases."""
    
    def __init__(self, config: AnalyzerConfig):
        self.config = config
    
    def scan(self, directory: str, recursive: bool = True) -> List[FileAnalysisResult]:
        # Custom scanning implementation
        results = []
        
        # Implement custom logic
        for file_path in self._get_files(directory, recursive):
            result = self._analyze_file(file_path)
            results.append(result)
        
        return results
    
    def _get_files(self, directory: str, recursive: bool) -> List[str]:
        # Custom file collection logic
        pass
    
    def _analyze_file(self, file_path: str) -> FileAnalysisResult:
        # Custom file analysis logic
        pass
```

2. **Register Strategy**

```python
# src/python/modular_scanner.py

SUPPORTED_STRATEGIES = ("fast", "balanced", "deep", "custom")

def create_strategy(strategy_name: str, config: AnalyzerConfig) -> ScanStrategy:
    if strategy_name == "custom":
        return CustomScanStrategy(config)
    # ... other strategies
```

### Adding New Database Tables

1. **Define Schema**

```python
# src/python/database.py

def create_custom_tables(conn: sqlite3.Connection):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS custom_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            custom_field TEXT,
            analysis_data BLOB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (file_id) REFERENCES file_metadata (id)
        )
    """)
```

2. **Update Data Models**

```python
# src/python/core_analyzer.py

@dataclass
class CustomAnalysisResult:
    file_id: int
    custom_field: str
    analysis_data: bytes
    created_at: datetime
```

3. **Add Database Operations**

```python
def save_custom_analysis(conn: sqlite3.Connection, result: CustomAnalysisResult):
    conn.execute("""
        INSERT INTO custom_analysis (file_id, custom_field, analysis_data)
        VALUES (?, ?, ?)
    """, (result.file_id, result.custom_field, result.analysis_data))
```

## Testing

### Test Structure

```
tests/
├── conftest.py                  # shared fixtures (corpus, detector, real-file builders)
├── test_core_analyzer.py        # detector, statuses, baselines, migration
├── test_format_validators.py    # per-format validators
├── test_processing_modules.py   # encodings, processors, strategies
├── test_cie_math.py             # entropy / variance / checksums
├── test_import_hygiene.py       # no stdlib shadowing, modules import standalone
└── test_cli.py                  # end-to-end CLI: scan, JSON, exit codes, quarantine
```

Run them with `make test`, or `python3 -m pytest tests/ -q`.

### Writing Tests

#### Unit Tests

```python
# tests/test_format_validators.py

import unittest
from unittest.mock import patch, mock_open
from src.python.format_validators import PDFValidator

class TestPDFValidator(unittest.TestCase):
    def setUp(self):
        self.validator = PDFValidator()
    
    def test_valid_pdf(self):
        with patch('builtins.open', mock_open(read_data=b'%PDF-1.4\n')):
            result = self.validator.validate('test.pdf')
            self.assertTrue(result.is_valid)
    
    def test_invalid_pdf(self):
        with patch('builtins.open', mock_open(read_data=b'Not a PDF')):
            result = self.validator.validate('test.pdf')
            self.assertFalse(result.is_valid)
            self.assertIn('Invalid PDF', result.error_message)
```

#### Integration Tests

```python
# tests/test_cli.py

import unittest
import tempfile
import os
from src.python.core_analyzer import CorruptionDetector, AnalyzerConfig

class TestFullScan(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.config = AnalyzerConfig(
            db_path=":memory:",
            quarantine_dir=tempfile.mkdtemp()
        )
        self.detector = CorruptionDetector(self.config)
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir)
        shutil.rmtree(self.config.quarantine_dir)
    
    def test_scan_directory_with_files(self):
        # Create test files
        with open(os.path.join(self.test_dir, 'test.txt'), 'w') as f:
            f.write('test content')
        
        results = self.detector.scan_directory(self.test_dir)
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].is_corrupted)
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/python --cov-report=html

# Run specific test file
pytest tests/test_core_analyzer.py

# Run with verbose output
pytest -v

# Run specific test method
pytest tests/test_core_analyzer.py::test_scan_directory_detects_corruption
```

### Test Data Management

#### Fixtures

```python
# tests/conftest.py

import pytest
import tempfile
import os

@pytest.fixture
def temp_directory():
    dir_path = tempfile.mkdtemp()
    yield dir_path
    import shutil
    shutil.rmtree(dir_path)

@pytest.fixture
def sample_files(temp_directory):
    files = {}
    for name, content in [
        ('valid.txt', 'valid content'),
        ('invalid.pdf', b'not a pdf'),
        ('empty.txt', '')
    ]:
        path = os.path.join(temp_directory, name)
        mode = 'w' if isinstance(content, str) else 'wb'
        with open(path, mode) as f:
            f.write(content)
        files[name] = path
    return files
```

## Debugging

### Logging Configuration

```python
import logging

# Enable debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('debug.log'),
        logging.StreamHandler()
    ]
)

# Specific module logging
logging.getLogger('src.python.core_analyzer').setLevel(logging.DEBUG)
```

### Debug Tools

#### Memory Profiling

```python
# Install: pip install memory-profiler
from memory_profiler import profile

@profile
def memory_intensive_function():
    # Function to profile
    pass
```

#### Performance Profiling

```python
import cProfile
import pstats

def profile_function():
    pr = cProfile.Profile()
    pr.enable()
    
    # Code to profile
    result = some_function()
    
    pr.disable()
    stats = pstats.Stats(pr)
    stats.sort_stats('cumulative')
    stats.print_stats(10)
    
    return result
```

#### Database Debugging

```python
# Enable SQLite debugging
import sqlite3

def debug_database():
    conn = sqlite3.connect('cie_database.db')
    conn.set_trace_callback(print)  # Print all SQL queries
    
    # Your database operations
    cursor = conn.execute("SELECT * FROM file_metadata LIMIT 5")
    for row in cursor:
        print(row)
    
    conn.close()
```

### Common Debugging Scenarios

#### Database Lock Issues

```python
# Check database locks
import sqlite3
import time

def check_database_locks(db_path: str):
    try:
        conn = sqlite3.connect(db_path, timeout=1)
        cursor = conn.execute("PRAGMA lock_status")
        print("Lock status:", cursor.fetchone())
        conn.close()
    except sqlite3.OperationalError as e:
        print(f"Database locked: {e}")
```

#### Thread Debugging

```python
import threading
import time

def debug_threads():
    print("Active threads:")
    for thread in threading.enumerate():
        print(f"  {thread.name}: {thread.is_alive()}")
    
    # Thread stack traces
    import traceback
    for thread_id, frame in sys._current_frames().items():
        print(f"\nThread {thread_id}:")
        traceback.print_stack(frame)
```

## Performance Optimization

### Profiling

#### CPU Profiling

```bash
# Profile Python code
python -m cProfile -o profile.stats src/python/core_analyzer.py

# Analyze results
python -c "
import pstats
p = pstats.Stats('profile.stats')
p.sort_stats('cumulative').print_stats(20)
"
```

#### Memory Profiling

```bash
# Memory profiling
python -m memory_profiler src/python/core_analyzer.py
```

#### I/O Profiling

```python
import time
import functools

def timing_decorator(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        end = time.perf_counter()
        print(f"{func.__name__}: {end - start:.4f}s")
        return result
    return wrapper

# Usage
@timing_decorator
def scan_directory(directory: str):
    # Scanning logic
    pass
```

### Optimization Techniques

#### 1. Concurrent Processing

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def optimized_scan(files: List[str], max_workers: int = 8):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(analyze_file, f): f for f in files}
        
        for future in as_completed(futures):
            file_path = futures[future]
            try:
                result = future.result()
                yield result
            except Exception as e:
                print(f"Error analyzing {file_path}: {e}")
```

#### 2. Memory-Efficient Processing

```python
def stream_analyze_file(file_path: str, chunk_size: int = 65536):
    """Analyze file using streaming to reduce memory usage."""
    sha256_hash = hashlib.sha256()
    entropy_calculator = EntropyCalculator()
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(chunk_size):
            sha256_hash.update(chunk)
            entropy_calculator.update(chunk)
    
    return {
        'checksum': sha256_hash.hexdigest(),
        'entropy': entropy_calculator.entropy()
    }
```

#### 3. Database Optimization

```python
# Batch database operations
def batch_insert_results(conn: sqlite3.Connection, results: List[FileAnalysisResult]):
    cursor = conn.cursor()
    data = [
        (r.file_path, r.file_size, r.checksum, r.is_corrupted)
        for r in results
    ]
    
    cursor.executemany("""
        INSERT INTO file_metadata (file_path, file_size, checksum, is_corrupted)
        VALUES (?, ?, ?, ?)
    """, data)
    conn.commit()
```

#### 4. Caching

```python
from functools import lru_cache
import time

@lru_cache(maxsize=1024)
def cached_file_type_detection(file_path: str, file_size: int, mtime: float):
    """Cache file type detection results."""
    # Expensive file type detection
    return detect_file_type(file_path)

# Usage with file metadata for cache invalidation
def get_file_type(file_path: str):
    stat = os.stat(file_path)
    return cached_file_type_detection(file_path, stat.st_size, stat.st_mtime)
```

## Contributing Guidelines

### Code Style

#### Python

- Use Black for formatting (line length 100)
- Follow PEP 8 guidelines
- Use type hints where possible
- Write docstrings for all public functions

```python
def analyze_file(file_path: str, config: AnalyzerConfig) -> FileAnalysisResult:
    """
    Analyze a file for corruption.
    
    Args:
        file_path: Path to the file to analyze
        config: Analyzer configuration
        
    Returns:
        FileAnalysisResult: Analysis result
        
    Raises:
        FileAccessError: If file cannot be accessed
    """
    # Implementation
    pass
```

#### C++

- Follow Google C++ Style Guide
- Use clang-format for formatting
- Include proper headers
- Use RAII principles

```cpp
#include <fstream>
#include <string>

class FileAnalyzer {
public:
    explicit FileAnalyzer(const std::string& file_path);
    
    bool analyze() const;
    
private:
    std::string file_path_;
    
    bool validate_header() const;
    bool calculate_checksum() const;
};
```

### Pull Request Process

1. **Fork Repository**
2. **Create Feature Branch**
   ```bash
   git checkout -b feature/new-validator
   ```

3. **Make Changes**
   - Write code
   - Add tests
   - Update documentation

4. **Run Tests**
   ```bash
   pytest
   black --check src/ tests/
   flake8 src/ tests/
   ```

5. **Commit Changes**
   ```bash
   git add .
   git commit -m "Add new custom file validator"
   ```

6. **Push and Create PR**
   ```bash
   git push origin feature/new-validator
   ```

### Commit Message Format

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style
- `refactor`: Refactoring
- `test`: Tests
- `chore`: Maintenance

Examples:
```
feat(validators): add custom file format validator

- Implement CustomValidator class
- Add unit tests
- Update documentation

Closes #123
```

### Code Review Guidelines

#### What to Review

1. **Functionality**: Does the code work as intended?
2. **Performance**: Is the code efficient?
3. **Security**: Are there any security vulnerabilities?
4. **Style**: Does the code follow style guidelines?
5. **Tests**: Are tests comprehensive?
6. **Documentation**: Is documentation updated?

#### Review Checklist

- [ ] Code follows style guidelines
- [ ] Tests are added and passing
- [ ] Documentation is updated
- [ ] No obvious security issues
- [ ] Performance is acceptable
- [ ] Error handling is appropriate
- [ ] Code is readable and maintainable

## API Extensions

### Plugin System

#### Plugin Interface

```python
# src/python/plugins/base.py

from abc import ABC, abstractmethod

class CIEPlugin(ABC):
    """Base class for CIE plugins."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name."""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version."""
        pass
    
    @abstractmethod
    def initialize(self, config: dict) -> None:
        """Initialize plugin with configuration."""
        pass
    
    @abstractmethod
    def cleanup(self) -> None:
        """Cleanup plugin resources."""
        pass
```

#### Validator Plugin

```python
# src/python/plugins/validator_plugin.py

class ValidatorPlugin(CIEPlugin):
    """Plugin for adding custom validators."""
    
    def __init__(self):
        self.validators = {}
    
    @property
    def name(self) -> str:
        return "Custom Validator Plugin"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def initialize(self, config: dict) -> None:
        # Register custom validators
        for validator_config in config.get('validators', []):
            validator = self.create_validator(validator_config)
            self.validators[validator.name] = validator
    
    def register_validator(self, name: str, validator_class: type):
        """Register a new validator."""
        self.validators[name] = validator_class
    
    def get_validator(self, name: str) -> BaseValidator:
        """Get registered validator."""
        return self.validators.get(name)
```

### REST API Extension

#### Flask API Server

```python
# src/api/server.py

from flask import Flask, request, jsonify
from src.python.core_analyzer import CorruptionDetector, AnalyzerConfig

app = Flask(__name__)
detector = None

@app.route('/api/scan', methods=['POST'])
def scan_directory():
    data = request.json
    directory = data.get('directory')
    recursive = data.get('recursive', True)
    
    try:
        results = detector.scan_directory(directory, recursive)
        return jsonify({
            'status': 'success',
            'results': [result_to_dict(r) for r in results]
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/quarantine/<path:file_path>', methods=['POST'])
def quarantine_file(file_path):
    try:
        success = detector.quarantine_file(file_path)
        return jsonify({
            'status': 'success' if success else 'failed',
            'file_path': file_path
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def create_api_server(config: AnalyzerConfig):
    global detector
    detector = CorruptionDetector(config)
    return app
```

### CLI Extensions

#### Custom Commands

```python
# src/cli/commands.py

import click
from src.python.core_analyzer import CorruptionDetector, AnalyzerConfig

@click.group()
def cli():
    """CIE CLI extensions."""
    pass

@cli.command()
@click.argument('directory')
@click.option('--strategy', default='fast', help='Scanning strategy')
@click.option('--output', help='Output file')
def scan(directory, strategy, output):
    """Enhanced scan command."""
    config = AnalyzerConfig()
    detector = CorruptionDetector(config)
    
    # Custom scanning logic
    results = detector.scan_directory(directory)
    
    if output:
        with open(output, 'w') as f:
            json.dump([result_to_dict(r) for r in results], f, indent=2)
    else:
        for result in results:
            if result.is_corrupted:
                click.echo(f"Corrupted: {result.file_path}")

# Register custom commands
cie_cli = click.CommandCollection(sources=[cli, original_cli])
```

This developer guide provides comprehensive information for extending and contributing to the CIE project. It covers architecture, testing, debugging, performance optimization, and best practices for maintaining code quality.
