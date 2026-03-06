"""
Pytest configuration and shared fixtures for CIE tests.

This Project Is Made By Kanishk Soni
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Optional
import pytest
import sqlite3

# Add src to path for imports
import sys
project_root = Path(__file__).parent.parent
src_dir = project_root / "src"
sys.path.insert(0, str(src_dir))
sys.path.insert(0, str(src_dir / "python"))

from src.python.core_analyzer import AnalyzerConfig, CorruptionDetector


@pytest.fixture
def temp_directory():
    """Create a temporary directory for tests."""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir)


@pytest.fixture
def temp_file(temp_directory):
    """Create a temporary file in the temp directory."""
    def _create_temp_file(name: str, content: str = "", binary: bool = False) -> Path:
        file_path = temp_directory / name
        mode = "wb" if binary else "w"
        file_content = content.encode() if binary else content
        file_path.write_bytes(file_content) if binary else file_path.write_text(file_content)
        return file_path
    return _create_temp_file


@pytest.fixture
def analyzer_config():
    """Create a test analyzer configuration."""
    return AnalyzerConfig(
        db_path=":memory:",
        quarantine_dir=tempfile.mkdtemp(),
        chunk_size=1024,
        max_workers=2,
        entropy_threshold=7.95,
        detect_ransomware=True
    )


@pytest.fixture
def corruption_detector(analyzer_config):
    """Create a corruption detector instance for testing."""
    detector = CorruptionDetector(analyzer_config)
    yield detector
    # Cleanup
    if os.path.exists(analyzer_config.quarantine_dir):
        shutil.rmtree(analyzer_config.quarantine_dir)


@pytest.fixture
def sample_files(temp_directory):
    """Create sample files for testing."""
    files = {}
    
    # Valid text file
    files['valid_txt'] = temp_directory / "valid.txt"
    files['valid_txt'].write_text("This is a valid text file with normal content.")
    
    # Empty file
    files['empty'] = temp_directory / "empty.txt"
    files['empty'].write_text("")
    
    # Binary file with null bytes
    files['null_bytes'] = temp_directory / "null_bytes.bin"
    files['null_bytes'].write_bytes(b"Valid content\x00\x00\x00\x00\x00\x00\x00\x00")
    
    # Large file for testing
    files['large'] = temp_directory / "large.txt"
    files['large'].write_text("Large file content\n" * 10000)
    
    # High entropy file (simulated encrypted)
    files['high_entropy'] = temp_directory / "encrypted.bin"
    import os
    with open(files['high_entropy'], 'wb') as f:
        f.write(os.urandom(1024))  # Random high-entropy data
    
    # Valid JPEG header
    files['valid_jpg'] = temp_directory / "valid.jpg"
    files['valid_jpg'].write_bytes(b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xFF\xDB\x00C\x00')
    
    # Invalid JPEG (corrupted header)
    files['invalid_jpg'] = temp_directory / "invalid.jpg"
    files['invalid_jpg'].write_bytes(b"NOT A JPEG FILE")
    
    # Valid PDF header
    files['valid_pdf'] = temp_directory / "valid.pdf"
    files['valid_pdf'].write_bytes(b"%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n>>\nendobj\n%%EOF")
    
    # Invalid PDF
    files['invalid_pdf'] = temp_directory / "invalid.pdf"
    files['invalid_pdf'].write_bytes(b"Not a PDF file")
    
    # Valid ZIP file
    files['valid_zip'] = temp_directory / "valid.zip"
    files['valid_zip'].write_bytes(b"PK\x03\x04\x14\x00\x00\x00\x08\x00")
    
    # Invalid ZIP
    files['invalid_zip'] = temp_directory / "invalid.zip"
    files['invalid_zip'].write_bytes(b"Not a ZIP file")
    
    return files


@pytest.fixture
def quarantine_directory():
    """Create a temporary quarantine directory."""
    quarantine_dir = tempfile.mkdtemp()
    yield Path(quarantine_dir)
    shutil.rmtree(quarantine_dir)


@pytest.fixture
def mock_database():
    """Create an in-memory SQLite database for testing."""
    conn = sqlite3.connect(":memory:")
    
    # Create tables
    conn.execute("""
        CREATE TABLE file_metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE,
            file_size INTEGER,
            file_type TEXT,
            checksum TEXT,
            is_corrupted BOOLEAN,
            status TEXT,
            error_message TEXT,
            shannon_entropy REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.execute("""
        CREATE TABLE quarantine_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_path TEXT,
            quarantine_path TEXT,
            file_size INTEGER,
            checksum TEXT,
            quarantine_reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    yield conn
    conn.close()


@pytest.fixture
def library_status_mock():
    """Mock library status for testing."""
    return {
        "Pillow": True,
        "PyPDF2": True,
        "python-docx": False,
        "openpyxl": True,
        "ffmpeg": False,
        "python-magic": True
    }


@pytest.fixture(autouse=True)
def cleanup_temp_files():
    """Automatically cleanup temporary files after each test."""
    yield
    # Cleanup any remaining temp files
    temp_patterns = [
        "/tmp/cie_test_*",
        "/tmp/quarantine_test_*"
    ]
    
    import glob
    for pattern in temp_patterns:
        for temp_file in glob.glob(pattern):
            try:
                if os.path.isfile(temp_file):
                    os.remove(temp_file)
                elif os.path.isdir(temp_file):
                    shutil.rmtree(temp_file)
            except (OSError, IOError):
                pass


class MockValidator:
    """Mock validator for testing."""
    
    def __init__(self, is_valid: bool = True, error_message: Optional[str] = None):
        self.is_valid = is_valid
        self.error_message = error_message
    
    def validate(self, file_path: str):
        """Mock validation method."""
        from src.python.core_analyzer import FormatValidation
        
        if self.is_valid:
            return FormatValidation(
                is_valid=True,
                format_info={"mock": True}
            )
        else:
            return FormatValidation(
                is_valid=False,
                error_message=self.error_message or "Mock validation failed",
                corruption_details=["Mock error detail"]
            )


@pytest.fixture
def mock_validator():
    """Create a mock validator."""
    return MockValidator


@pytest.fixture
def mock_invalid_validator():
    """Create a mock validator that always fails."""
    return lambda: MockValidator(is_valid=False, error_message="Mock validation error")


def create_test_file_with_entropy(temp_path: Path, entropy: float) -> Path:
    """Create a test file with specific entropy."""
    import math
    
    if entropy <= 0:
        # All zeros
        data = b'\x00' * 1024
    elif entropy >= 8.0:
        # Maximum entropy (random data)
        import os
        data = os.urandom(1024)
    else:
        # Create data with target entropy
        # This is simplified - in practice you'd need more sophisticated generation
        import os
        data = bytearray()
        for i in range(1024):
            # Mix of predictable and random bytes to achieve target entropy
            if i < int((8 - entropy) * 128):
                data.append(0)  # Predictable
            else:
                data.append(os.urandom(1)[0])  # Random
        data = bytes(data)
    
    file_path = temp_path / f"entropy_{entropy:.2f}.bin"
    file_path.write_bytes(data)
    return file_path


@pytest.fixture
def entropy_files(temp_directory):
    """Create files with different entropy levels for testing."""
    entropy_levels = [0.0, 2.0, 4.0, 6.0, 7.5, 8.0]
    files = {}
    
    for entropy in entropy_levels:
        files[f"entropy_{entropy:.1f}"] = create_test_file_with_entropy(
            temp_directory, entropy
        )
    
    return files
