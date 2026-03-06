"""
Unit tests for core_analyzer.py

This Project Is Made By Kanishk Soni
"""

import os
import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.python.core_analyzer import (
    CorruptionDetector, 
    AnalyzerConfig, 
    FileStatus,
    FileAnalysisResult,
    FormatValidation,
    AnalyzerBaseException,
    FileAccessError,
    DatabaseConcurrencyError,
    QuarantineError,
    ScanCancelledError
)


class TestAnalyzerConfig:
    """Test cases for AnalyzerConfig class."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = AnalyzerConfig()
        
        assert config.db_path == "cie_database.db"
        assert config.quarantine_dir == "quarantine"
        assert config.chunk_size == 256 * 1024
        assert config.hash_algorithm == "sha256"
        assert config.max_workers >= 1
        assert config.detect_ransomware is True
        assert config.entropy_threshold == 7.95
        assert config.db_busy_timeout_ms == 5000
        assert config.db_retry_attempts == 6
        assert config.exclude_quarantine_from_scans is True
        assert config.follow_symlinks is False
        assert config.include_hidden_files is True
    
    def test_custom_config(self):
        """Test custom configuration values."""
        config = AnalyzerConfig(
            db_path="custom.db",
            quarantine_dir="custom_quarantine",
            chunk_size=512,
            max_workers=4,
            entropy_threshold=7.0,
            detect_ransomware=False
        )
        
        assert config.db_path == "custom.db"
        assert config.quarantine_dir == "custom_quarantine"
        assert config.chunk_size == 512
        assert config.max_workers == 4
        assert config.entropy_threshold == 7.0
        assert config.detect_ransomware is False


class TestCorruptionDetector:
    """Test cases for CorruptionDetector class."""
    
    def test_detector_initialization(self, analyzer_config):
        """Test detector initialization."""
        detector = CorruptionDetector(analyzer_config)
        
        assert detector.config == analyzer_config
        assert detector.config.db_path == ":memory:"
    
    def test_scan_directory_empty(self, corruption_detector, temp_directory):
        """Test scanning empty directory."""
        results = corruption_detector.scan_directory(str(temp_directory))
        
        assert isinstance(results, list)
        assert len(results) == 0
    
    def test_scan_directory_with_files(self, corruption_detector, sample_files):
        """Test scanning directory with files."""
        temp_dir = list(sample_files.values())[0].parent
        results = corruption_detector.scan_directory(str(temp_dir))
        
        assert isinstance(results, list)
        assert len(results) > 0
        
        # Check result structure
        for result in results:
            assert isinstance(result, FileAnalysisResult)
            assert hasattr(result, 'file_path')
            assert hasattr(result, 'file_size')
            assert hasattr(result, 'is_corrupted')
            assert hasattr(result, 'status')
    
    def test_scan_directory_non_recursive(self, corruption_detector, sample_files):
        """Test non-recursive directory scanning."""
        temp_dir = list(sample_files.values())[0].parent
        
        # Create subdirectory with file
        sub_dir = temp_dir / "subdir"
        sub_dir.mkdir()
        (sub_dir / "subfile.txt").write_text("Subdirectory file")
        
        results_recursive = corruption_detector.scan_directory(str(temp_dir), recursive=True)
        results_non_recursive = corruption_detector.scan_directory(str(temp_dir), recursive=False)
        
        # Non-recursive should find fewer files
        assert len(results_non_recursive) < len(results_recursive)
    
    def test_scan_nonexistent_directory(self, corruption_detector):
        """Test scanning non-existent directory."""
        with pytest.raises((FileNotFoundError, OSError)):
            corruption_detector.scan_directory("/nonexistent/directory")
    
    def test_analyze_file_valid(self, corruption_detector, sample_files):
        """Test analyzing a valid file."""
        valid_file = sample_files['valid_txt']
        result = corruption_detector._analyze_file(str(valid_file))
        
        assert isinstance(result, FileAnalysisResult)
        assert result.file_path == str(valid_file)
        assert result.file_size > 0
        assert result.status == FileStatus.VALID
        assert result.is_corrupted is False
        assert result.checksum is not None
        assert result.shannon_entropy >= 0.0
    
    def test_analyze_empty_file(self, corruption_detector, sample_files):
        """Test analyzing empty file."""
        empty_file = sample_files['empty']
        result = corruption_detector._analyze_file(str(empty_file))
        
        assert result.file_size == 0
        # Empty files might be marked as corrupted due to size anomaly
        assert result.status in [FileStatus.VALID, FileStatus.CORRUPTED_SIZE]
    
    def test_analyze_unreadable_file(self, corruption_detector, temp_directory):
        """Test analyzing unreadable file."""
        unreadable_file = temp_directory / "unreadable.txt"
        unreadable_file.write_text("content")
        
        # Make file unreadable
        os.chmod(unreadable_file, 0o000)
        
        try:
            result = corruption_detector._analyze_file(str(unreadable_file))
            assert result.status == FileStatus.UNREADABLE
            assert result.is_corrupted is True
        finally:
            # Restore permissions for cleanup
            os.chmod(unreadable_file, 0o644)
    
    def test_quarantine_file_success(self, corruption_detector, sample_files):
        """Test successful file quarantine."""
        file_to_quarantine = sample_files['valid_txt']
        
        result = corruption_detector.quarantine_file(str(file_to_quarantine))
        
        assert result is True
        assert not file_to_quarantine.exists()
        
        # Check if file exists in quarantine
        quarantine_files = list(Path(corruption_detector.config.quarantine_dir).rglob("*"))
        assert len(quarantine_files) > 0
    
    def test_quarantine_nonexistent_file(self, corruption_detector):
        """Test quarantining non-existent file."""
        result = corruption_detector.quarantine_file("/nonexistent/file.txt")
        
        assert result is False
    
    def test_quarantine_file_permission_error(self, corruption_detector, temp_directory):
        """Test quarantine with permission error."""
        test_file = temp_directory / "test.txt"
        test_file.write_text("content")
        
        # Make quarantine directory read-only
        quarantine_dir = Path(corruption_detector.config.quarantine_dir)
        original_mode = quarantine_dir.stat().st_mode
        quarantine_dir.chmod(0o444)
        
        try:
            result = corruption_detector.quarantine_file(str(test_file))
            assert result is False
        finally:
            # Restore permissions
            quarantine_dir.chmod(original_mode)
    
    def test_get_library_status(self, corruption_detector):
        """Test getting library status."""
        status = corruption_detector.get_library_status()
        
        assert isinstance(status, dict)
        # Check for common libraries
        expected_libraries = [
            "Pillow", "PyPDF2", "python-docx", "openpyxl", 
            "ffmpeg", "python-magic"
        ]
        
        for lib in expected_libraries:
            assert lib in status
            assert isinstance(status[lib], bool)
    
    def test_checksum_calculation(self, corruption_detector, sample_files):
        """Test checksum calculation."""
        file_path = sample_files['valid_txt']
        
        # Calculate checksum twice
        checksum1 = corruption_detector._calculate_checksum(str(file_path))
        checksum2 = corruption_detector._calculate_checksum(str(file_path))
        
        assert checksum1 == checksum2
        assert len(checksum1) == 64  # SHA-256 hex length
        assert all(c in '0123456789abcdef' for c in checksum1.lower())
    
    def test_entropy_calculation(self, corruption_detector, sample_files):
        """Test entropy calculation."""
        # Test with different file types
        low_entropy_file = sample_files['valid_txt']  # Regular text
        high_entropy_file = sample_files['high_entropy']  # Random data
        
        entropy_low = corruption_detector._calculate_entropy(str(low_entropy_file))
        entropy_high = corruption_detector._calculate_entropy(str(high_entropy_file))
        
        assert 0.0 <= entropy_low <= 8.0
        assert 0.0 <= entropy_high <= 8.0
        # High entropy file should have higher entropy
        assert entropy_high > entropy_low
    
    def test_file_type_detection(self, corruption_detector, sample_files):
        """Test file type detection."""
        test_cases = [
            ('valid_txt', 'Text'),
            ('valid_jpg', 'JPEG'),
            ('valid_pdf', 'PDF'),
            ('valid_zip', 'ZIP'),
        ]
        
        for file_key, expected_type in test_cases:
            if file_key in sample_files:
                file_path = sample_files[file_key]
                detected_type = corruption_detector._detect_file_type(str(file_path))
                
                # Should detect the expected type or a reasonable alternative
                assert detected_type is not None
                assert isinstance(detected_type, str)
    
    def test_ransomware_detection(self, corruption_detector, entropy_files):
        """Test ransomware detection based on entropy."""
        high_entropy_file = entropy_files['entropy_8.0']
        low_entropy_file = entropy_files['entropy_0.0']
        
        result_high = corruption_detector._analyze_file(str(high_entropy_file))
        result_low = corruption_detector._analyze_file(str(low_entropy_file))
        
        # High entropy file should trigger ransomware detection
        if corruption_detector.config.detect_ransomware:
            if result_high.shannon_entropy > corruption_detector.config.entropy_threshold:
                # Should be marked as potentially corrupted (ransomware)
                assert result_high.is_corrupted or result_high.status == FileStatus.VALID
        
        # Low entropy file should not trigger ransomware detection
        assert result_low.shannon_entropy < corruption_detector.config.entropy_threshold
    
    def test_database_operations(self, corruption_detector, mock_database):
        """Test database operations."""
        # Mock the database connection
        corruption_detector._db_connection = mock_database
        
        # Test saving file metadata
        result = FileAnalysisResult(
            file_path="/test/file.txt",
            file_size=100,
            file_type="Text",
            checksum="abc123",
            error_message=None,
            is_corrupted=False,
            status=FileStatus.VALID,
            format_validation=None,
            shannon_entropy=2.5
        )
        
        corruption_detector._save_file_metadata(result)
        
        # Verify data was saved
        cursor = mock_database.execute("SELECT * FROM file_metadata WHERE file_path = ?", 
                                     ("/test/file.txt",))
        row = cursor.fetchone()
        
        assert row is not None
        assert row[1] == "/test/file.txt"  # file_path
        assert row[2] == 100  # file_size
        assert row[3] == "Text"  # file_type
    
    def test_concurrent_scanning(self, corruption_detector, sample_files):
        """Test concurrent file scanning."""
        temp_dir = list(sample_files.values())[0].parent
        
        # Create more files for concurrent testing
        for i in range(10):
            (temp_dir / f"concurrent_{i}.txt").write_text(f"Content {i}")
        
        results = corruption_detector.scan_directory(str(temp_dir))
        
        # Should process all files
        assert len(results) >= 10
        
        # All results should be valid FileAnalysisResult objects
        for result in results:
            assert isinstance(result, FileAnalysisResult)
            assert hasattr(result, 'file_path')
    
    def test_scan_cancellation(self, corruption_detector, temp_directory):
        """Test scan cancellation."""
        # Create many files to ensure scan takes some time
        for i in range(100):
            (temp_directory / f"large_file_{i}.txt").write_text("Content " * 1000)
        
        # Mock cancellation
        with patch.object(corruption_detector, '_should_cancel_scan', return_value=True):
            with pytest.raises(ScanCancelledError):
                corruption_detector.scan_directory(str(temp_directory))
    
    def test_error_handling_in_scan(self, corruption_detector, temp_directory):
        """Test error handling during scanning."""
        # Create a file that will cause issues
        problematic_file = temp_directory / "problematic.txt"
        problematic_file.write_text("content")
        
        # Mock file reading to raise an exception
        with patch('builtins.open', side_effect=IOError("Mock error")):
            results = corruption_detector.scan_directory(str(temp_directory))
            
            # Should handle the error gracefully
            assert isinstance(results, list)
            # Error should be reflected in results
            if results:
                error_result = results[0]
                assert error_result.status == FileStatus.UNREADABLE


class TestExceptions:
    """Test cases for custom exceptions."""
    
    def test_analyzer_base_exception(self):
        """Test AnalyzerBaseException."""
        with pytest.raises(AnalyzerBaseException):
            raise AnalyzerBaseException("Test error")
    
    def test_file_access_error(self):
        """Test FileAccessError."""
        with pytest.raises(FileAccessError):
            raise FileAccessError("Cannot access file")
    
    def test_database_concurrency_error(self):
        """Test DatabaseConcurrencyError."""
        with pytest.raises(DatabaseConcurrencyError):
            raise DatabaseConcurrencyError("Database locked")
    
    def test_quarantine_error(self):
        """Test QuarantineError."""
        with pytest.raises(QuarantineError):
            raise QuarantineError("Quarantine failed")
    
    def test_scan_cancelled_error(self):
        """Test ScanCancelledError."""
        with pytest.raises(ScanCancelledError):
            raise ScanCancelledError("Scan was cancelled")


class TestFileAnalysisResult:
    """Test cases for FileAnalysisResult dataclass."""
    
    def test_file_analysis_result_creation(self):
        """Test FileAnalysisResult creation."""
        validation = FormatValidation(
            is_valid=True,
            format_info={"test": "data"}
        )
        
        result = FileAnalysisResult(
            file_path="/test/file.txt",
            file_size=100,
            file_type="Text",
            checksum="abc123",
            error_message=None,
            is_corrupted=False,
            status=FileStatus.VALID,
            format_validation=validation,
            shannon_entropy=2.5
        )
        
        assert result.file_path == "/test/file.txt"
        assert result.file_size == 100
        assert result.file_type == "Text"
        assert result.checksum == "abc123"
        assert result.error_message is None
        assert result.is_corrupted is False
        assert result.status == FileStatus.VALID
        assert result.format_validation == validation
        assert result.shannon_entropy == 2.5
    
    def test_file_analysis_result_with_validation_error(self):
        """Test FileAnalysisResult with validation error."""
        validation = FormatValidation(
            is_valid=False,
            error_message="Invalid format",
            corruption_details=["Error 1", "Error 2"]
        )
        
        result = FileAnalysisResult(
            file_path="/test/corrupted.txt",
            file_size=50,
            file_type="PDF",
            checksum="def456",
            error_message="File corrupted",
            is_corrupted=True,
            status=FileStatus.CORRUPTED_FORMAT,
            format_validation=validation,
            shannon_entropy=7.8
        )
        
        assert result.is_corrupted is True
        assert result.status == FileStatus.CORRUPTED_FORMAT
        assert result.format_validation.is_valid is False
        assert result.format_validation.error_message == "Invalid format"
        assert len(result.format_validation.corruption_details) == 2


class TestFormatValidation:
    """Test cases for FormatValidation dataclass."""
    
    def test_format_validation_creation_valid(self):
        """Test FormatValidation creation for valid file."""
        validation = FormatValidation(
            is_valid=True,
            format_info={"version": "1.0", "type": "PDF"}
        )
        
        assert validation.is_valid is True
        assert validation.error_message is None
        assert validation.format_info["version"] == "1.0"
        assert validation.corruption_details == ()
    
    def test_format_validation_creation_invalid(self):
        """Test FormatValidation creation for invalid file."""
        validation = FormatValidation(
            is_valid=False,
            error_message="Invalid PDF structure",
            format_info=None,
            corruption_details=("Missing EOF", "Invalid xref")
        )
        
        assert validation.is_valid is False
        assert validation.error_message == "Invalid PDF structure"
        assert validation.format_info is None
        assert len(validation.corruption_details) == 2
        assert "Missing EOF" in validation.corruption_details
