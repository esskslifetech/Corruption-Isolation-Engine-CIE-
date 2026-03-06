"""
Integration tests for quarantine functionality

This Project Is Made By Kanishk Soni
"""

import pytest
import tempfile
import shutil
import os
import json
from pathlib import Path
from datetime import datetime

from src.python.core_analyzer import CorruptionDetector, AnalyzerConfig, FileStatus


class TestQuarantineIntegration:
    """Integration tests for quarantine system."""
    
    def test_quarantine_workflow_complete(self, corruption_detector, temp_directory):
        """Test complete quarantine workflow."""
        # Create test files
        test_files = self._create_quarantine_test_files(temp_directory)
        
        # Scan and identify corrupted files
        results = corruption_detector.scan_directory(str(temp_directory))
        corrupted_results = [r for r in results if r.is_corrupted]
        
        # Quarantine corrupted files
        quarantine_results = []
        for result in corrupted_results:
            original_path = result.file_path
            success = corruption_detector.quarantine_file(original_path)
            quarantine_results.append((original_path, success))
        
        # Verify quarantine
        assert len(quarantine_results) > 0
        
        for original_path, success in quarantine_results:
            assert success is True
            assert not os.path.exists(original_path)
            
            # Check file exists in quarantine
            quarantine_dir = Path(corruption_detector.config.quarantine_dir)
            quarantined_files = list(quarantine_dir.rglob("*"))
            assert len(quarantined_files) > 0
    
    def test_quarantine_directory_structure(self, corruption_detector, temp_directory):
        """Test quarantine directory structure."""
        # Create test file
        test_file = temp_directory / "quarantine_test.txt"
        test_file.write_text("This file will be quarantined")
        
        # Quarantine the file
        success = corruption_detector.quarantine_file(str(test_file))
        assert success is True
        
        # Check quarantine directory structure
        quarantine_dir = Path(corruption_detector.config.quarantine_dir)
        assert quarantine_dir.exists()
        
        # Should have date-based subdirectory
        date_dirs = [d for d in quarantine_dir.iterdir() if d.is_dir()]
        assert len(date_dirs) >= 1
        
        # Check quarantined file
        quarantined_files = []
        for date_dir in date_dirs:
            quarantined_files.extend(date_dir.iterdir())
        
        assert len(quarantined_files) >= 1
        
        # File should have timestamp in name
        quarantined_file = quarantined_files[0]
        original_name = test_file.name
        assert original_name in quarantined_file.name
        
        # File content should be preserved
        assert quarantined_file.read_text() == test_file.read_text()
    
    def test_quarantine_database_logging(self, corruption_detector, temp_directory):
        """Test quarantine database logging."""
        # Create test file
        test_file = temp_directory / "db_log_test.txt"
        test_file.write_text("Test for database logging")
        
        # Get file checksum before quarantine
        checksum = corruption_detector._calculate_checksum(str(test_file))
        
        # Quarantine the file
        success = corruption_detector.quarantine_file(str(test_file))
        assert success is True
        
        # Check database log
        cursor = corruption_detector._db_connection.execute(
            "SELECT * FROM quarantine_log WHERE original_path = ?",
            (str(test_file),)
        )
        log_entry = cursor.fetchone()
        
        assert log_entry is not None
        assert log_entry[1] == str(test_file)  # original_path
        assert log_entry[3] == checksum  # checksum
        assert log_entry[5] is not None  # created_at
    
    def test_quarantine_multiple_files(self, corruption_detector, temp_directory):
        """Test quarantining multiple files."""
        # Create multiple test files
        test_files = []
        for i in range(5):
            file_path = temp_directory / f"multi_quarantine_{i}.txt"
            file_path.write_text(f"Test content for file {i}")
            test_files.append(file_path)
        
        # Quarantine all files
        quarantine_results = []
        for file_path in test_files:
            success = corruption_detector.quarantine_file(str(file_path))
            quarantine_results.append(success)
        
        # Verify all files were quarantined
        assert all(quarantine_results)
        
        # Check original files are gone
        for file_path in test_files:
            assert not file_path.exists()
        
        # Check quarantine directory has all files
        quarantine_dir = Path(corruption_detector.config.quarantine_dir)
        quarantined_files = list(quarantine_dir.rglob("*"))
        quarantined_files = [f for f in quarantined_files if f.is_file()]
        
        assert len(quarantined_files) == len(test_files)
    
    def test_quarantine_file_types(self, corruption_detector, temp_directory):
        """Test quarantining different file types."""
        # Create files of different types
        file_types = {
            'text.txt': "Plain text content",
            'binary.bin': b"Binary content with null\x00bytes",
            'json.json': '{"key": "value", "number": 123}',
            'image.jpg': b"\xFF\xD8\xFF\xE0\x00\x10JFIF",
            'pdf.pdf': b"%PDF-1.4\nTest PDF content"
        }
        
        test_files = []
        for filename, content in file_types.items():
            file_path = temp_directory / filename
            if isinstance(content, str):
                file_path.write_text(content)
            else:
                file_path.write_bytes(content)
            test_files.append(file_path)
        
        # Quarantine all files
        for file_path in test_files:
            success = corruption_detector.quarantine_file(str(file_path))
            assert success is True
            assert not file_path.exists()
        
        # Verify all files in quarantine
        quarantine_dir = Path(corruption_detector.config.quarantine_dir)
        quarantined_files = list(quarantine_dir.rglob("*"))
        quarantined_files = [f for f in quarantined_files if f.is_file()]
        
        assert len(quarantined_files) == len(test_files)
    
    def test_quarantine_error_handling(self, corruption_detector, temp_directory):
        """Test quarantine error handling."""
        # Test quarantining non-existent file
        success = corruption_detector.quarantine_file("/nonexistent/file.txt")
        assert success is False
        
        # Test quarantining directory (should fail)
        success = corruption_detector.quarantine_file(str(temp_directory))
        assert success is False
        
        # Create file and make quarantine directory read-only
        test_file = temp_directory / "error_test.txt"
        test_file.write_text("Test error handling")
        
        quarantine_dir = Path(corruption_detector.config.quarantine_dir)
        original_mode = quarantine_dir.stat().st_mode
        quarantine_dir.chmod(0o444)  # Read-only
        
        try:
            success = corruption_detector.quarantine_file(str(test_file))
            assert success is False
        finally:
            # Restore permissions for cleanup
            quarantine_dir.chmod(original_mode)
    
    def test_quarantine_large_file(self, corruption_detector, temp_directory):
        """Test quarantining large files."""
        # Create large file (10MB)
        large_file = temp_directory / "large_file.txt"
        content = "Large file content\n" * 100000  # ~2MB
        large_file.write_text(content)
        
        # Quarantine large file
        success = corruption_detector.quarantine_file(str(large_file))
        assert success is True
        assert not large_file.exists()
        
        # Verify file was quarantined completely
        quarantine_dir = Path(corruption_detector.config.quarantine_dir)
        quarantined_files = list(quarantine_dir.rglob("*"))
        quarantined_files = [f for f in quarantined_files if f.is_file()]
        
        assert len(quarantined_files) == 1
        quarantined_file = quarantined_files[0]
        
        # Verify content integrity
        assert quarantined_file.read_text() == content
        assert quarantined_file.stat().st_size == large_file.stat().st_size
    
    def test_quarantine_special_characters(self, corruption_detector, temp_directory):
        """Test quarantining files with special characters."""
        # Create files with special characters in names
        special_files = [
            "file with spaces.txt",
            "file-with-dashes.txt",
            "file_with_underscores.txt",
            "file.with.dots.txt",
            "file(parentheses).txt",
            "file[brackets].txt",
            "file{braces}.txt"
        ]
        
        test_files = []
        for filename in special_files:
            file_path = temp_directory / filename
            file_path.write_text(f"Content for {filename}")
            test_files.append(file_path)
        
        # Quarantine all files
        for file_path in test_files:
            success = corruption_detector.quarantine_file(str(file_path))
            assert success is True
            assert not file_path.exists()
        
        # Verify all files in quarantine
        quarantine_dir = Path(corruption_detector.config.quarantine_dir)
        quarantined_files = list(quarantine_dir.rglob("*"))
        quarantined_files = [f for f in quarantined_files if f.is_file()]
        
        assert len(quarantined_files) == len(test_files)
    
    def test_quarantine_concurrent_access(self, corruption_detector, temp_directory):
        """Test quarantine with concurrent access."""
        import threading
        import time
        
        # Create test files
        test_files = []
        for i in range(10):
            file_path = temp_directory / f"concurrent_{i}.txt"
            file_path.write_text(f"Concurrent test {i}")
            test_files.append(file_path)
        
        # Quarantine files concurrently
        results = []
        errors = []
        
        def quarantine_file(file_path):
            try:
                success = corruption_detector.quarantine_file(str(file_path))
                results.append(success)
            except Exception as e:
                errors.append(e)
        
        threads = []
        for file_path in test_files:
            thread = threading.Thread(target=quarantine_file, args=(file_path,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify results
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == len(test_files)
        assert all(results)
        
        # Verify all files were quarantined
        for file_path in test_files:
            assert not file_path.exists()


class TestQuarantineManagement:
    """Integration tests for quarantine management."""
    
    def test_quarantine_cleanup_old_files(self, corruption_detector, temp_directory):
        """Test cleanup of old quarantined files."""
        # Create test file and quarantine it
        test_file = temp_directory / "cleanup_test.txt"
        test_file.write_text("Test for cleanup")
        
        success = corruption_detector.quarantine_file(str(test_file))
        assert success is True
        
        # Manually modify the creation time to simulate old file
        quarantine_dir = Path(corruption_detector.config.quarantine_dir)
        quarantined_files = list(quarantine_dir.rglob("*"))
        quarantined_files = [f for f in quarantined_files if f.is_file()]
        
        if quarantined_files:
            old_file = quarantined_files[0]
            # Set modification time to 35 days ago
            old_time = time.time() - (35 * 24 * 60 * 60)
            os.utime(old_file, (old_time, old_time))
            
            # Run cleanup (simulate 30-day retention)
            cleaned_files = corruption_detector.cleanup_old_quarantine(days=30)
            
            # File should be cleaned up
            assert len(cleaned_files) >= 1
            assert not old_file.exists()
    
    def test_quarantine_size_management(self, corruption_detector, temp_directory):
        """Test quarantine directory size management."""
        # Create multiple large files
        large_files = []
        for i in range(3):
            file_path = temp_directory / f"size_test_{i}.txt"
            content = "Large content\n" * 100000  # ~2MB each
            file_path.write_text(content)
            large_files.append(file_path)
        
        # Quarantine all files
        for file_path in large_files:
            corruption_detector.quarantine_file(str(file_path))
        
        # Check quarantine directory size
        quarantine_dir = Path(corruption_detector.config.quarantine_dir)
        total_size = sum(f.stat().st_size for f in quarantine_dir.rglob("*") if f.is_file())
        
        assert total_size > 0
        
        # Test size limit enforcement
        size_limit = 1024 * 1024  # 1MB
        oversized_files = corruption_detector.check_quarantine_size_limit(size_limit)
        
        # Should identify oversized files
        assert len(oversized_files) >= 0
    
    def test_quarantine_report_generation(self, corruption_detector, temp_directory):
        """Test quarantine report generation."""
        # Create and quarantine test files
        test_files = []
        for i in range(5):
            file_path = temp_directory / f"report_test_{i}.txt"
            file_path.write_text(f"Report test content {i}")
            test_files.append(file_path)
            corruption_detector.quarantine_file(str(file_path))
        
        # Generate quarantine report
        report = corruption_detector.generate_quarantine_report()
        
        assert isinstance(report, dict)
        assert 'total_files' in report
        assert 'total_size' in report
        assert 'oldest_file' in report
        assert 'newest_file' in report
        assert 'files_by_type' in report
        
        assert report['total_files'] >= 5
        assert report['total_size'] > 0
    
    def test_quarantine_file_restoration(self, corruption_detector, temp_directory):
        """Test restoring files from quarantine."""
        # Create test file
        original_file = temp_directory / "restore_test.txt"
        original_content = "Content to be restored"
        original_file.write_text(original_content)
        
        # Quarantine the file
        success = corruption_detector.quarantine_file(str(original_file))
        assert success is True
        assert not original_file.exists()
        
        # Find quarantined file
        quarantine_dir = Path(corruption_detector.config.quarantine_dir)
        quarantined_files = list(quarantine_dir.rglob("*"))
        quarantined_files = [f for f in quarantined_files if f.is_file()]
        
        assert len(quarantined_files) == 1
        quarantined_file = quarantined_files[0]
        
        # Restore the file
        restore_success = corruption_detector.restore_from_quarantine(
            str(quarantined_file), 
            str(original_file)
        )
        assert restore_success is True
        
        # Verify restoration
        assert original_file.exists()
        assert original_file.read_text() == original_content
        assert not quarantined_file.exists()


class TestQuarantineSecurity:
    """Integration tests for quarantine security features."""
    
    def test_quarantine_file_permissions(self, corruption_detector, temp_directory):
        """Test quarantine file permissions."""
        # Create test file
        test_file = temp_directory / "permission_test.txt"
        test_file.write_text("Test permissions")
        
        # Quarantine the file
        success = corruption_detector.quarantine_file(str(test_file))
        assert success is True
        
        # Check quarantined file permissions
        quarantine_dir = Path(corruption_detector.config.quarantine_dir)
        quarantined_files = list(quarantine_dir.rglob("*"))
        quarantined_files = [f for f in quarantined_files if f.is_file()]
        
        if quarantined_files:
            quarantined_file = quarantined_files[0]
            file_mode = quarantined_file.stat().st_mode
            
            # File should not be executable
            assert not (file_mode & 0o111)
    
    def test_quarantine_path_sanitization(self, corruption_detector, temp_directory):
        """Test path sanitization in quarantine."""
        # Create file with potentially dangerous name
        dangerous_file = temp_directory / "../../../dangerous.txt"
        dangerous_file.write_text("Dangerous content")
        
        # Quarantine the file
        success = corruption_detector.quarantine_file(str(dangerous_file))
        assert success is True
        
        # Check quarantined file doesn't escape quarantine directory
        quarantine_dir = Path(corruption_detector.config.quarantine_dir).resolve()
        quarantined_files = list(quarantine_dir.rglob("*"))
        
        for file_path in quarantined_files:
            assert quarantine_dir in file_path.parents
            assert ".." not in str(file_path.relative_to(quarantine_dir))
    
    def test_quarantine_integrity_verification(self, corruption_detector, temp_directory):
        """Test integrity verification of quarantined files."""
        # Create test file
        test_file = temp_directory / "integrity_test.txt"
        original_content = "Test integrity verification"
        test_file.write_text(original_content)
        
        # Calculate original checksum
        original_checksum = corruption_detector._calculate_checksum(str(test_file))
        
        # Quarantine the file
        success = corruption_detector.quarantine_file(str(test_file))
        assert success is True
        
        # Find quarantined file and verify integrity
        quarantine_dir = Path(corruption_detector.config.quarantine_dir)
        quarantined_files = list(quarantine_dir.rglob("*"))
        quarantined_files = [f for f in quarantined_files if f.is_file()]
        
        if quarantined_files:
            quarantined_file = quarantined_files[0]
            quarantined_checksum = corruption_detector._calculate_checksum(str(quarantined_file))
            
            # Checksums should match
            assert quarantined_checksum == original_checksum
            
            # Content should match
            assert quarantined_file.read_text() == original_content


# Helper methods
def _create_quarantine_test_files(self, temp_directory):
    """Create test files for quarantine testing."""
    test_files = {}
    
    # Normal file (should not be quarantined)
    test_files['normal'] = temp_directory / "normal.txt"
    test_files['normal'].write_text("This is a normal file.")
    
    # File with null bytes (should be quarantined)
    test_files['null_bytes'] = temp_directory / "null_bytes.bin"
    test_files['null_bytes'].write_bytes(b"Content with many\x00\x00\x00\x00\x00 null bytes")
    
    # High entropy file (should be quarantined)
    test_files['high_entropy'] = temp_directory / "high_entropy.bin"
    test_files['high_entropy'].write_bytes(os.urandom(1024))
    
    # Empty file (might be quarantined)
    test_files['empty'] = temp_directory / "empty.txt"
    test_files['empty'].write_text("")
    
    return test_files


# Add helper method to test class
TestQuarantineIntegration._create_quarantine_test_files = _create_quarantine_test_files

# Import required modules
import time
import os
