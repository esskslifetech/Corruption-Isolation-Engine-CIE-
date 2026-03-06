"""
Integration tests for full scanning functionality

This Project Is Made By Kanishk Soni
"""

import pytest
import tempfile
import shutil
import os
import json
from pathlib import Path
from unittest.mock import patch

from src.python.core_analyzer import CorruptionDetector, AnalyzerConfig, FileStatus
from src.python.modular_scanner import ModularScanner


class TestFullScanIntegration:
    """Integration tests for complete scanning workflows."""
    
    def test_end_to_end_scan_workflow(self, corruption_detector, temp_directory):
        """Test complete end-to-end scanning workflow."""
        # Create diverse test files
        test_files = self._create_test_file_set(temp_directory)
        
        # Perform scan
        results = corruption_detector.scan_directory(str(temp_directory))
        
        # Verify scan results
        assert len(results) == len(test_files)
        
        # Check each file was processed
        scanned_files = {Path(r.file_path).name for r in results}
        expected_files = {f.name for f in test_files.values()}
        assert scanned_files == expected_files
        
        # Verify result structure
        for result in results:
            assert hasattr(result, 'file_path')
            assert hasattr(result, 'file_size')
            assert hasattr(result, 'is_corrupted')
            assert hasattr(result, 'status')
            assert hasattr(result, 'checksum')
            assert hasattr(result, 'shannon_entropy')
    
    def test_scan_with_quarantine_workflow(self, corruption_detector, temp_directory):
        """Test scanning with automatic quarantine workflow."""
        # Create test files including some that should be quarantined
        test_files = self._create_test_file_set(temp_directory)
        
        # Add corrupted files
        corrupted_files = self._create_corrupted_files(temp_directory)
        
        # Scan with quarantine
        scan_results = corruption_detector.scan_directory(str(temp_directory))
        
        # Quarantine corrupted files
        quarantine_results = []
        for result in scan_results:
            if result.is_corrupted:
                success = corruption_detector.quarantine_file(result.file_path)
                quarantine_results.append((result.file_path, success))
        
        # Verify quarantine
        assert len(quarantine_results) > 0
        
        for file_path, success in quarantine_results:
            assert success is True
            assert not os.path.exists(file_path)
            
            # Check file exists in quarantine
            quarantine_files = list(Path(corruption_detector.config.quarantine_dir).rglob("*"))
            assert len(quarantine_files) > 0
    
    def test_database_integration_workflow(self, corruption_detector, temp_directory):
        """Test database integration during scanning."""
        # Create test files
        test_files = self._create_test_file_set(temp_directory)
        
        # Perform scan
        results = corruption_detector.scan_directory(str(temp_directory))
        
        # Verify database operations
        corruption_detector._db_connection.row_factory = lambda cursor, row: {
            col[0]: row[idx] for idx, col in enumerate(cursor.description)
        }
        
        # Check file metadata was saved
        cursor = corruption_detector._db_connection.execute(
            "SELECT COUNT(*) as count FROM file_metadata"
        )
        db_count = cursor.fetchone()['count']
        
        assert db_count == len(results)
        
        # Verify data integrity
        for result in results:
            cursor = corruption_detector._db_connection.execute(
                "SELECT * FROM file_metadata WHERE file_path = ?",
                (result.file_path,)
            )
            db_row = cursor.fetchone()
            
            assert db_row is not None
            assert db_row['file_size'] == result.file_size
            assert db_row['checksum'] == result.checksum
            assert db_row['is_corrupted'] == result.is_corrupted
    
    def test_concurrent_scanning_workflow(self, corruption_detector, temp_directory):
        """Test concurrent scanning with multiple workers."""
        # Create many files for concurrent processing
        for i in range(50):
            file_path = temp_directory / f"concurrent_{i}.txt"
            file_path.write_text(f"Concurrent test file {i}\n" * 100)
        
        # Scan with multiple workers
        corruption_detector.config.max_workers = 4
        results = corruption_detector.scan_directory(str(temp_directory))
        
        assert len(results) >= 50
        
        # Verify all files were processed correctly
        for result in results:
            assert result.checksum is not None
            assert result.shannon_entropy >= 0.0
            assert result.file_size > 0
    
    def test_large_directory_scan(self, corruption_detector, temp_directory):
        """Test scanning large directory structure."""
        # Create nested directory structure
        for i in range(5):
            subdir = temp_directory / f"subdir_{i}"
            subdir.mkdir()
            
            for j in range(10):
                file_path = subdir / f"file_{j}.txt"
                file_path.write_text(f"Content in {subdir.name}/{file_path.name}")
        
        # Scan recursively
        results = corruption_detector.scan_directory(str(temp_directory), recursive=True)
        
        # Should find all files
        expected_files = 5 * 10  # 5 subdirs * 10 files each
        assert len(results) == expected_files
        
        # Verify directory structure in results
        for result in results:
            assert "subdir_" in result.file_path
    
    def test_memory_efficiency_large_files(self, corruption_detector, temp_directory):
        """Test memory efficiency with large files."""
        # Create large files
        large_files = []
        for i in range(3):
            file_path = temp_directory / f"large_{i}.txt"
            content = f"Large file {i} content\n" * 100000  # ~2MB each
            file_path.write_text(content)
            large_files.append(file_path)
        
        # Monitor memory usage during scan
        import psutil
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Scan large files
        results = corruption_detector.scan_directory(str(temp_directory))
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable
        assert len(results) == len(large_files)
        assert memory_increase < 50 * 1024 * 1024  # Less than 50MB increase
        
        # Verify large files were processed correctly
        for result in results:
            assert result.file_size > 1000000  # > 1MB
            assert result.checksum is not None
    
    def test_error_recovery_workflow(self, corruption_detector, temp_directory):
        """Test error recovery during scanning."""
        # Create mix of valid and problematic files
        valid_files = []
        for i in range(5):
            file_path = temp_directory / f"valid_{i}.txt"
            file_path.write_text(f"Valid content {i}")
            valid_files.append(file_path)
        
        # Create problematic file (permission denied)
        problematic_file = temp_directory / "problematic.txt"
        problematic_file.write_text("Problematic content")
        os.chmod(problematic_file, 0o000)  # No permissions
        
        try:
            # Scan should handle errors gracefully
            results = corruption_detector.scan_directory(str(temp_directory))
            
            # Should have results for readable files
            readable_results = [r for r in results if r.status != FileStatus.UNREADABLE]
            unreadable_results = [r for r in results if r.status == FileStatus.UNREADABLE]
            
            assert len(readable_results) == len(valid_files)
            assert len(unreadable_results) >= 1
            
            # Check error handling
            for result in unreadable_results:
                assert result.error_message is not None
                assert result.is_corrupted is True
        
        finally:
            # Restore permissions for cleanup
            os.chmod(problematic_file, 0o644)


class TestModularScannerIntegration:
    """Integration tests for modular scanner."""
    
    def test_modular_scanner_strategies(self, modular_scanner, temp_directory):
        """Test different scanning strategies."""
        # Create test files
        self._create_test_file_set(temp_directory)
        
        # Test each strategy
        strategies = ["fast", "balanced", "deep"]
        results_by_strategy = {}
        
        for strategy in strategies:
            modular_scanner.set_strategy(strategy)
            results = modular_scanner.scan(str(temp_directory))
            results_by_strategy[strategy] = results
        
        # Verify all strategies found files
        for strategy, results in results_by_strategy.items():
            assert len(results) > 0
            assert all(hasattr(r, 'strategy_used') for r in results)
            assert all(r.strategy_used == strategy for r in results)
    
    def test_strategy_comparison_integration(self, modular_scanner, temp_directory):
        """Test strategy comparison functionality."""
        # Create diverse test files
        self._create_test_file_set(temp_directory)
        
        # Compare strategies
        from src.python.modular_scanner import ComparisonMode
        comparison = ComparisonMode(modular_scanner.config)
        
        comparison_results = comparison.compare_strategies(
            str(temp_directory),
            strategies=["fast", "balanced"]
        )
        
        assert "fast" in comparison_results
        assert "balanced" in comparison_results
        
        # Generate comparison report
        report = comparison.generate_report(comparison_results)
        assert 'strategies' in report
        assert 'comparison' in report
        assert 'recommendations' in report
    
    def test_benchmark_integration(self, modular_scanner, temp_directory):
        """Test benchmark functionality."""
        # Create test files
        for i in range(20):
            (temp_directory / f"benchmark_{i}.txt").write_text(f"Benchmark content {i}")
        
        # Run benchmark
        from src.python.modular_scanner import BenchmarkMode
        benchmark = BenchmarkMode(modular_scanner.config)
        
        results = benchmark.run_benchmark(
            str(temp_directory),
            iterations=2,
            strategies=["fast", "balanced"]
        )
        
        assert "fast" in results
        assert "balanced" in results
        
        for strategy_name, strategy_results in results.items():
            assert 'iterations' in strategy_results
            assert 'average_time' in strategy_results
            assert 'performance_metrics' in strategy_results


class TestRealWorldScenarios:
    """Integration tests for real-world scenarios."""
    
    def test_document_repository_scan(self, corruption_detector, temp_directory):
        """Test scanning a document repository."""
        # Create realistic document structure
        docs_dir = temp_directory / "documents"
        docs_dir.mkdir()
        
        # Create various document types
        documents = [
            ("report.pdf", b"%PDF-1.4\nSample PDF content"),
            ("presentation.pptx", b"Sample PowerPoint content"),
            ("spreadsheet.xlsx", b"Sample Excel content"),
            ("notes.txt", "Meeting notes and important information"),
            ("archive.zip", b"PK\x03\x04Sample ZIP content")
        ]
        
        for filename, content in documents:
            file_path = docs_dir / filename
            if isinstance(content, str):
                file_path.write_text(content)
            else:
                file_path.write_bytes(content)
        
        # Scan documents
        results = corruption_detector.scan_directory(str(docs_dir))
        
        assert len(results) == len(documents)
        
        # Verify document type detection
        for result in results:
            assert result.file_type is not None
            assert result.file_size > 0
    
    def test_media_library_scan(self, corruption_detector, temp_directory):
        """Test scanning a media library."""
        # Create media directory structure
        media_dir = temp_directory / "media"
        media_dir.mkdir()
        
        # Create media-like files (simulated)
        media_files = [
            ("photo1.jpg", b"\xFF\xD8\xFF\xE0\x00\x10JFIF"),
            ("photo2.png", b"\x89PNG\r\n\x1a\n"),
            ("video1.mp4", b"Sample MP4 header"),
            ("audio1.mp3", b"ID3Sample MP3 content"),
            ("document.pdf", b"%PDF-1.4\nSample document")
        ]
        
        for filename, content in media_files:
            file_path = media_dir / filename
            file_path.write_bytes(content)
        
        # Scan media library
        results = corruption_detector.scan_directory(str(media_dir))
        
        assert len(results) == len(media_files)
        
        # Verify media file handling
        for result in results:
            assert result.file_type is not None
            # Media files should have reasonable entropy
            if result.file_size > 0:
                assert 0.0 <= result.shannon_entropy <= 8.0
    
    def test_software_directory_scan(self, corruption_detector, temp_directory):
        """Test scanning a software directory."""
        # Create software project structure
        src_dir = temp_directory / "software" / "src"
        src_dir.mkdir(parents=True)
        
        # Create various software files
        software_files = [
            ("main.py", "#!/usr/bin/env python3\nprint('Hello World')\n"),
            ("utils.c", "#include <stdio.h>\nint main() { return 0; }"),
            ("config.json", '{"name": "test", "version": "1.0"}'),
            ("README.md", "# Test Project\nThis is a test project."),
            ("Makefile", "all:\n\techo 'Building project'")
        ]
        
        for filename, content in software_files:
            file_path = src_dir / filename
            file_path.write_text(content)
        
        # Scan software directory
        results = corruption_detector.scan_directory(str(src_dir))
        
        assert len(results) == len(software_files)
        
        # Verify source code handling
        for result in results:
            assert result.file_type is not None
            # Source files should have reasonable entropy
            if result.file_size > 0:
                assert result.shannon_entropy > 0.0
    
    def test_backup_directory_scan(self, corruption_detector, temp_directory):
        """Test scanning a backup directory."""
        # Create backup directory structure
        backup_dir = temp_directory / "backup"
        backup_dir.mkdir()
        
        # Create backup-like files
        backup_files = [
            ("database_backup.sql", "CREATE TABLE users (id INT);\nINSERT INTO users VALUES (1);"),
            ("config_backup.xml", "<config><setting name='test'>value</setting></config>"),
            ("logs_backup.tar.gz", b"Sample compressed archive content"),
            ("documents_backup.zip", b"PK\x03\x04Backup archive content"),
            ("system_backup.img", b"Sample disk image content")
        ]
        
        for filename, content in backup_files:
            file_path = backup_dir / filename
            if isinstance(content, str):
                file_path.write_text(content)
            else:
                file_path.write_bytes(content)
        
        # Scan backup directory
        results = corruption_detector.scan_directory(str(backup_dir))
        
        assert len(results) == len(backup_files)
        
        # Verify backup file handling
        for result in results:
            assert result.file_type is not None
            # Backup files should be analyzed properly
            assert result.checksum is not None


class TestPerformanceIntegration:
    """Integration tests for performance scenarios."""
    
    def test_scan_performance_comparison(self, corruption_detector, temp_directory):
        """Test performance comparison between different configurations."""
        # Create test files
        for i in range(100):
            (temp_directory / f"perf_test_{i}.txt").write_text(f"Performance test {i}")
        
        # Test with different worker counts
        configs = [
            (1, "single_worker"),
            (2, "dual_worker"),
            (4, "quad_worker")
        ]
        
        performance_results = {}
        
        for worker_count, config_name in configs:
            corruption_detector.config.max_workers = worker_count
            
            import time
            start_time = time.time()
            results = corruption_detector.scan_directory(str(temp_directory))
            scan_time = time.time() - start_time
            
            performance_results[config_name] = {
                'scan_time': scan_time,
                'file_count': len(results),
                'files_per_second': len(results) / scan_time
            }
        
        # Verify performance differences
        assert all(result['file_count'] == 100 for result in performance_results.values())
        
        # Multi-worker should generally be faster (though not guaranteed in tests)
        single_worker_time = performance_results['single_worker']['scan_time']
        multi_worker_time = min(
            performance_results['dual_worker']['scan_time'],
            performance_results['quad_worker']['scan_time']
        )
        
        # At minimum, performance should be reasonable
        assert single_worker_time < 30.0  # Should complete within 30 seconds
    
    def test_memory_usage_scaling(self, corruption_detector, temp_directory):
        """Test memory usage scaling with file size."""
        import psutil
        
        # Create files of different sizes
        file_sizes = [1024, 10240, 102400, 1024000]  # 1KB to 1MB
        files = []
        
        for size in file_sizes:
            file_path = temp_directory / f"size_test_{size}.txt"
            content = "X" * size
            file_path.write_text(content)
            files.append(file_path)
        
        # Monitor memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Scan files
        results = corruption_detector.scan_directory(str(temp_directory))
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory usage should scale reasonably
        assert len(results) == len(files)
        assert memory_increase < 100 * 1024 * 1024  # Less than 100MB for 4MB of data
    
    def test_database_performance(self, corruption_detector, temp_directory):
        """Test database performance with many files."""
        # Create many files
        for i in range(1000):
            (temp_directory / f"db_test_{i}.txt").write_text(f"Database test {i}")
        
        # Time the scan and database operations
        import time
        start_time = time.time()
        
        results = corruption_detector.scan_directory(str(temp_directory))
        
        scan_time = time.time() - start_time
        
        # Verify performance
        assert len(results) == 1000
        assert scan_time < 60.0  # Should complete within 1 minute
        
        # Verify database integrity
        cursor = corruption_detector._db_connection.execute(
            "SELECT COUNT(*) as count FROM file_metadata"
        )
        db_count = cursor.fetchone()[0]
        
        assert db_count == 1000


# Helper methods
def _create_test_file_set(self, temp_directory):
    """Create a set of test files for scanning."""
    test_files = {}
    
    # Text files
    test_files['text1'] = temp_directory / "document1.txt"
    test_files['text1'].write_text("This is a test document with normal content.")
    
    test_files['text2'] = temp_directory / "document2.txt"
    test_files['text2'].write_text("Another document with different content.")
    
    # Binary files
    test_files['binary1'] = temp_directory / "binary1.bin"
    test_files['binary1'].write_bytes(b"Binary content with some \x00 null bytes")
    
    test_files['binary2'] = temp_directory / "binary2.bin"
    test_files['binary2'].write_bytes(os.urandom(1024))  # Random binary data
    
    # Empty file
    test_files['empty'] = temp_directory / "empty.txt"
    test_files['empty'].write_text("")
    
    # Simulated image files
    test_files['image'] = temp_directory / "test.jpg"
    test_files['image'].write_bytes(b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00")
    
    # Simulated PDF file
    test_files['pdf'] = temp_directory / "test.pdf"
    test_files['pdf'].write_bytes(b"%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n>>\nendobj\n%%EOF")
    
    return test_files


def _create_corrupted_files(self, temp_directory):
    """Create files that should be detected as corrupted."""
    corrupted_files = {}
    
    # File with too many null bytes
    corrupted_files['null_heavy'] = temp_directory / "null_heavy.bin"
    corrupted_files['null_heavy'].write_bytes(b"Content\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    
    # File with invalid header
    corrupted_files['invalid_header'] = temp_directory / "fake.jpg"
    corrupted_files['invalid_header'].write_bytes(b"This is not a JPEG file")
    
    # Very high entropy file (simulated encrypted)
    corrupted_files['high_entropy'] = temp_directory / "encrypted.bin"
    corrupted_files['high_entropy'].write_bytes(os.urandom(2048))
    
    return corrupted_files


# Add helper methods to test classes
TestFullScanIntegration._create_test_file_set = _create_test_file_set
TestFullScanIntegration._create_corrupted_files = _create_corrupted_files
TestRealWorldScenarios._create_test_file_set = _create_test_file_set
TestPerformanceIntegration._create_test_file_set = _create_test_file_set
