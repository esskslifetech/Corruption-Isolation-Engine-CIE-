"""
Unit tests for processing_modules.py

This Project Is Made By Kanishk Soni
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import hashlib
import tempfile

from src.python.core_analyzer import AnalyzerConfig, FileAnalysisResult, FileStatus
from src.python.processing_modules import (
    FileProcessor,
    StreamingProcessor,
    BatchProcessor,
    CacheManager,
    ProgressTracker,
    ProcessingPipeline
)


class TestFileProcessor:
    """Test cases for FileProcessor class."""
    
    def test_file_processor_initialization(self, analyzer_config):
        """Test FileProcessor initialization."""
        processor = FileProcessor(analyzer_config)
        
        assert processor.config == analyzer_config
        assert processor.chunk_size == analyzer_config.chunk_size
        assert processor.max_workers == analyzer_config.max_workers
    
    def test_analyze_file_basic(self, file_processor, sample_files):
        """Test basic file analysis."""
        test_file = sample_files['valid_txt']
        result = file_processor.analyze_file(str(test_file))
        
        assert isinstance(result, FileAnalysisResult)
        assert result.file_path == str(test_file)
        assert result.file_size > 0
        assert result.checksum is not None
        assert result.shannon_entropy >= 0.0
    
    def test_analyze_file_with_validation(self, file_processor, sample_files):
        """Test file analysis with format validation."""
        test_file = sample_files['valid_pdf']
        
        with patch.object(file_processor, '_validate_file_format') as mock_validate:
            mock_validation = Mock(is_valid=True, error_message=None, format_info={'type': 'PDF'})
            mock_validate.return_value = mock_validation
            
            result = file_processor.analyze_file(str(test_file))
            
            mock_validate.assert_called_once_with(str(test_file))
            assert result.format_validation == mock_validation
    
    def test_analyze_file_checksum_calculation(self, file_processor, temp_file):
        """Test checksum calculation during analysis."""
        test_content = "Test content for checksum"
        test_file = temp_file("checksum_test.txt", test_content)
        
        result = file_processor.analyze_file(str(test_file))
        
        # Verify checksum matches expected SHA-256
        expected_checksum = hashlib.sha256(test_content.encode()).hexdigest()
        assert result.checksum == expected_checksum
    
    def test_analyze_file_entropy_calculation(self, file_processor, entropy_files):
        """Test entropy calculation during analysis."""
        low_entropy_file = entropy_files['entropy_0.0']
        high_entropy_file = entropy_files['entropy_8.0']
        
        result_low = file_processor.analyze_file(str(low_entropy_file))
        result_high = file_processor.analyze_file(str(high_entropy_file))
        
        assert result_low.shannon_entropy < result_high.shannon_entropy
        assert 0.0 <= result_low.shannon_entropy <= 8.0
        assert 0.0 <= result_high.shannon_entropy <= 8.0
    
    def test_analyze_file_error_handling(self, file_processor, temp_directory):
        """Test error handling during file analysis."""
        nonexistent_file = temp_directory / "nonexistent.txt"
        
        result = file_processor.analyze_file(str(nonexistent_file))
        
        assert result.status == FileStatus.UNREADABLE
        assert result.is_corrupted is True
        assert result.error_message is not None
    
    def test_analyze_large_file_streaming(self, file_processor, temp_directory):
        """Test analyzing large file with streaming."""
        large_content = "Large file content\n" * 10000
        large_file = temp_directory / "large.txt"
        large_file.write_text(large_content)
        
        result = file_processor.analyze_file(str(large_file))
        
        assert result.file_size == len(large_content.encode())
        assert result.checksum is not None
        assert result.shannon_entropy > 0.0
    
    def test_detect_file_type(self, file_processor, sample_files):
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
                detected_type = file_processor._detect_file_type(str(file_path))
                
                assert detected_type is not None
                assert isinstance(detected_type, str)
    
    def test_process_multiple_files(self, file_processor, sample_files):
        """Test processing multiple files."""
        file_paths = [str(f) for f in sample_files.values()]
        
        results = file_processor.process_multiple_files(file_paths)
        
        assert len(results) == len(file_paths)
        for result in results:
            assert isinstance(result, FileAnalysisResult)
    
    def test_process_with_progress_callback(self, file_processor, sample_files):
        """Test processing with progress callback."""
        progress_calls = []
        
        def progress_callback(current, total, file_path):
            progress_calls.append((current, total, file_path))
        
        file_paths = [str(f) for f in list(sample_files.values())[:3]]
        
        results = file_processor.process_multiple_files(
            file_paths, 
            progress_callback=progress_callback
        )
        
        assert len(progress_calls) == len(file_paths)
        assert len(results) == len(file_paths)


class TestStreamingProcessor:
    """Test cases for StreamingProcessor class."""
    
    def test_streaming_processor_initialization(self, analyzer_config):
        """Test StreamingProcessor initialization."""
        processor = StreamingProcessor(analyzer_config)
        
        assert processor.config == analyzer_config
        assert processor.chunk_size == analyzer_config.chunk_size
    
    def test_read_file_in_chunks(self, streaming_processor, temp_file):
        """Test reading file in chunks."""
        content = "Chunk content " * 100  # Create content larger than chunk size
        test_file = temp_file("chunks.txt", content)
        
        chunks = list(streaming_processor._read_file_in_chunks(str(test_file)))
        
        assert len(chunks) > 1  # Should be multiple chunks
        combined_content = b''.join(chunks).decode()
        assert combined_content == content
    
    def test_calculate_checksum_streaming(self, streaming_processor, temp_file):
        """Test streaming checksum calculation."""
        content = "Streaming checksum test content"
        test_file = temp_file("streaming_checksum.txt", content)
        
        checksum = streaming_processor._calculate_checksum_streaming(str(test_file))
        
        expected_checksum = hashlib.sha256(content.encode()).hexdigest()
        assert checksum == expected_checksum
    
    def test_calculate_entropy_streaming(self, streaming_processor, entropy_files):
        """Test streaming entropy calculation."""
        high_entropy_file = entropy_files['entropy_8.0']
        
        entropy = streaming_processor._calculate_entropy_streaming(str(high_entropy_file))
        
        assert 0.0 <= entropy <= 8.0
        # High entropy file should have high entropy value
        assert entropy > 7.0
    
    def test_process_large_file_streaming(self, streaming_processor, temp_directory):
        """Test processing large file with streaming."""
        # Create a file larger than default chunk size
        large_content = "X" * (streaming_processor.chunk_size * 3)
        large_file = temp_directory / "large_streaming.txt"
        large_file.write_text(large_content)
        
        result = streaming_processor.process_file_streaming(str(large_file))
        
        assert isinstance(result, FileAnalysisResult)
        assert result.file_size == len(large_content)
        assert result.checksum is not None
        assert result.shannon_entropy >= 0.0
    
    def test_streaming_processor_memory_efficiency(self, streaming_processor, temp_directory):
        """Test that streaming processor is memory efficient."""
        import psutil
        import os
        
        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Create very large file
        large_content = "Memory test content\n" * 100000  # ~2MB
        large_file = temp_directory / "memory_test.txt"
        large_file.write_text(large_content)
        
        # Process with streaming
        result = streaming_processor.process_file_streaming(str(large_file))
        
        # Check memory usage didn't grow excessively
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than file size)
        assert memory_increase < len(large_content.encode())
        assert result.checksum is not None


class TestBatchProcessor:
    """Test cases for BatchProcessor class."""
    
    def test_batch_processor_initialization(self, analyzer_config):
        """Test BatchProcessor initialization."""
        processor = BatchProcessor(analyzer_config)
        
        assert processor.config == analyzer_config
        assert processor.batch_size > 0
    
    def test_process_files_in_batches(self, batch_processor, sample_files):
        """Test processing files in batches."""
        file_paths = [str(f) for f in sample_files.values()]
        
        all_results = []
        for batch_results in batch_processor.process_files_in_batches(file_paths):
            all_results.extend(batch_results)
        
        assert len(all_results) == len(file_paths)
        for result in all_results:
            assert isinstance(result, FileAnalysisResult)
    
    def test_batch_size_configuration(self, analyzer_config):
        """Test batch size configuration."""
        analyzer_config.batch_size = 3
        processor = BatchProcessor(analyzer_config)
        
        assert processor.batch_size == 3
    
    def test_process_empty_batch(self, batch_processor):
        """Test processing empty batch."""
        results = list(batch_processor.process_files_in_batches([]))
        
        assert len(results) == 0
    
    def test_batch_progress_tracking(self, batch_processor, sample_files):
        """Test progress tracking during batch processing."""
        progress_updates = []
        
        def progress_callback(batch_num, total_batches, batch_results):
            progress_updates.append((batch_num, total_batches, len(batch_results)))
        
        file_paths = [str(f) for f in sample_files.values()]
        
        all_results = []
        for batch_results in batch_processor.process_files_in_batches(
            file_paths, 
            progress_callback=progress_callback
        ):
            all_results.extend(batch_results)
        
        assert len(progress_updates) > 0
        assert len(all_results) == len(file_paths)


class TestCacheManager:
    """Test cases for CacheManager class."""
    
    def test_cache_manager_initialization(self, analyzer_config):
        """Test CacheManager initialization."""
        cache = CacheManager(analyzer_config)
        
        assert cache.config == analyzer_config
        assert cache.cache_size > 0
    
    def test_cache_storage_and_retrieval(self, cache_manager):
        """Test storing and retrieving from cache."""
        key = "test_key"
        value = {"data": "test_value"}
        
        # Store in cache
        cache_manager.put(key, value)
        
        # Retrieve from cache
        retrieved_value = cache_manager.get(key)
        
        assert retrieved_value == value
    
    def test_cache_miss(self, cache_manager):
        """Test cache miss scenario."""
        result = cache_manager.get("nonexistent_key")
        
        assert result is None
    
    def test_cache_size_limit(self, cache_manager):
        """Test cache size limit enforcement."""
        # Fill cache beyond its size limit
        for i in range(cache_manager.cache_size + 10):
            cache_manager.put(f"key_{i}", f"value_{i}")
        
        # Check that cache doesn't exceed size limit
        assert len(cache_manager._cache) <= cache_manager.cache_size
    
    def test_cache_eviction(self, cache_manager):
        """Test cache eviction policy."""
        # Fill cache to capacity
        for i in range(cache_manager.cache_size):
            cache_manager.put(f"key_{i}", f"value_{i}")
        
        # Add one more item to trigger eviction
        cache_manager.put("new_key", "new_value")
        
        # Check that oldest item was evicted
        assert cache_manager.get("key_0") is None
        assert cache_manager.get("new_key") == "new_value"
    
    def test_cache_clear(self, cache_manager):
        """Test cache clearing."""
        # Add some items
        cache_manager.put("key1", "value1")
        cache_manager.put("key2", "value2")
        
        # Clear cache
        cache_manager.clear()
        
        # Check cache is empty
        assert len(cache_manager._cache) == 0
        assert cache_manager.get("key1") is None
        assert cache_manager.get("key2") is None
    
    def test_cache_with_file_metadata(self, cache_manager, sample_files):
        """Test caching file metadata."""
        file_path = str(sample_files['valid_txt'])
        metadata = {
            "size": 100,
            "mtime": 1234567890,
            "checksum": "abc123"
        }
        
        # Cache metadata
        cache_key = f"file_meta:{file_path}"
        cache_manager.put(cache_key, metadata)
        
        # Retrieve cached metadata
        cached_metadata = cache_manager.get(cache_key)
        
        assert cached_metadata == metadata


class TestProgressTracker:
    """Test cases for ProgressTracker class."""
    
    def test_progress_tracker_initialization(self):
        """Test ProgressTracker initialization."""
        tracker = ProgressTracker(total_items=100)
        
        assert tracker.total_items == 100
        assert tracker.current_item == 0
        assert tracker.progress_percentage == 0.0
    
    def test_progress_update(self):
        """Test progress update."""
        tracker = ProgressTracker(total_items=100)
        
        tracker.update()
        assert tracker.current_item == 1
        assert tracker.progress_percentage == 1.0
        
        tracker.update(10)
        assert tracker.current_item == 11
        assert tracker.progress_percentage == 11.0
    
    def test_progress_completion(self):
        """Test progress completion."""
        tracker = ProgressTracker(total_items=5)
        
        for i in range(5):
            tracker.update()
        
        assert tracker.current_item == 5
        assert tracker.progress_percentage == 100.0
        assert tracker.is_complete()
    
    def test_progress_callback(self):
        """Test progress callback functionality."""
        callback_calls = []
        
        def progress_callback(current, total, percentage):
            callback_calls.append((current, total, percentage))
        
        tracker = ProgressTracker(total_items=3, callback=progress_callback)
        
        tracker.update()
        tracker.update()
        tracker.update()
        
        assert len(callback_calls) == 3
        assert callback_calls[0] == (1, 3, 33.33)
        assert callback_calls[1] == (2, 3, 66.67)
        assert callback_calls[2] == (3, 3, 100.0)
    
    def test_progress_reset(self):
        """Test progress reset."""
        tracker = ProgressTracker(total_items=10)
        
        tracker.update(5)
        assert tracker.current_item == 5
        
        tracker.reset()
        assert tracker.current_item == 0
        assert tracker.progress_percentage == 0.0


class TestProcessingPipeline:
    """Test cases for ProcessingPipeline class."""
    
    def test_pipeline_initialization(self, analyzer_config):
        """Test ProcessingPipeline initialization."""
        pipeline = ProcessingPipeline(analyzer_config)
        
        assert pipeline.config == analyzer_config
        assert len(pipeline.stages) == 0
    
    def test_add_stage(self, processing_pipeline):
        """Test adding processing stage."""
        def mock_stage(file_path, result):
            result.processed = True
            return result
        
        processing_pipeline.add_stage("mock_stage", mock_stage)
        
        assert len(processing_pipeline.stages) == 1
        assert "mock_stage" in processing_pipeline.stages
    
    def test_remove_stage(self, processing_pipeline):
        """Test removing processing stage."""
        def mock_stage(file_path, result):
            return result
        
        processing_pipeline.add_stage("mock_stage", mock_stage)
        processing_pipeline.remove_stage("mock_stage")
        
        assert len(processing_pipeline.stages) == 0
        assert "mock_stage" not in processing_pipeline.stages
    
    def test_execute_pipeline(self, processing_pipeline, sample_files):
        """Test executing processing pipeline."""
        # Add mock stages
        def stage1(file_path, result):
            result.stage1_processed = True
            return result
        
        def stage2(file_path, result):
            result.stage2_processed = True
            return result
        
        processing_pipeline.add_stage("stage1", stage1)
        processing_pipeline.add_stage("stage2", stage2)
        
        # Execute pipeline
        test_file = str(sample_files['valid_txt'])
        result = processing_pipeline.execute(test_file)
        
        assert result.stage1_processed is True
        assert result.stage2_processed is True
    
    def test_pipeline_with_error_stage(self, processing_pipeline, sample_files):
        """Test pipeline with stage that raises error."""
        def error_stage(file_path, result):
            raise ValueError("Stage error")
        
        def recovery_stage(file_path, result):
            result.error_handled = True
            return result
        
        processing_pipeline.add_stage("error_stage", error_stage)
        processing_pipeline.add_stage("recovery_stage", recovery_stage)
        
        test_file = str(sample_files['valid_txt'])
        
        # Should handle error gracefully
        result = processing_pipeline.execute(test_file)
        assert hasattr(result, 'error_handled')
    
    def test_pipeline_progress_tracking(self, processing_pipeline, sample_files):
        """Test progress tracking in pipeline."""
        progress_calls = []
        
        def progress_callback(stage_name, stage_progress):
            progress_calls.append((stage_name, stage_progress))
        
        processing_pipeline.set_progress_callback(progress_callback)
        
        def mock_stage(file_path, result):
            return result
        
        processing_pipeline.add_stage("stage1", mock_stage)
        processing_pipeline.add_stage("stage2", mock_stage)
        
        test_file = str(sample_files['valid_txt'])
        processing_pipeline.execute(test_file)
        
        assert len(progress_calls) >= 2  # At least one call per stage


# Fixtures for test classes
@pytest.fixture
def file_processor(analyzer_config):
    """Create a FileProcessor instance for testing."""
    return FileProcessor(analyzer_config)


@pytest.fixture
def streaming_processor(analyzer_config):
    """Create a StreamingProcessor instance for testing."""
    return StreamingProcessor(analyzer_config)


@pytest.fixture
def batch_processor(analyzer_config):
    """Create a BatchProcessor instance for testing."""
    analyzer_config.batch_size = 2
    return BatchProcessor(analyzer_config)


@pytest.fixture
def cache_manager(analyzer_config):
    """Create a CacheManager instance for testing."""
    analyzer_config.cache_size = 5
    return CacheManager(analyzer_config)


@pytest.fixture
def processing_pipeline(analyzer_config):
    """Create a ProcessingPipeline instance for testing."""
    return ProcessingPipeline(analyzer_config)
