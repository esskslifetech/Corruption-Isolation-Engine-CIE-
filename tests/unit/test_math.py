"""
Unit tests for math.py

This Project Is Made By Kanishk Soni
"""

import pytest
import math
from unittest.mock import Mock, patch

from src.python.math import (
    calculate_shannon_entropy,
    detect_null_byte_patterns,
    detect_repeated_patterns,
    calculate_byte_frequency,
    calculate_file_statistics,
    analyze_binary_patterns,
    entropy_calculator,
    pattern_detector,
    binary_analyzer
)


class TestShannonEntropy:
    """Test cases for Shannon entropy calculation."""
    
    def test_calculate_shannon_entropy_empty_data(self):
        """Test entropy calculation with empty data."""
        entropy = calculate_shannon_entropy(b"")
        assert entropy == 0.0
    
    def test_calculate_shannon_entropy_uniform_data(self):
        """Test entropy calculation with uniform data."""
        # All same bytes should have entropy 0
        entropy = calculate_shannon_entropy(b"AAAAAAA")
        assert entropy == 0.0
    
    def test_calculate_shannon_entropy_max_entropy(self):
        """Test entropy calculation with maximum entropy data."""
        import os
        # Random data should have high entropy
        random_data = os.urandom(1024)
        entropy = calculate_shannon_entropy(random_data)
        
        # Should be close to maximum (8.0 for bytes)
        assert entropy > 7.0
        assert entropy <= 8.0
    
    def test_calculate_shannon_entropy_known_data(self):
        """Test entropy calculation with known data."""
        # "ABABAB" pattern should have entropy of 1.0 (two equally likely bytes)
        data = b"ABABABAB"
        entropy = calculate_shannon_entropy(data)
        
        # Should be exactly 1.0 for this pattern
        assert abs(entropy - 1.0) < 0.01
    
    def test_calculate_shannon_entropy_text_data(self):
        """Test entropy calculation with text data."""
        text = "This is a sample text for entropy calculation."
        data = text.encode('utf-8')
        entropy = calculate_shannon_entropy(data)
        
        assert 0.0 < entropy < 8.0
    
    def test_calculate_shannon_entropy_large_data(self):
        """Test entropy calculation with large data."""
        import os
        large_data = os.urandom(1024 * 1024)  # 1MB
        entropy = calculate_shannon_entropy(large_data)
        
        assert 0.0 <= entropy <= 8.0
    
    def test_calculate_shannon_entropy_unicode(self):
        """Test entropy calculation with Unicode data."""
        unicode_text = "Hello 世界 🌍"
        data = unicode_text.encode('utf-8')
        entropy = calculate_shannon_entropy(data)
        
        assert 0.0 < entropy < 8.0


class TestNullByteDetection:
    """Test cases for null byte pattern detection."""
    
    def test_detect_null_byte_patterns_no_nulls(self):
        """Test null byte detection with no null bytes."""
        data = b"This data has no null bytes"
        result = detect_null_byte_patterns(data)
        
        assert result['null_count'] == 0
        assert result['null_ratio'] == 0.0
        assert result['has_null_sequences'] is False
        assert result['max_null_sequence'] == 0
    
    def test_detect_null_byte_patterns_single_nulls(self):
        """Test null byte detection with single null bytes."""
        data = b"Data\x00with\x00null\x00bytes"
        result = detect_null_byte_patterns(data)
        
        assert result['null_count'] == 3
        assert result['null_ratio'] == 3 / len(data)
        assert result['has_null_sequences'] is False
        assert result['max_null_sequence'] == 1
    
    def test_detect_null_byte_patterns_sequences(self):
        """Test null byte detection with null sequences."""
        data = b"Start\x00\x00\x00\x00Middle\x00\x00End"
        result = detect_null_byte_patterns(data)
        
        assert result['null_count'] == 6
        assert result['has_null_sequences'] is True
        assert result['max_null_sequence'] == 4
        assert result['null_sequences'] == [4, 2]
    
    def test_detect_null_byte_patterns_all_nulls(self):
        """Test null byte detection with all null bytes."""
        data = b"\x00" * 100
        result = detect_null_byte_patterns(data)
        
        assert result['null_count'] == 100
        assert result['null_ratio'] == 1.0
        assert result['has_null_sequences'] is True
        assert result['max_null_sequence'] == 100
        assert result['null_sequences'] == [100]
    
    def test_detect_null_byte_patterns_empty_data(self):
        """Test null byte detection with empty data."""
        result = detect_null_byte_patterns(b"")
        
        assert result['null_count'] == 0
        assert result['null_ratio'] == 0.0
        assert result['has_null_sequences'] is False
        assert result['max_null_sequence'] == 0
        assert result['null_sequences'] == []


class TestRepeatedPatternDetection:
    """Test cases for repeated pattern detection."""
    
    def test_detect_repeated_patterns_no_patterns(self):
        """Test pattern detection with no repeated patterns."""
        data = b"Unique data with no repetitions"
        result = detect_repeated_patterns(data, min_length=2)
        
        assert len(result['patterns']) == 0
        assert result['has_repeated_patterns'] is False
    
    def test_detect_repeated_patterns_simple_pattern(self):
        """Test detection of simple repeated patterns."""
        data = b"ABABABABAB"
        result = detect_repeated_patterns(data, min_length=2)
        
        assert result['has_repeated_patterns'] is True
        assert len(result['patterns']) > 0
        
        # Should find "AB" pattern
        pattern_found = any(p['pattern'] == b'AB' for p in result['patterns'])
        assert pattern_found
    
    def test_detect_repeated_patterns_multiple_patterns(self):
        """Test detection of multiple repeated patterns."""
        data = b"ABABABCDCDCDXYXY"
        result = detect_repeated_patterns(data, min_length=2)
        
        assert result['has_repeated_patterns'] is True
        assert len(result['patterns']) >= 3  # AB, CD, XY patterns
        
        # Check pattern details
        patterns = {p['pattern'].decode(): p for p in result['patterns']}
        assert 'AB' in patterns
        assert 'CD' in patterns
        assert 'XY' in patterns
    
    def test_detect_repeated_patterns_long_pattern(self):
        """Test detection of long repeated patterns."""
        pattern = b"LONGPATTERN"
        data = pattern + b"RANDOM" + pattern + b"MORE" + pattern
        result = detect_repeated_patterns(data, min_length=4)
        
        assert result['has_repeated_patterns'] is True
        
        # Should find the long pattern
        pattern_found = any(p['pattern'] == pattern for p in result['patterns'])
        assert pattern_found
    
    def test_detect_repeated_patterns_overlapping(self):
        """Test detection of overlapping patterns."""
        data = b"AAAAAA"  # Multiple overlapping "AA" patterns
        result = detect_repeated_patterns(data, min_length=2)
        
        assert result['has_repeated_patterns'] is True
        assert len(result['patterns']) > 0
    
    def test_detect_repeated_pattern_frequency(self):
        """Test pattern frequency calculation."""
        data = b"ABABABCABAB"
        result = detect_repeated_patterns(data, min_length=2)
        
        # Find AB pattern
        ab_pattern = next((p for p in result['patterns'] if p['pattern'] == b'AB'), None)
        
        if ab_pattern:
            assert ab_pattern['frequency'] >= 4  # AB appears at least 4 times
            assert ab_pattern['positions']  # Should have position list
    
    def test_detect_repeated_patterns_min_length(self):
        """Test minimum pattern length parameter."""
        data = b"ABABABCDCD"
        
        # With min_length=2, should find patterns
        result2 = detect_repeated_patterns(data, min_length=2)
        assert result2['has_repeated_patterns'] is True
        
        # With min_length=3, should find fewer or no patterns
        result3 = detect_repeated_patterns(data, min_length=3)
        assert len(result3['patterns']) <= len(result2['patterns'])


class TestByteFrequency:
    """Test cases for byte frequency calculation."""
    
    def test_calculate_byte_frequency_empty_data(self):
        """Test frequency calculation with empty data."""
        freq = calculate_byte_frequency(b"")
        
        assert len(freq) == 0
        assert sum(freq.values()) == 0
    
    def test_calculate_byte_frequency_uniform_data(self):
        """Test frequency calculation with uniform data."""
        data = b"AAAAAAA"
        freq = calculate_byte_frequency(data)
        
        assert len(freq) == 1
        assert freq[ord('A')] == 7
        assert sum(freq.values()) == 7
    
    def test_calculate_byte_frequency_mixed_data(self):
        """Test frequency calculation with mixed data."""
        data = b"ABCABC"
        freq = calculate_byte_frequency(data)
        
        assert len(freq) == 3
        assert freq[ord('A')] == 2
        assert freq[ord('B')] == 2
        assert freq[ord('C')] == 2
        assert sum(freq.values()) == 6
    
    def test_calculate_byte_frequency_all_bytes(self):
        """Test frequency calculation with all possible byte values."""
        data = bytes(range(256))  # All byte values 0-255
        freq = calculate_byte_frequency(data)
        
        assert len(freq) == 256
        for byte_val in range(256):
            assert freq[byte_val] == 1
        assert sum(freq.values()) == 256
    
    def test_calculate_byte_frequency_percentages(self):
        """Test frequency percentage calculation."""
        data = b"AABBCC"
        freq = calculate_byte_frequency(data, as_percentage=True)
        
        assert len(freq) == 3
        assert abs(freq[ord('A')] - 33.33) < 0.1
        assert abs(freq[ord('B')] - 33.33) < 0.1
        assert abs(freq[ord('C')] - 33.33) < 0.1


class TestFileStatistics:
    """Test cases for file statistics calculation."""
    
    def test_calculate_file_statistics_basic(self, temp_file):
        """Test basic file statistics calculation."""
        content = b"Test file content for statistics"
        test_file = temp_file("stats_test.txt", content, binary=True)
        
        stats = calculate_file_statistics(str(test_file))
        
        assert stats['file_size'] == len(content)
        assert stats['byte_count'] == len(content)
        assert stats['unique_bytes'] <= len(content)
        assert 0.0 <= stats['entropy'] <= 8.0
        assert stats['null_ratio'] >= 0.0
    
    def test_calculate_file_statistics_empty_file(self, temp_file):
        """Test statistics calculation for empty file."""
        test_file = temp_file("empty.txt", "", binary=True)
        
        stats = calculate_file_statistics(str(test_file))
        
        assert stats['file_size'] == 0
        assert stats['byte_count'] == 0
        assert stats['unique_bytes'] == 0
        assert stats['entropy'] == 0.0
        assert stats['null_ratio'] == 0.0
    
    def test_calculate_file_statistics_with_metadata(self, temp_file):
        """Test statistics calculation with file metadata."""
        content = b"Content for metadata test"
        test_file = temp_file("metadata_test.txt", content, binary=True)
        
        stats = calculate_file_statistics(str(test_file), include_metadata=True)
        
        assert 'file_size' in stats
        assert 'byte_count' in stats
        assert 'unique_bytes' in stats
        assert 'entropy' in stats
        assert 'null_ratio' in stats
        assert 'file_path' in stats
        assert 'last_modified' in stats


class TestBinaryPatternAnalysis:
    """Test cases for binary pattern analysis."""
    
    def test_analyze_binary_patterns_basic(self):
        """Test basic binary pattern analysis."""
        data = b"Test data for binary analysis"
        result = analyze_binary_patterns(data)
        
        assert 'entropy' in result
        assert 'null_patterns' in result
        assert 'repeated_patterns' in result
        assert 'byte_frequency' in result
        assert 'statistics' in result
    
    def test_analyze_binary_patterns_with_options(self):
        """Test binary pattern analysis with options."""
        data = b"ABABAB\x00\x00\x00CDCD"
        result = analyze_binary_patterns(
            data,
            min_pattern_length=2,
            entropy_threshold=5.0
        )
        
        assert result['entropy'] > 0
        assert result['null_patterns']['has_null_sequences'] is True
        assert result['repeated_patterns']['has_repeated_patterns'] is True
    
    def test_analyze_binary_patterns_high_entropy(self):
        """Test analysis of high entropy data."""
        import os
        data = os.urandom(1024)
        result = analyze_binary_patterns(data)
        
        assert result['entropy'] > 7.0
        assert result['null_patterns']['null_count'] == 0
        assert result['repeated_patterns']['has_repeated_patterns'] is False


class TestEntropyCalculator:
    """Test cases for EntropyCalculator class."""
    
    def test_entropy_calculator_initialization(self):
        """Test EntropyCalculator initialization."""
        calc = entropy_calculator()
        
        assert hasattr(calc, 'calculate')
        assert hasattr(calc, 'reset')
    
    def test_entropy_calculator_streaming(self):
        """Test streaming entropy calculation."""
        calc = entropy_calculator()
        
        # Add data in chunks
        calc.update(b"First chunk")
        calc.update(b"Second chunk")
        calc.update(b"Third chunk")
        
        entropy = calc.entropy()
        assert 0.0 <= entropy <= 8.0
    
    def test_entropy_calculator_reset(self):
        """Test entropy calculator reset."""
        calc = entropy_calculator()
        
        calc.update(b"Some data")
        assert len(calc._data) > 0
        
        calc.reset()
        assert len(calc._data) == 0
        assert calc.entropy() == 0.0
    
    def test_entropy_calculator_large_data(self):
        """Test entropy calculator with large data."""
        calc = entropy_calculator()
        
        # Add large amount of data
        for i in range(1000):
            calc.update(f"Chunk {i}\n".encode())
        
        entropy = calc.entropy()
        assert 0.0 <= entropy <= 8.0


class TestPatternDetector:
    """Test cases for PatternDetector class."""
    
    def test_pattern_detector_initialization(self):
        """Test PatternDetector initialization."""
        detector = pattern_detector()
        
        assert hasattr(detector, 'detect_patterns')
        assert hasattr(detector, 'set_min_length')
    
    def test_pattern_detector_find_patterns(self):
        """Test pattern detection."""
        detector = pattern_detector()
        detector.set_min_length(2)
        
        data = b"ABABABCDCDXYXY"
        patterns = detector.detect_patterns(data)
        
        assert len(patterns) > 0
        assert any(p['pattern'] == b'AB' for p in patterns)
        assert any(p['pattern'] == b'CD' for p in patterns)
    
    def test_pattern_detector_with_threshold(self):
        """Test pattern detection with frequency threshold."""
        detector = pattern_detector()
        detector.set_min_length(2)
        detector.set_frequency_threshold(2)
        
        data = b"ABABABCDCDXYXY"  # AB appears 3 times, others 2 times
        patterns = detector.detect_patterns(data)
        
        # Should find patterns that appear at least 2 times
        for pattern in patterns:
            assert pattern['frequency'] >= 2


class TestBinaryAnalyzer:
    """Test cases for BinaryAnalyzer class."""
    
    def test_binary_analyzer_initialization(self):
        """Test BinaryAnalyzer initialization."""
        analyzer = binary_analyzer()
        
        assert hasattr(analyzer, 'analyze')
        assert hasattr(analyzer, 'set_options')
    
    def test_binary_analyzer_comprehensive_analysis(self):
        """Test comprehensive binary analysis."""
        analyzer = binary_analyzer()
        analyzer.set_options({
            'entropy_threshold': 5.0,
            'pattern_min_length': 2,
            'include_metadata': True
        })
        
        data = b"ABABAB\x00\x00\x00RandomData"
        result = analyzer.analyze(data)
        
        assert 'entropy' in result
        assert 'patterns' in result
        assert 'null_analysis' in result
        assert 'statistics' in result
        assert 'summary' in result
        
        # Check summary
        assert 'is_high_entropy' in result['summary']
        assert 'has_null_patterns' in result['summary']
        assert 'has_repeated_patterns' in result['summary']
    
    def test_binary_analyzer_empty_data(self):
        """Test analysis of empty data."""
        analyzer = binary_analyzer()
        result = analyzer.analyze(b"")
        
        assert result['entropy'] == 0.0
        assert result['summary']['is_empty'] is True
    
    def test_binary_analyzer_suspicious_patterns(self):
        """Test detection of suspicious patterns."""
        analyzer = binary_analyzer()
        
        # Data with suspicious patterns (high null ratio, repeated patterns)
        suspicious_data = b"\x00\x00\x00\x00" * 100 + b"ABABAB" * 50
        result = analyzer.analyze(suspicious_data)
        
        assert result['summary']['has_null_patterns'] is True
        assert result['summary']['has_repeated_patterns'] is True
        assert result['null_analysis']['null_ratio'] > 0.5


class TestMathUtilitiesIntegration:
    """Integration tests for math utilities."""
    
    def test_entropy_and_pattern_correlation(self):
        """Test correlation between entropy and pattern detection."""
        # Low entropy data should have more patterns
        low_entropy_data = b"ABABABABABABABAB"
        high_entropy_data = bytes([i % 256 for i in range(1000)])
        
        low_result = analyze_binary_patterns(low_entropy_data)
        high_result = analyze_binary_patterns(high_entropy_data)
        
        assert low_result['entropy'] < high_result['entropy']
        assert low_result['repeated_patterns']['has_repeated_patterns'] is True
    
    def test_comprehensive_analysis_workflow(self):
        """Test comprehensive analysis workflow."""
        import os
        data = os.urandom(1024)
        
        # Step 1: Calculate entropy
        entropy = calculate_shannon_entropy(data)
        
        # Step 2: Detect patterns
        patterns = detect_repeated_patterns(data)
        
        # Step 3: Analyze null bytes
        null_analysis = detect_null_byte_patterns(data)
        
        # Step 4: Calculate statistics
        stats = calculate_file_statistics_from_data(data)
        
        # Verify consistency
        assert 0.0 <= entropy <= 8.0
        assert isinstance(patterns, dict)
        assert isinstance(null_analysis, dict)
        assert isinstance(stats, dict)


# Helper function for testing
def calculate_file_statistics_from_data(data):
    """Helper function to calculate statistics from data (not file)."""
    return {
        'file_size': len(data),
        'byte_count': len(data),
        'unique_bytes': len(set(data)),
        'entropy': calculate_shannon_entropy(data),
        'null_ratio': detect_null_byte_patterns(data)['null_ratio']
    }
