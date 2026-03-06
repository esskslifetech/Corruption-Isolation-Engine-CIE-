"""
Unit tests for modular_scanner.py

This Project Is Made By Kanishk Soni
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import time
import json

from src.python.modular_scanner import (
    ModularScanner,
    ScanStrategy,
    FastScanStrategy,
    BalancedScanStrategy,
    DeepScanStrategy,
    ScanResult,
    ScanSummary,
    StrategyFactory,
    ComparisonMode,
    BenchmarkMode
)


class TestScanStrategy:
    """Test cases for ScanStrategy abstract class."""
    
    def test_scan_strategy_is_abstract(self):
        """Test that ScanStrategy cannot be instantiated directly."""
        with pytest.raises(TypeError):
            ScanStrategy()
    
    def test_scan_strategy_methods_raise_not_implemented(self):
        """Test that abstract methods raise NotImplementedError."""
        
        class ConcreteStrategy(ScanStrategy):
            pass
        
        strategy = ConcreteStrategy()
        
        with pytest.raises(NotImplementedError):
            strategy.scan("/test/directory")
        
        with pytest.raises(NotImplementedError):
            strategy.get_strategy_name()


class TestFastScanStrategy:
    """Test cases for FastScanStrategy class."""
    
    def test_fast_scan_strategy_initialization(self, analyzer_config):
        """Test FastScanStrategy initialization."""
        strategy = FastScanStrategy(analyzer_config)
        
        assert strategy.config == analyzer_config
        assert strategy.name == "fast"
    
    def test_get_strategy_name(self, fast_scan_strategy):
        """Test getting strategy name."""
        name = fast_scan_strategy.get_strategy_name()
        assert name == "fast"
    
    def test_fast_scan_basic(self, fast_scan_strategy, sample_files):
        """Test basic fast scanning."""
        temp_dir = list(sample_files.values())[0].parent
        results = fast_scan_strategy.scan(str(temp_dir))
        
        assert isinstance(results, list)
        assert len(results) > 0
        
        for result in results:
            assert hasattr(result, 'file_path')
            assert hasattr(result, 'file_size')
            assert hasattr(result, 'scan_time')
    
    def test_fast_scan_performance(self, fast_scan_strategy, temp_directory):
        """Test fast scan performance characteristics."""
        # Create many files for performance testing
        for i in range(50):
            (temp_directory / f"fast_test_{i}.txt").write_text(f"Content {i}")
        
        start_time = time.time()
        results = fast_scan_strategy.scan(str(temp_directory))
        scan_time = time.time() - start_time
        
        assert len(results) >= 50
        assert scan_time < 5.0  # Should be fast
        
        # Check that results include timing information
        for result in results:
            assert hasattr(result, 'scan_time')
            assert result.scan_time >= 0
    
    def test_fast_scan_minimal_analysis(self, fast_scan_strategy, sample_files):
        """Test that fast scan performs minimal analysis."""
        temp_dir = list(sample_files.values())[0].parent
        results = fast_scan_strategy.scan(str(temp_dir))
        
        # Fast scan should skip expensive operations
        for result in results:
            # Should have basic info but skip deep validation
            assert result.file_path is not None
            assert result.file_size >= 0
            # May not have full format validation in fast mode
    
    def test_fast_scan_nonexistent_directory(self, fast_scan_strategy):
        """Test fast scan with non-existent directory."""
        with pytest.raises((FileNotFoundError, OSError)):
            fast_scan_strategy.scan("/nonexistent/directory")


class TestBalancedScanStrategy:
    """Test cases for BalancedScanStrategy class."""
    
    def test_balanced_scan_strategy_initialization(self, analyzer_config):
        """Test BalancedScanStrategy initialization."""
        strategy = BalancedScanStrategy(analyzer_config)
        
        assert strategy.config == analyzer_config
        assert strategy.name == "balanced"
    
    def test_get_strategy_name(self, balanced_scan_strategy):
        """Test getting strategy name."""
        name = balanced_scan_strategy.get_strategy_name()
        assert name == "balanced"
    
    def test_balanced_scan_comprehensive(self, balanced_scan_strategy, sample_files):
        """Test balanced scan with comprehensive analysis."""
        temp_dir = list(sample_files.values())[0].parent
        results = balanced_scan_strategy.scan(str(temp_dir))
        
        assert isinstance(results, list)
        assert len(results) > 0
        
        # Balanced scan should include more analysis than fast scan
        for result in results:
            assert result.file_path is not None
            assert result.file_size >= 0
            # Should have more detailed analysis than fast scan
    
    def test_balanced_scan_entropy_analysis(self, balanced_scan_strategy, entropy_files):
        """Test balanced scan includes entropy analysis."""
        temp_dir = list(entropy_files.values())[0].parent
        results = balanced_scan_strategy.scan(str(temp_dir))
        
        # Should include entropy information
        for result in results:
            if result.file_size > 0:
                assert hasattr(result, 'entropy')
                assert 0.0 <= result.entropy <= 8.0
    
    def test_balanced_scan_format_validation(self, balanced_scan_strategy, sample_files):
        """Test balanced scan includes format validation."""
        temp_dir = list(sample_files.values())[0].parent
        results = balanced_scan_strategy.scan(str(temp_dir))
        
        # Should include format validation for common file types
        for result in results:
            # May have format validation for recognized types
            assert hasattr(result, 'format_validation')


class TestDeepScanStrategy:
    """Test cases for DeepScanStrategy class."""
    
    def test_deep_scan_strategy_initialization(self, analyzer_config):
        """Test DeepScanStrategy initialization."""
        strategy = DeepScanStrategy(analyzer_config)
        
        assert strategy.config == analyzer_config
        assert strategy.name == "deep"
    
    def test_get_strategy_name(self, deep_scan_strategy):
        """Test getting strategy name."""
        name = deep_scan_strategy.get_strategy_name()
        assert name == "deep"
    
    def test_deep_scan_thorough_analysis(self, deep_scan_strategy, sample_files):
        """Test deep scan with thorough analysis."""
        temp_dir = list(sample_files.values())[0].parent
        results = deep_scan_strategy.scan(str(temp_dir))
        
        assert isinstance(results, list)
        assert len(results) > 0
        
        # Deep scan should include maximum analysis
        for result in results:
            assert result.file_path is not None
            assert result.file_size >= 0
            # Should have comprehensive validation and analysis
    
    def test_deep_scan_extended_validation(self, deep_scan_strategy, sample_files):
        """Test deep scan includes extended validation."""
        temp_dir = list(sample_files.values())[0].parent
        results = deep_scan_strategy.scan(str(temp_dir))
        
        # Deep scan should perform extensive validation
        for result in results:
            # Should have detailed format validation
            assert hasattr(result, 'format_validation')
            assert hasattr(result, 'detailed_analysis')
    
    def test_deep_scan_performance_impact(self, deep_scan_strategy, temp_directory):
        """Test that deep scan takes longer but provides more detail."""
        # Create test files
        for i in range(10):
            (temp_directory / f"deep_test_{i}.txt").write_text(f"Content {i}" * 100)
        
        start_time = time.time()
        results = deep_scan_strategy.scan(str(temp_directory))
        scan_time = time.time() - start_time
        
        assert len(results) >= 10
        # Deep scan should take longer but provide more detail
        assert scan_time > 0.1  # Should take some time
        
        # Results should be comprehensive
        for result in results:
            assert hasattr(result, 'detailed_analysis')
            assert hasattr(result, 'validation_details')


class TestModularScanner:
    """Test cases for ModularScanner class."""
    
    def test_modular_scanner_initialization(self, analyzer_config):
        """Test ModularScanner initialization."""
        scanner = ModularScanner(analyzer_config)
        
        assert scanner.config == analyzer_config
        assert scanner.strategies is not None
        assert len(scanner.strategies) > 0
    
    def test_set_strategy(self, modular_scanner):
        """Test setting scan strategy."""
        modular_scanner.set_strategy("fast")
        assert modular_scanner.current_strategy.name == "fast"
        
        modular_scanner.set_strategy("balanced")
        assert modular_scanner.current_strategy.name == "balanced"
        
        modular_scanner.set_strategy("deep")
        assert modular_scanner.current_strategy.name == "deep"
    
    def test_set_invalid_strategy(self, modular_scanner):
        """Test setting invalid strategy."""
        with pytest.raises(ValueError):
            modular_scanner.set_strategy("invalid")
    
    def test_scan_with_current_strategy(self, modular_scanner, sample_files):
        """Test scanning with current strategy."""
        modular_scanner.set_strategy("fast")
        temp_dir = list(sample_files.values())[0].parent
        
        results = modular_scanner.scan(str(temp_dir))
        
        assert isinstance(results, list)
        assert len(results) > 0
    
    def test_scan_with_strategy_override(self, modular_scanner, sample_files):
        """Test scanning with strategy override."""
        temp_dir = list(sample_files.values())[0].parent
        
        # Override strategy for this scan
        results = modular_scanner.scan(str(temp_dir), strategy="deep")
        
        assert isinstance(results, list)
        assert len(results) > 0
        # Should have used deep strategy
    
    def test_get_available_strategies(self, modular_scanner):
        """Test getting available strategies."""
        strategies = modular_scanner.get_available_strategies()
        
        assert isinstance(strategies, list)
        assert "fast" in strategies
        assert "balanced" in strategies
        assert "deep" in strategies
    
    def test_scan_with_progress_callback(self, modular_scanner, sample_files):
        """Test scanning with progress callback."""
        progress_calls = []
        
        def progress_callback(current, total, current_file):
            progress_calls.append((current, total, current_file))
        
        temp_dir = list(sample_files.values())[0].parent
        results = modular_scanner.scan(str(temp_dir), progress_callback=progress_callback)
        
        assert len(results) > 0
        assert len(progress_calls) > 0
    
    def test_scan_cancellation(self, modular_scanner, temp_directory):
        """Test scan cancellation."""
        # Create many files
        for i in range(100):
            (temp_directory / f"cancel_test_{i}.txt").write_text(f"Content {i}")
        
        # Mock cancellation
        cancelled = False
        
        def should_cancel():
            nonlocal cancelled
            if not cancelled:
                cancelled = True
                return True
            return False
        
        modular_scanner.set_cancellation_check(should_cancel)
        
        with pytest.raises(Exception):  # Should raise cancellation exception
            modular_scanner.scan(str(temp_directory))


class TestScanResult:
    """Test cases for ScanResult class."""
    
    def test_scan_result_creation(self):
        """Test ScanResult creation."""
        result = ScanResult(
            file_path="/test/file.txt",
            file_size=100,
            strategy_used="fast",
            scan_time=0.5,
            is_corrupted=False,
            entropy=2.5,
            format_validation=None
        )
        
        assert result.file_path == "/test/file.txt"
        assert result.file_size == 100
        assert result.strategy_used == "fast"
        assert result.scan_time == 0.5
        assert result.is_corrupted is False
        assert result.entropy == 2.5
        assert result.format_validation is None
    
    def test_scan_result_with_validation(self):
        """Test ScanResult with format validation."""
        mock_validation = Mock(is_valid=True, error_message=None)
        
        result = ScanResult(
            file_path="/test/file.pdf",
            file_size=200,
            strategy_used="deep",
            scan_time=1.5,
            is_corrupted=False,
            entropy=3.2,
            format_validation=mock_validation
        )
        
        assert result.format_validation == mock_validation
        assert result.is_corrupted is False
    
    def test_scan_result_serialization(self):
        """Test ScanResult serialization."""
        result = ScanResult(
            file_path="/test/file.txt",
            file_size=100,
            strategy_used="balanced",
            scan_time=0.8,
            is_corrupted=True,
            entropy=7.5,
            format_validation=None
        )
        
        # Convert to dictionary
        result_dict = result.to_dict()
        
        assert isinstance(result_dict, dict)
        assert result_dict['file_path'] == "/test/file.txt"
        assert result_dict['file_size'] == 100
        assert result_dict['strategy_used'] == "balanced"
        assert result_dict['scan_time'] == 0.8
        assert result_dict['is_corrupted'] is True
        assert result_dict['entropy'] == 7.5


class TestScanSummary:
    """Test cases for ScanSummary class."""
    
    def test_scan_summary_creation(self):
        """Test ScanSummary creation."""
        summary = ScanSummary(
            strategy="fast",
            total_files=100,
            corrupted_files=5,
            scan_time=10.5,
            total_size=1000000,
            average_file_size=10000
        )
        
        assert summary.strategy == "fast"
        assert summary.total_files == 100
        assert summary.corrupted_files == 5
        assert summary.scan_time == 10.5
        assert summary.total_size == 1000000
        assert summary.average_file_size == 10000
    
    def test_scan_summary_derived_metrics(self):
        """Test ScanSummary derived metrics."""
        summary = ScanSummary(
            strategy="balanced",
            total_files=100,
            corrupted_files=5,
            scan_time=10.0,
            total_size=1000000,
            average_file_size=10000
        )
        
        # Should calculate derived metrics
        assert summary.corruption_rate == 0.05  # 5/100
        assert summary.files_per_second == 10.0  # 100/10
    
    def test_scan_summary_serialization(self):
        """Test ScanSummary serialization."""
        summary = ScanSummary(
            strategy="deep",
            total_files=50,
            corrupted_files=2,
            scan_time=15.0,
            total_size=500000,
            average_file_size=10000
        )
        
        # Convert to dictionary
        summary_dict = summary.to_dict()
        
        assert isinstance(summary_dict, dict)
        assert summary_dict['strategy'] == "deep"
        assert summary_dict['total_files'] == 50
        assert summary_dict['corrupted_files'] == 2
        assert summary_dict['scan_time'] == 15.0
        assert summary_dict['corruption_rate'] == 0.04


class TestStrategyFactory:
    """Test cases for StrategyFactory class."""
    
    def test_create_fast_strategy(self, analyzer_config):
        """Test creating fast strategy."""
        strategy = StrategyFactory.create_strategy("fast", analyzer_config)
        
        assert isinstance(strategy, FastScanStrategy)
        assert strategy.name == "fast"
    
    def test_create_balanced_strategy(self, analyzer_config):
        """Test creating balanced strategy."""
        strategy = StrategyFactory.create_strategy("balanced", analyzer_config)
        
        assert isinstance(strategy, BalancedScanStrategy)
        assert strategy.name == "balanced"
    
    def test_create_deep_strategy(self, analyzer_config):
        """Test creating deep strategy."""
        strategy = StrategyFactory.create_strategy("deep", analyzer_config)
        
        assert isinstance(strategy, DeepScanStrategy)
        assert strategy.name == "deep"
    
    def test_create_invalid_strategy(self, analyzer_config):
        """Test creating invalid strategy."""
        with pytest.raises(ValueError):
            StrategyFactory.create_strategy("invalid", analyzer_config)
    
    def test_get_available_strategies(self):
        """Test getting available strategies."""
        strategies = StrategyFactory.get_available_strategies()
        
        assert isinstance(strategies, list)
        assert "fast" in strategies
        assert "balanced" in strategies
        assert "deep" in strategies


class TestComparisonMode:
    """Test cases for ComparisonMode class."""
    
    def test_comparison_mode_initialization(self, analyzer_config):
        """Test ComparisonMode initialization."""
        comparison = ComparisonMode(analyzer_config)
        
        assert comparison.config == analyzer_config
        assert comparison.strategies is not None
    
    def test_compare_strategies(self, comparison_mode, sample_files):
        """Test comparing different strategies."""
        temp_dir = list(sample_files.values())[0].parent
        
        results = comparison_mode.compare_strategies(
            str(temp_dir),
            strategies=["fast", "balanced"]
        )
        
        assert isinstance(results, dict)
        assert "fast" in results
        assert "balanced" in results
        
        for strategy_name, strategy_results in results.items():
            assert isinstance(strategy_results, list)
            assert len(strategy_results) > 0
    
    def test_compare_all_strategies(self, comparison_mode, sample_files):
        """Test comparing all available strategies."""
        temp_dir = list(sample_files.values())[0].parent
        
        results = comparison_mode.compare_all_strategies(str(temp_dir))
        
        assert isinstance(results, dict)
        assert len(results) >= 3  # At least fast, balanced, deep
        
        # Each strategy should have results
        for strategy_name, strategy_results in results.items():
            assert isinstance(strategy_results, list)
    
    def test_generate_comparison_report(self, comparison_mode, sample_files):
        """Test generating comparison report."""
        temp_dir = list(sample_files.values())[0].parent
        
        comparison_results = comparison_mode.compare_all_strategies(str(temp_dir))
        report = comparison_mode.generate_report(comparison_results)
        
        assert isinstance(report, dict)
        assert 'strategies' in report
        assert 'comparison' in report
        assert 'recommendations' in report


class TestBenchmarkMode:
    """Test cases for BenchmarkMode class."""
    
    def test_benchmark_mode_initialization(self, analyzer_config):
        """Test BenchmarkMode initialization."""
        benchmark = BenchmarkMode(analyzer_config)
        
        assert benchmark.config == analyzer_config
    
    def test_run_benchmark(self, benchmark_mode, temp_directory):
        """Test running benchmark."""
        # Create test files
        for i in range(20):
            (temp_directory / f"benchmark_{i}.txt").write_text(f"Benchmark content {i}")
        
        results = benchmark_mode.run_benchmark(
            str(temp_directory),
            iterations=3,
            strategies=["fast", "balanced"]
        )
        
        assert isinstance(results, dict)
        assert "fast" in results
        assert "balanced" in results
        
        for strategy_name, strategy_results in results.items():
            assert 'iterations' in strategy_results
            assert 'average_time' in strategy_results
            assert 'performance_metrics' in strategy_results
    
    def test_run_performance_benchmark(self, benchmark_mode, temp_directory):
        """Test running performance benchmark."""
        # Create varied test files
        file_types = [
            ("small.txt", "Small content"),
            ("medium.txt", "Medium content " * 100),
            ("large.txt", "Large content " * 10000)
        ]
        
        for filename, content in file_types:
            (temp_directory / filename).write_text(content)
        
        results = benchmark_mode.run_performance_benchmark(str(temp_directory))
        
        assert isinstance(results, dict)
        assert 'file_size_analysis' in results
        assert 'strategy_performance' in results
        assert 'recommendations' in results


# Fixtures for test classes
@pytest.fixture
def analyzer_config():
    """Create analyzer config for testing."""
    from src.python.core_analyzer import AnalyzerConfig
    return AnalyzerConfig(
        db_path=":memory:",
        quarantine_dir=tempfile.mkdtemp(),
        chunk_size=1024,
        max_workers=2
    )


@pytest.fixture
def fast_scan_strategy(analyzer_config):
    """Create FastScanStrategy instance for testing."""
    return FastScanStrategy(analyzer_config)


@pytest.fixture
def balanced_scan_strategy(analyzer_config):
    """Create BalancedScanStrategy instance for testing."""
    return BalancedScanStrategy(analyzer_config)


@pytest.fixture
def deep_scan_strategy(analyzer_config):
    """Create DeepScanStrategy instance for testing."""
    return DeepScanStrategy(analyzer_config)


@pytest.fixture
def modular_scanner(analyzer_config):
    """Create ModularScanner instance for testing."""
    return ModularScanner(analyzer_config)


@pytest.fixture
def comparison_mode(analyzer_config):
    """Create ComparisonMode instance for testing."""
    return ComparisonMode(analyzer_config)


@pytest.fixture
def benchmark_mode(analyzer_config):
    """Create BenchmarkMode instance for testing."""
    return BenchmarkMode(analyzer_config)


import tempfile
