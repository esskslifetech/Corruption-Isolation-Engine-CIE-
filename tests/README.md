# Test Suite for Corruption Isolation Engine (CIE)

This directory contains comprehensive tests for the Corruption Isolation Engine project.

## Test Structure

```
tests/
├── __init__.py                 # Test package initialization
├── conftest.py                 # Pytest configuration and shared fixtures
├── pytest.ini                  # Pytest configuration file
├── requirements.txt             # Test-specific dependencies
├── README.md                   # This file
├── unit/                       # Unit tests
│   ├── test_core_analyzer.py
│   ├── test_format_validators.py
│   ├── test_processing_modules.py
│   ├── test_math.py
│   └── test_modular_scanner.py
├── integration/                # Integration tests
│   ├── test_full_scan.py
│   └── test_quarantine.py
└── fixtures/                   # Test data fixtures
    ├── __init__.py
    └── sample_files.py
```

## Test Categories

### Unit Tests
Located in `tests/unit/`, these tests verify individual components in isolation:

- **test_core_analyzer.py**: Tests for the main corruption detection engine
- **test_format_validators.py**: Tests for file format validation modules
- **test_processing_modules.py**: Tests for file processing pipeline
- **test_math.py**: Tests for mathematical utilities and entropy calculations
- **test_modular_scanner.py**: Tests for modular scanning strategies

### Integration Tests
Located in `tests/integration/`, these tests verify complete workflows:

- **test_full_scan.py**: End-to-end scanning workflows
- **test_quarantine.py**: Quarantine system integration tests

### Fixtures
Located in `tests/fixtures/`, these provide test data and utilities:

- **sample_files.py**: Generators for creating test files of various types

## Running Tests

### Prerequisites

Install test dependencies:
```bash
pip install -r tests/requirements.txt
```

### Basic Test Execution

Run all tests:
```bash
pytest
```

Run specific test file:
```bash
pytest tests/unit/test_core_analyzer.py
```

Run specific test class:
```bash
pytest tests/unit/test_core_analyzer.py::TestCorruptionDetector
```

Run specific test method:
```bash
pytest tests/unit/test_core_analyzer.py::TestCorruptionDetector::test_scan_directory_with_files
```

### Test Options

#### Verbose Output
```bash
pytest -v
```

#### Coverage Report
```bash
pytest --cov=src --cov-report=html
```

#### Parallel Execution
```bash
pytest -n auto
```

#### Run Only Failed Tests
```bash
pytest --lf
```

#### Run Tests with Markers
```bash
# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Run only performance tests
pytest -m performance

# Skip slow tests
pytest -m "not slow"
```

#### Timeout Tests
```bash
pytest --timeout=30
```

#### Generate HTML Report
```bash
pytest --html=report.html --self-contained-html
```

### Test Markers

The following markers are available to categorize tests:

- `@pytest.mark.unit`: Unit tests for individual modules
- `@pytest.mark.integration`: Integration tests for complete workflows
- `@pytest.mark.slow`: Tests that take a long time to run
- `@pytest.mark.network`: Tests that require network access
- `@pytest.mark.database`: Tests that require database operations
- `@pytest.mark.quarantine`: Tests that involve quarantine operations
- `@pytest.mark.performance`: Performance benchmarking tests
- `@pytest.mark.security`: Security-related tests

## Test Configuration

### Pytest Configuration

The `pytest.ini` file contains configuration for:

- Test discovery patterns
- Output formatting
- Markers definition
- Coverage settings

### Fixtures

The `conftest.py` file provides shared fixtures:

- `temp_directory`: Creates temporary directories for tests
- `temp_file`: Creates temporary files
- `analyzer_config`: Provides test configuration
- `corruption_detector`: Creates detector instances
- `sample_files`: Creates various test file types
- `entropy_files`: Creates files with specific entropy levels

### Test Data

The `fixtures/sample_files.py` module provides utilities for:

- Creating sample files of different types
- Generating files with specific entropy levels
- Creating test directory structures
- Performance test file generation

## Writing New Tests

### Unit Test Template

```python
import pytest
from unittest.mock import Mock, patch

class TestNewModule:
    """Test cases for NewModule class."""
    
    def test_basic_functionality(self, fixture_name):
        """Test basic functionality."""
        # Arrange
        # Setup test data
        
        # Act
        # Execute code under test
        
        # Assert
        # Verify results
        assert True
    
    def test_error_handling(self, fixture_name):
        """Test error handling."""
        # Test error conditions
        with pytest.raises(ExpectedException):
            # Code that should raise exception
            pass
```

### Integration Test Template

```python
class TestNewIntegration:
    """Integration tests for new functionality."""
    
    def test_end_to_end_workflow(self, corruption_detector, temp_directory):
        """Test complete workflow."""
        # Create test files
        # Execute complete workflow
        # Verify end-to-end results
        assert True
```

### Using Fixtures

```python
def test_with_fixture(self, corruption_detector, sample_files):
    """Test using fixtures."""
    # Use corruption_detector fixture
    # Use sample_files fixture
    results = corruption_detector.scan_directory(str(sample_files['valid_txt'].parent))
    assert len(results) > 0
```

## Test Data Management

### Temporary Files

Tests use temporary directories and files that are automatically cleaned up:

```python
def test_with_temp_files(self, temp_directory):
    """Test with temporary files."""
    test_file = temp_directory / "test.txt"
    test_file.write_text("test content")
    # File is automatically cleaned up
```

### Sample Files

Use the sample file generators for consistent test data:

```python
def test_with_sample_files(self, temp_directory):
    """Test with generated sample files."""
    from tests.fixtures.sample_files import SampleFileGenerator
    
    generator = SampleFileGenerator(temp_directory)
    files = generator.create_text_files()
    
    # Use generated files
    assert 'normal' in files
```

## Performance Testing

### Benchmark Tests

Use the `@pytest.mark.benchmark` marker for performance tests:

```python
@pytest.mark.performance
def test_scan_performance(self, corruption_detector, temp_directory):
    """Test scanning performance."""
    # Create performance test files
    from tests.fixtures.sample_files import create_performance_test_files
    
    files = create_performance_test_files(temp_directory, count=1000)
    
    import time
    start_time = time.time()
    results = corruption_detector.scan_directory(str(temp_directory))
    scan_time = time.time() - start_time
    
    # Assert performance requirements
    assert scan_time < 30.0  # Should complete within 30 seconds
    assert len(results) == 1000
```

### Memory Testing

Monitor memory usage in tests:

```python
def test_memory_usage(self, corruption_detector, temp_directory):
    """Test memory efficiency."""
    import psutil
    
    process = psutil.Process()
    initial_memory = process.memory_info().rss
    
    # Execute memory-intensive operation
    results = corruption_detector.scan_directory(str(temp_directory))
    
    final_memory = process.memory_info().rss
    memory_increase = final_memory - initial_memory
    
    # Assert memory requirements
    assert memory_increase < 100 * 1024 * 1024  # Less than 100MB
```

## Continuous Integration

### GitHub Actions

Tests are configured to run on CI/CD:

```yaml
- name: Run Tests
  run: |
    pip install -r tests/requirements.txt
    pytest --cov=src --cov-report=xml
    
- name: Upload Coverage
  uses: codecov/codecov-action@v1
```

### Test Reports

Generate test reports for CI:

```bash
# JUnit XML for CI systems
pytest --junitxml=test-results.xml

# Coverage for code quality
pytest --cov=src --cov-report=xml
```

## Debugging Tests

### Debug Failed Tests

```bash
# Run with pdb on failure
pytest --pdb

# Run with verbose output
pytest -v -s

# Stop on first failure
pytest -x
```

### Test Logging

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Mock External Dependencies

Use mocking for external dependencies:

```python
from unittest.mock import patch

@patch('module.external_function')
def test_with_mock(self, mock_function):
    """Test with mocked external function."""
    mock_function.return_value = "mocked_value"
    # Test code that calls external_function
```

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure src directory is in Python path
2. **Permission Errors**: Check file permissions for test directories
3. **Database Locks**: Use in-memory databases for tests
4. **Timeout Issues**: Increase timeout for slow tests
5. **Memory Issues**: Clean up resources in tests

### Test Isolation

Ensure tests are isolated:

- Use temporary directories
- Clean up resources in `teardown`
- Use in-memory databases
- Mock external services

### Best Practices

1. **Descriptive Names**: Use clear test method names
2. **Arrange-Act-Assert**: Structure tests clearly
3. **Single Responsibility**: Test one thing per test
4. **Independent Tests**: Tests should not depend on each other
5. **Cleanup**: Always clean up resources
6. **Assertions**: Use specific assertions with clear messages

## Contributing

When adding new tests:

1. Follow existing naming conventions
2. Use appropriate fixtures
3. Add documentation for complex tests
4. Include both positive and negative test cases
5. Update this README if adding new test categories

For more information on pytest, see: https://docs.pytest.org/
