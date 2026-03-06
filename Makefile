# Makefile for Corruption Isolation Engine (CIE)

# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
TARGET_CPP = src/cpp/file_analyzer
CPP_SOURCE = src/cpp/file_analyzer.cpp

# Python settings
PYTHON = python3
PYTHON_MAIN = src/gui/main_window.py
PYTHON_CORE = src/python/core_analyzer.py

# Directories
BUILD_DIR = build
QUARANTINE_DIR = quarantine

# Default target
all: cpp gui

# Build C++ executable
cpp: $(TARGET_CPP)

$(TARGET_CPP): $(CPP_SOURCE)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(CPP_SOURCE) -o $(TARGET_CPP)
	@echo "C++ module compiled successfully"

# Run Python GUI
gui: $(PYTHON_MAIN)
	@mkdir -p $(QUARANTINE_DIR)
	$(PYTHON) $(PYTHON_MAIN)

# Run C++ analyzer
run-cpp: $(TARGET_CPP)
	@mkdir -p $(QUARANTINE_DIR)
	@echo "Running C++ analyzer..."
	@read -p "Enter directory path: " dir; \
	$(TARGET_CPP) "$$dir" true

# Install Python dependencies
install:
	pip3 install -r requirements.txt

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(TARGET_CPP)
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Clean quarantine directory
clean-quarantine:
	rm -rf $(QUARANTINE_DIR)
	@echo "Quarantine directory cleaned"

# Full clean
clean-all: clean clean-quarantine
	rm -f *.db *.sqlite

# Test C++ compilation
test-cpp: $(TARGET_CPP)
	@echo "Testing C++ compilation..."
	@mkdir -p test_data
	@echo "test content" > test_data/test.txt
	@$(TARGET_CPP) test_data false
	@rm -rf test_data

# Test Python module
test-python:
	@echo "Testing Python module..."
	$(PYTHON) -c "from src.python.core_analyzer import CorruptionDetector; print('Python module OK')"

# Run all tests
test: test-cpp test-python
	@echo "All tests completed"

# Create distribution package
dist:
	tar -czf cie-$(shell date +%Y%m%d).tar.gz \
		src/ \
		requirements.txt \
		Makefile \
		README.md \
		--exclude='.git*' \
		--exclude='__pycache__' \
		--exclude='*.pyc' \
		--exclude='build' \
		--exclude='quarantine' \
		--exclude='*.db' \
		--exclude='*.sqlite'

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Build both C++ and prepare Python"
	@echo "  cpp          - Compile C++ analyzer"
	@echo "  gui          - Run Python GUI"
	@echo "  run-cpp      - Run C++ analyzer (interactive)"
	@echo "  install      - Install Python dependencies"
	@echo "  clean        - Clean build artifacts"
	@echo "  clean-quarantine - Clean quarantine directory"
	@echo "  clean-all    - Full clean including databases"
	@echo "  test         - Run all tests"
	@echo "  test-cpp     - Test C++ compilation"
	@echo "  test-python  - Test Python module"
	@echo "  dist         - Create distribution package"
	@echo "  help         - Show this help"

.PHONY: all cpp gui run-cpp install clean clean-quarantine clean-all test test-cpp test-python dist help
