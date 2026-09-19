# Makefile for the Corruption Isolation Engine (CIE)
#
# Corrections versus the original:
#   * -std=c++20 (the source uses C++20 constructs; c++17 did not compile)
#   * `all` no longer launches the GUI - it built the engine and then blocked
#     on a desktop window, which made it unusable on a server or over SSH
#   * `test` runs the real pytest suite instead of two smoke prints
#   * `dist` excludes the truth data (.db, quarantine, __pycache__, .git)
#   * `install` uses `python3 -m pip` so it works without a pip3 shim
#   * every target that writes files is phony and `make -n` shows real work

CXX        ?= g++
CXXFLAGS   ?= -std=c++20 -Wall -Wextra -O2
CPP_SOURCE  = src/cpp/file_analyzer.cpp
CPP_TARGET  = build/file_analyzer
# Python-facing C ABI core loaded by src/python/cpp_accel.py (ctypes). It reuses
# the SHA-256 and byte statistics from file_analyzer.cpp, so the two cannot
# drift apart; when it is absent the Python engine falls back to a pure-Python
# metrics pass automatically.
ACCEL_SOURCE = src/cpp/cie_accel.cpp
ACCEL_TARGET = build/libcie_accel.so

PYTHON      ?= python3
CIE_CLI      = cie.py
PYTHON_SRC   = src/python
GUI_SOURCE   = src/gui/main_window.py

BUILD_DIR       = build
QUARANTINE_DIR  = quarantine
DIST_VERSION   ?= $(shell date +%Y%m%d)

# ---------------------------------------------------------------------------
# Default: make the engine ready to run - never start a GUI from `all`.
# ---------------------------------------------------------------------------
all: check

# Sanity-check the Python entry point (fast, no side effects).
check:
	@echo "Checking the CIE Python engine ..."
	@$(PYTHON) $(PYTHON_SRC)/core_analyzer.py >/dev/null
	@$(PYTHON) $(CIE_CLI) --version
	@echo "Engine ready. Try: make scan DIR=/path/to/data"

# ---------------------------------------------------------------------------
# Scanning helpers
# ---------------------------------------------------------------------------
scan:
	@test -n "$(DIR)" || { echo "usage: make scan DIR=/path/to/data"; exit 2; }
	$(PYTHON) $(CIE_CLI) --scan "$(DIR)"

scan-fast:
	@test -n "$(DIR)" || { echo "usage: make scan-fast DIR=/path/to/data"; exit 2; }
	$(PYTHON) $(CIE_CLI) --modular-scan "$(DIR)" --strategy fast

# ---------------------------------------------------------------------------
# C++ helper (optional: the shipped engine is pure Python)
# ---------------------------------------------------------------------------
cpp: $(CPP_TARGET) $(ACCEL_TARGET)

$(CPP_TARGET): $(CPP_SOURCE)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(CPP_SOURCE) -o $(CPP_TARGET)
	@echo "C++ module compiled -> $(CPP_TARGET)"

# The acceleration library is what the Python engine actually calls.
$(ACCEL_TARGET): $(ACCEL_SOURCE) $(CPP_SOURCE)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -fPIC -shared -fvisibility=hidden $(ACCEL_SOURCE) -o $(ACCEL_TARGET)
	@echo "C++ acceleration library -> $(ACCEL_TARGET) (used by the Python engine)"

run-cpp: $(CPP_TARGET)
	@test -n "$(DIR)" || { echo "usage: make run-cpp DIR=/path/to/data"; exit 2; }
	$(CPP_TARGET) "$(DIR)" true

# ---------------------------------------------------------------------------
# GUI (explicit target only)
# ---------------------------------------------------------------------------
gui: $(GUI_SOURCE)
	@mkdir -p $(QUARANTINE_DIR)
	$(PYTHON) $(CIE_CLI) --gui

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
test:
	$(PYTHON) -m pytest tests/ -q

test-verbose:
	$(PYTHON) -m pytest tests/ -v

test-cov:
	$(PYTHON) -m pytest tests/ --cov=src/python --cov-report=term-missing

# Self-tests embedded in each module (no pytest needed).
test-selftest:
	@for module in core_analyzer format_validators cie_math processing_modules; do \
		echo "--- $$module ---"; \
		( cd $(PYTHON_SRC) && $(PYTHON) $$module.py ) || exit 1; \
	done

test-cpp: $(CPP_TARGET)
	@echo "C++ module built and runnable: $(CPP_TARGET)"

# ---------------------------------------------------------------------------
# Setup / distribution
# ---------------------------------------------------------------------------
install:
	$(PYTHON) -m pip install -r requirements.txt

dist:
	tar -czf cie-$(DIST_VERSION).tar.gz \
		--exclude='.git*' \
		--exclude='__pycache__' \
		--exclude='*.pyc' \
		--exclude='$(BUILD_DIR)' \
		--exclude='$(QUARANTINE_DIR)' \
		--exclude='*.db' \
		--exclude='*.db-wal' \
		--exclude='*.db-shm' \
		--exclude='*.sqlite' \
		--exclude='cie-*.tar.gz' \
		cie.py src tests config docs requirements.txt Makefile README.md LICENSE 2>/dev/null || \
	tar -czf cie-$(DIST_VERSION).tar.gz \
		--exclude='.git*' --exclude='__pycache__' --exclude='*.pyc' \
		--exclude='$(BUILD_DIR)' --exclude='$(QUARANTINE_DIR)' \
		--exclude='*.db*' --exclude='*.sqlite' \
		cie.py src tests config docs requirements.txt Makefile README.md
	@echo "Created cie-$(DIST_VERSION).tar.gz"

# ---------------------------------------------------------------------------
# Cleaning
# ---------------------------------------------------------------------------
clean:
	rm -rf $(BUILD_DIR)
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

clean-quarantine:
	rm -rf $(QUARANTINE_DIR)
	@echo "Quarantine directory cleaned (quarantined files are gone for good)"

clean-db:
	rm -f *.db *.db-wal *.db-shm *.sqlite
	@echo "Scan databases removed - baselines are lost, corruption history resets"

clean-all: clean clean-quarantine clean-db

help:
	@echo "Corruption Isolation Engine - available targets"
	@echo ""
	@echo "  all              - check the engine (default; no GUI)"
	@echo "  check            - run the entry-point sanity check"
	@echo "  scan DIR=...     - full corrupting-file scan of DIR"
	@echo "  scan-fast DIR=.. - fast signature-only modular scan of DIR"
	@echo "  cpp              - compile the C++ analyzer + acceleration library"
	@echo "  run-cpp DIR=...  - run the optional C++ helper"
	@echo "  gui              - launch the Tk GUI"
	@echo "  install          - install Python dependencies"
	@echo "  test             - run the pytest suite"
	@echo "  test-verbose     - run the pytest suite verbosely"
	@echo "  test-cov         - run the suite with coverage"
	@echo "  test-selftest    - run each module's embedded self-test"
	@echo "  test-cpp         - build the C++ helper"
	@echo "  dist             - create a source tarball"
	@echo "  clean            - remove build artifacts"
	@echo "  clean-quarantine - delete the quarantine directory"
	@echo "  clean-db         - delete scan databases (loses history!)"
	@echo "  clean-all        - clean + quarantine + databases"
	@echo "  help             - show this help"

.PHONY: all check scan scan-fast cpp run-cpp gui install dist \
        test test-verbose test-cov test-selftest test-cpp \
        clean clean-quarantine clean-db clean-all help
