"""
Test package for Corruption Isolation Engine

This Project Is Made By Kanishk Soni
"""

# Test configuration
import sys
from pathlib import Path

# Add src to path for imports
project_root = Path(__file__).parent.parent
src_dir = project_root / "src"
sys.path.insert(0, str(src_dir))
sys.path.insert(0, str(src_dir / "python"))

# Test constants
TEST_DATA_DIR = Path(__file__).parent / "fixtures"
TEMP_DIR = Path("/tmp/cie_test")

# Ensure test directories exist
TEST_DATA_DIR.mkdir(exist_ok=True)
TEMP_DIR.mkdir(exist_ok=True)
