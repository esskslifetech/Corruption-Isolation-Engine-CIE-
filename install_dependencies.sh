#!/bin/bash
# Dependency installer for the Corruption Isolation Engine (CIE).
#
# Verifies the interpreter, installs requirements.txt, then *checks* that the
# optional validators really import - the old script printed "Installation
# complete!" unconditionally, so a failed install looked like a success.

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

echo "Corruption Isolation Engine (CIE) - dependency setup"
echo "===================================================="

# --- interpreter ---------------------------------------------------------
PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "ERROR: $PYTHON_BIN not found. CIE needs Python 3.8 or newer." >&2
    exit 1
fi

PY_VERSION="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
echo "Python             : $PYTHON_BIN ($PY_VERSION)"
if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)'; then
    echo "ERROR: Python 3.8+ is required (found $PY_VERSION)." >&2
    exit 1
fi

# --- pip -----------------------------------------------------------------
if ! "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
    echo "ERROR: pip is not available for $PYTHON_BIN." >&2
    echo "       Try: $PYTHON_BIN -m ensurepip --upgrade" >&2
    exit 1
fi

# tkinter is a stdlib module, not a pip package: check rather than install.
if "$PYTHON_BIN" -c 'import tkinter' >/dev/null 2>&1; then
    echo "tkinter (GUI)      : available"
    GUI_OK=1
else
    echo "tkinter (GUI)      : MISSING - the CLI works, --gui will not."
    echo "                     Debian/Ubuntu: sudo apt-get install python3-tk"
    GUI_OK=0
fi

# --- requirements --------------------------------------------------------
echo
echo "Installing Python packages from requirements.txt ..."
if ! "$PYTHON_BIN" -m pip install -r requirements.txt; then
    echo "ERROR: pip install failed - see the output above." >&2
    exit 1
fi

# --- optional external tools --------------------------------------------
echo
echo "Checking optional external tools ..."
FFPROBE_OK=0
if command -v ffprobe >/dev/null 2>&1; then
    echo "ffprobe            : available - media validation enabled"
    FFPROBE_OK=1
else
    echo "ffprobe            : not found - media files (mp4/mkv/mp3/...) get"
    echo "                     signature checks only"
    echo "                     Debian/Ubuntu: sudo apt-get install ffmpeg"
    echo "                     macOS:         brew install ffmpeg"
fi

CXX_OK=0
if command -v g++ >/dev/null 2>&1 && "$PYTHON_BIN" -c 'exit(0)' ; then
    if echo 'int main(){return 0;}' | g++ -std=c++20 -x c++ - -o /tmp/cie_cxx_probe 2>/dev/null; then
        echo "g++ (C++20)        : available - optional native scanner can build"
        CXX_OK=1
        rm -f /tmp/cie_cxx_probe
    else
        echo "g++ (C++20)        : present but does not accept -std=c++20"
        echo "                     (the engine is pure Python; this is optional)"
    fi
else
    echo "g++ (C++20)        : not found - optional native scanner disabled"
fi

# --- verify the install actually works ----------------------------------
echo
echo "Verifying the installation ..."
if ! "$PYTHON_BIN" - <<'PY'
import importlib.util
import sys

modules = {
    "core engine": ["sqlite3", "hashlib", "zlib"],
    "Pillow": ["PIL"],
    "pypdf": ["pypdf", "PyPDF2"],          # either name satisfies the validator
    "python-docx": ["docx"],
    "openpyxl": ["openpyxl"],
    "numpy": ["numpy"],
}
missing = []
for label, names in modules.items():
    if not any(importlib.util.find_spec(name) for name in names):
        missing.append(label)

for label, names in modules.items():
    found = next((n for n in names if importlib.util.find_spec(n)), None)
    print(f"  {label:<14}: {'OK (' + found + ')' if found else 'MISSING'}")

missing = [m for m in missing if m != "numpy"]
if missing:
    print("Missing required packages: " + ", ".join(missing), file=sys.stderr)
    raise SystemExit(1)
PY
then
    echo "ERROR: verification failed - the engine would run with reduced checks." >&2
    exit 1
fi

# --- smoke test the CLI --------------------------------------------------
echo
if "$PYTHON_BIN" cie.py --version >/dev/null 2>&1; then
    echo "CLI smoke test     : OK ($("$PYTHON_BIN" cie.py --version))"
else
    echo "ERROR: 'python3 cie.py --version' failed - check the traceback above." >&2
    exit 1
fi

echo
echo "Setup complete."
echo "  Scan a folder : python3 cie.py --scan /path/to/data"
echo "  Launch the GUI: python3 cie.py --gui$( [ "$GUI_OK" -eq 1 ] || echo "   (tkinter missing!)")"
[ "$FFPROBE_OK" -eq 1 ] || echo "  Note: install ffmpeg for deeper media checks."
exit 0
