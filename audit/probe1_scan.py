#!/usr/bin/env python3
"""Fact-check harness: load CIE core_analyzer with the sys.path order FIXED
(so the repo's math.py does not shadow the stdlib math module), then exercise
the real logic end-to-end."""
import shutil
import sys
from pathlib import Path

ROOT = Path("/tmp/cie_wt")
sys.path.append(str(ROOT / "src" / "python"))   # APPEND, not insert -> stdlib wins

import math as _stdlib_math
assert "site-packages" in str(_stdlib_math.__file__) or "lib/python" in str(_stdlib_math.__file__), \
    f"stdlib math shadowed: {_stdlib_math.__file__}"

from core_analyzer import AnalyzerConfig, CorruptionDetector, FileStatus  # noqa: E402

WORK = Path("/tmp/cie_work")
if WORK.exists():
    shutil.rmtree(WORK)
WORK.mkdir(parents=True)

CORPUS = Path("/tmp/corpus")

cfg = AnalyzerConfig(db_path=str(WORK / "cie.db"), quarantine_dir=str(WORK / "quarantine"))
det = CorruptionDetector(cfg)

print("=" * 74)
print("A. FRESH-DATABASE SCAN OF REAL FILES  (what does 'detection' actually detect?)")
print("=" * 74)
results = det.scan_directory(CORPUS, recursive=True)
print(f"{'file':<22}{'status':<22}{'size':>8}  {'entropy':>7}  note")
for r in results:
    note = (r.error_message or "")[:34]
    print(f"{Path(r.file_path).name:<22}{r.status.name:<22}{r.file_size:>8}  {r.shannon_entropy:>7.3f}  {note}")
flagged = [r for r in results if r.is_corrupted]
print(f"\nflagged corrupted: {len(flagged)}/{len(results)}")
for r in flagged:
    print(f"   -> {Path(r.file_path).name:<20} {r.status.name}: {r.error_message}")
