#!/usr/bin/env python3
"""Probe 2: baseline/checksum logic, 'corruption amnesia', quarantine safety."""
import shutil
import sys
from pathlib import Path

ROOT = Path("/tmp/cie_wt")
sys.path.append(str(ROOT / "src" / "python"))
from core_analyzer import AnalyzerConfig, CorruptionDetector  # noqa: E402

WORK = Path("/tmp/cie_base")
if WORK.exists():
    shutil.rmtree(WORK)
WORK.mkdir(parents=True)
target = WORK / "document.txt"
target.write_bytes(b"IMPORTANT BUSINESS DATA v1")

cfg = AnalyzerConfig(db_path=str(WORK / "cie.db"), quarantine_dir=str(WORK / "quarantine"))
det = CorruptionDetector(cfg)

def show(label):
    res = det.scan_directory(WORK, recursive=True)
    for r in res:
        if Path(r.file_path).name == "document.txt":
            print(f"  {label:<42} -> {r.status.name:<20} is_corrupted={r.is_corrupted}  {r.error_message or ''}")

print("=" * 74)
print("B. DOES CORRUPTION DETECTION PERSIST ACROSS SCANS?")
print("=" * 74)
show("scan 1: new file, no baseline")
target.write_bytes(b"X" * 24)           # same size, different bytes = silent bit-rot
show("scan 2: same-size content changed")
show("scan 3: no change since scan 2")

target.write_bytes(b"TRUNCATED")
show("scan 4: file truncated (size changed)")
show("scan 5: no change since scan 4")

print()
print("=" * 74)
print("C. QUARANTINE BEHAVIOUR (auto-quarantine of flagged files)")
print("=" * 74)
risky = WORK / "deck.pptx"
shutil.copy("/tmp/corpus/real.pptx", risky)
res = det.scan_directory(WORK, recursive=True)
flagged_names: list[str] = []
for r in res:
    if r.is_corrupted:
        flagged_names.append(Path(r.file_path).name)
        print(f"  flagged: {Path(r.file_path).name} ({r.status.name})")
        ok = det.quarantine_file(r.file_path)
        print(f"  quarantine_file() -> {ok}; original still present? {Path(r.file_path).exists()}")
print("  quarantine dir contents:", [p.name for p in (WORK / 'quarantine').glob('*')])
if any(name.endswith(".pptx") for name in flagged_names):
    print("  NOTE: a valid PowerPoint file was flagged (false positive - still reproduced).")
else:
    print("  -> OK: the valid .pptx was not flagged (fixed).")

print()
print("=" * 74)
print("D. UNREADABLE FILE HANDLING")
print("=" * 74)
bad = WORK / "noperm.bin"
bad.write_bytes(b"\x00\x01\x02")
bad.chmod(0o000)
res = det.scan_directory(WORK, recursive=True)
for r in res:
    if Path(r.file_path).name == "noperm.bin":
        print(f"  {r.status.name} is_corrupted={r.is_corrupted} : {r.error_message}")
bad.chmod(0o644)
if r.is_corrupted:
    print("  -> unreadable files count as corruption (will trip --fail-on-findings)")
else:
    print("  -> unreadable files are a FAULT, not corruption; the CLI reports the scan")
    print("     as incomplete (exit code 3) instead of silently exiting 0.")
