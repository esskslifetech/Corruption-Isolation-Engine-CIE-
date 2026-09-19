#!/usr/bin/env python3
"""Probe 3: does CIE treat its own SQLite database as a corrupted file?"""
import shutil
import sys
from pathlib import Path

ROOT = Path("/tmp/cie_wt")
sys.path.append(str(ROOT / "src" / "python"))
from core_analyzer import AnalyzerConfig, CorruptionDetector  # noqa: E402

WORK = Path("/tmp/cie_self")
if WORK.exists():
    shutil.rmtree(WORK)
WORK.mkdir(parents=True)

# realistic user layout: data files AND the tool's database in the same folder
(WORK / "report.txt").write_text("quarterly numbers\n")
(WORK / "photo.jpg").write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9")

cfg = AnalyzerConfig(db_path=str(WORK / "cie_database.db"), quarantine_dir=str(WORK / "quarantine"))
det = CorruptionDetector(cfg)

print("=" * 74)
print("C2. SCANNING A FOLDER THAT ALSO CONTAINS THE TOOL'S OWN DATABASE")
print("=" * 74)
own_data_scanned: list[str] = []
for i in (1, 2, 3):
    res = det.scan_directory(WORK, recursive=True)
    print(f"\n-- scan {i}: files in {WORK.name} --")
    for r in sorted(res, key=lambda x: Path(x.file_path).name):
        name = Path(r.file_path).name
        is_own = name.startswith("cie_database")
        if is_own:
            own_data_scanned.append(name)
        mark = "  <== TOOL'S OWN DATA" if is_own else ""
        print(f"   {name:<20}{r.status.name:<20}is_corrupted={str(r.is_corrupted):<6}{mark}")

if own_data_scanned:
    print("\n-> FAIL: the tool's own WAL/SHM/DB files are being analysed as user data:")
    print("  ", sorted(set(own_data_scanned)))
else:
    print("\n-> OK: the tool's own database/WAL/SHM are excluded from the scan.")

print()
print("=" * 74)
print("C3. AUTO-QUARANTINE + OWN DATABASE = SELF-DESTRUCTION")
print("=" * 74)
res = det.scan_directory(WORK, recursive=True)
victims = [r for r in res if "cie_database" in Path(r.file_path).name]
flagged_own = [Path(v.file_path).name for v in victims]
print("  flagged tool-owned files:", flagged_own)
print("  -> self-destruction:", "STILL REPRODUCED" if flagged_own else "not reproduced (fixed)")
for v in victims:
    try:
        ok = det.quarantine_file(v.file_path)
        print(f"  quarantine_file({Path(v.file_path).name}) -> {ok}")
    except Exception as exc:
        print(f"  quarantine_file({Path(v.file_path).name}) RAISED {type(exc).__name__}: {exc}")
        print("  ^^ the engine just moved its own live SQLite database out from under itself")
        break

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
