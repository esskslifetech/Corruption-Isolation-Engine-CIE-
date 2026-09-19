#!/usr/bin/env python3
"""Probe 5: modular scanner strategies (via sys.path.append so stdlib math is safe)."""
import shutil
import sys
from pathlib import Path

REPO = Path("/tmp/cie_wt")
sys.path.append(str(REPO / "src" / "python"))

from modular_scanner import ModularScanner, run_strategy_comparison  # noqa: E402

# --- realistic text-encoding corpus ---
T = Path("/tmp/textenc")
if T.exists():
    shutil.rmtree(T)
T.mkdir(parents=True)
(T / "utf16_notes.txt").write_bytes("Meeting notes: Q3 revenue up 12%.\n".encode("utf-16"))       # legitimate UTF-16
(T / "utf16_export.csv").write_bytes("id,name,amount\n1,Widget,100\n".encode("utf-16"))           # Excel CSV export
(T / "hindi_blog.md").write_text("यह एक हिंदी ब्लॉग पोस्ट है। यह पूरी तरह से मान्य यूनिकोड टेक्स्ट है।\n" * 20, encoding="utf-8")
(T / "chinese_notes.txt").write_text("这是一份完全有效的中文文本文件，用于测试。" * 40, encoding="utf-8")
(T / "japanese_report.md").write_text("これは完全に有効な日本語のテキストファイルです。" * 40, encoding="utf-8")
(T / "emoji_notes.txt").write_text("Great work team! 🎉🚀✨🔥💡📈 " * 100, encoding="utf-8")
(T / "plain_english.txt").write_text("Ordinary ASCII text, nothing wrong here.\n" * 40)
(T / "utf8_bom.json").write_text('{"name": "café", "city": "Zürich"}', encoding="utf-8-sig")

from processing_modules import ProcessorFactory, TextEncodingProcessor  # noqa: E402

print("=" * 74)
print("G. ARE VALID UTF-16 / NON-ENGLISH TEXT FILES FLAGGED AS CORRUPT?")
print("=" * 74)
print(f"{'file':<22}{'fast':<10}{'balanced':<11}{'deep':<9}balanced verdict")
procs = {name: getattr(ProcessorFactory, f"create_{name}_processor")() for name in ("fast", "balanced", "deep")}
import concurrent.futures as cf
checks = {}
for name, p in procs.items():
    checks[name] = {str(r.file_path): r for r in p.process_files(tuple(sorted(T.iterdir())))}
for f in sorted(T.iterdir()):
    key = str(f)
    flags = {n: checks[n][key].is_corrupted for n in procs}
    msg = (checks["balanced"][key].error_message or "")[:60]
    print(f"{f.name:<22}{str(flags['fast']):<10}{str(flags['balanced']):<11}{str(flags['deep']):<9}{msg}")

_encoding_false_positives = [f.name for f in sorted(T.iterdir())
                             if checks["balanced"][str(f)].is_corrupted]
if _encoding_false_positives:
    print("\n-> FAIL: these valid non-Latin / UTF-16 text files are flagged as corrupted:")
    print("  ", _encoding_false_positives)
else:
    print("\n-> OK: no valid encoding is flagged (the old 'non-ASCII byte ratio >= 0.70'")
    print("   rule is gone; text is judged by decodability).")

print()
print("=" * 74)
print("H. STRATEGY COMPARISON ON THE REAL-FILE CORPUS (agreement between strategies?)")
print("=" * 74)
outcomes = run_strategy_comparison(Path("/tmp/corpus"), strategies=("fast", "balanced", "deep"),
                                   recursive=True, include_hidden=True, follow_symlinks=False)
corr = {}
for o in outcomes:
    corr[o.strategy] = {Path(r.file_path).name: r.is_corrupted for r in o.results}
names = sorted(corr["fast"])
print(f"{'file':<20}{'fast':<8}{'balanced':<10}{'deep':<8}agrees?")
for n in names:
    v = [corr[s][n] for s in ("fast", "balanced", "deep")]
    ok = "yes" if len(set(v)) == 1 else "**NO**"
    print(f"{n:<20}{str(v[0]):<8}{str(v[1]):<10}{str(v[2]):<8}{ok}")
disagreements = [n for n in names if len({corr[s][n] for s in ("fast", "balanced", "deep")}) > 1]
if disagreements:
    print("\n  -> FAIL: strategies disagree on:", disagreements)
else:
    print("\n  -> OK: fast/balanced/deep agree on every file in the corpus.")
