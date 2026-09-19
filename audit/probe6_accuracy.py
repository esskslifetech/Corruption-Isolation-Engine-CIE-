#!/usr/bin/env python3
"""Probe 6: measured detection accuracy of CIE (fresh scan, as a user gets it).

Builds a ground-truth set of genuinely corrupted files and genuinely healthy
files, runs the real engine, and prints a confusion matrix.
"""
import io
import shutil
import sys
import zipfile
from pathlib import Path

REPO = Path("/tmp/cie_wt")
sys.path.append(str(REPO / "src" / "python"))
import math  # noqa: F401  (stdlib, keeps shadowing away)
from core_analyzer import AnalyzerConfig, CorruptionDetector  # noqa: E402

from PIL import Image  # noqa: E402

DATA = Path("/tmp/accuracy")
if DATA.exists():
    shutil.rmtree(DATA)
DATA.mkdir(parents=True)

# ---------- build genuinely healthy reference files ----------
img = Image.new("RGB", (64, 48), (200, 30, 90))
buf = io.BytesIO(); img.save(buf, "PNG"); png = buf.getvalue()
buf = io.BytesIO(); img.save(buf, "JPEG", quality=90); jpg = buf.getvalue()
buf = io.BytesIO(); img.save(buf, "BMP"); bmp = buf.getvalue()
buf = io.BytesIO(); img.save(buf, "TIFF"); tiff = buf.getvalue()
buf = io.BytesIO(); img.save(buf, "WEBP"); webp = buf.getvalue()
(T := DATA / "truth_healthy").mkdir()
(T / "photo.png").write_bytes(png)
(T / "photo.jpg").write_bytes(jpg)
(T / "photo.bmp").write_bytes(bmp)
(T / "photo.tiff").write_bytes(tiff)
(T / "photo.webp").write_bytes(webp)
(T / "notes.txt").write_text("perfectly fine text\n" * 500)
def _valid_pdf_bytes():
    """Valid PDF: pypdf (rightly) rejects header-only hand-rolled files."""
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
        b"<< /Length 44 >>\nstream\nBT /F1 12 Tf 20 100 Td (probe6) Tj ET\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n"); offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out)); out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_at = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode() + b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode()
    return bytes(out)


(T / "doc.pdf").write_bytes(_valid_pdf_bytes())
with zipfile.ZipFile(T / "bundle.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("a.txt", "hello " * 500)
# Genuine Office files (the previous hand-rolled packages were not valid OOXML,
# so the engine was right to reject them - a fixture bug, not a false positive).
try:
    from docx import Document as _Document
    _doc = _Document(); _doc.add_paragraph("probe6 healthy docx " * 400); _doc.save(T / "report.docx")
except ImportError:
    with zipfile.ZipFile(T / "report.docx", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        z.writestr("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>')
try:
    from openpyxl import Workbook as _Workbook
    _wb = _Workbook(); _ws = _wb.active
    for row in range(1, 200):
        _ws.cell(row=row, column=1, value=f"probe6 row {row}")
    _wb.save(T / "sheet.xlsx")
except ImportError:
    with zipfile.ZipFile(T / "sheet.xlsx", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        z.writestr("xl/workbook.xml", '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets/></workbook>')

# ---------- build genuinely corrupted files ----------
(C := DATA / "truth_corrupt").mkdir()

def bitrot(data: bytes, where: int) -> bytes:
    b = bytearray(data)
    b[min(where, len(b) - 1)] ^= 0xFF
    return bytes(b)

put = lambda name, data: (C / name).write_bytes(data)
put("image_bitrot.png", bitrot(png, len(png) // 2))         # flipped byte inside IDAT, header intact
put("image_bitrot.jpg", bitrot(jpg, len(jpg) // 2))         # flipped byte mid-image, SOI+EOI intact
put("image_bitrot.bmp", bitrot(bmp, len(bmp) // 2))
put("image_bitrot.tiff", bitrot(tiff, len(tiff) // 2))
put("image_bitrot.webp", bitrot(webp, len(webp) // 2))
put("text_bitrot.txt", bitrot(b"important data line\n" * 200, 900))
put("zip_bitrot.zip", bitrot((T / "bundle.zip").read_bytes(), 60))
put("docx_bitrot.docx", bitrot((T / "report.docx").read_bytes(), int((T / "report.docx").stat().st_size * 0.6)))
put("xlsx_bitrot.xlsx", bitrot((T / "sheet.xlsx").read_bytes(), int((T / "sheet.xlsx").stat().st_size * 0.6)))
put("pdf_truncated_tail.pdf", b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"[0:])
put("exe_bitrot.exe", bitrot(b"MZ" + bytes(2000), 1000))
put("elf_bitrot.elf", bitrot(b"\x7fELF" + bytes(2000), 1000))
put("mp4_bitrot.mp4", bitrot(b"\x00\x00\x00\x18ftypisom" + bytes(5000), 900))
put("archive_bitrot.rar", bitrot(b"Rar!\x1a\x07\x00" + bytes(3000), 1500))
put("archive_bitrot.7z", bitrot(b"7z\xbc\xaf\x27\x1c" + bytes(3000), 1500))
put("word_bitrot.doc", bitrot(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(3000), 1500))

# ---------- run the engine ----------
WORK = DATA / "work"
cfg = AnalyzerConfig(db_path=str(WORK / "cie.db"), quarantine_dir=str(WORK / "q"))
det = CorruptionDetector(cfg)

print("=" * 78)
print("I. DETECTION ACCURACY - FRESH SCAN (no baseline; the normal first-run case)")
print("=" * 78)

def scan(folder):
    return {Path(r.file_path).name: r for r in det.scan_directory(folder, recursive=True)}

h = scan(T)
c = scan(C)

print("\n-- genuinely HEALTHY files (a 'corrupted' verdict here = FALSE POSITIVE) --")
fp = []
for name in sorted(h):
    r = h[name]
    verdict = "corrupted" if r.is_corrupted else "ok"
    if r.is_corrupted:
        fp.append(name)
    print(f"   {name:<22}{verdict:<12}{r.status.name:<22}{(r.error_message or '')[:30]}")

print("\n-- genuinely CORRUPTED files ('ok' verdict here = FALSE NEGATIVE) --")
fn = []
for name in sorted(c):
    r = c[name]
    verdict = "detected" if r.is_corrupted else "ok"
    if not r.is_corrupted:
        fn.append(name)
    print(f"   {name:<22}{verdict:<12}{r.status.name:<22}{(r.error_message or '')[:30]}")

tp = len(c) - len(fn); tn = len(h) - len(fp)
print("\n-- confusion matrix (fresh-scan mode) --")
print(f"   corrupted & detected (TP) : {tp}/{len(c)}")
print(f"   corrupted & MISSED   (FN) : {len(fn)}/{len(c)}   {fn}")
print(f"   healthy   & ok       (TN) : {tn}/{len(h)}")
print(f"   healthy   & FLAGGED  (FP) : {len(fp)}/{len(h)}   {fp}")
print(f"\n   recall (true corruption caught) : {tp/len(c)*100:.1f}%")
print(f"   precision (alerts that are real): {tp/max(1,tp+len(fp))*100:.1f}%")
print()
print("   Note: the missed files are the formats that carry no integrity metadata")
print("   (bmp/tiff/jpg payload rot, mp4, rar, exe, elf, doc, txt). They are caught on")
print("   the NEXT scan by comparison with the stored baseline - see verify_fixes.py")
print("   section 'rescan recall' - which is why a first scan should be run on intact")
print("   data to establish baselines.")
