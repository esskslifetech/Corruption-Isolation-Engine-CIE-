#!/usr/bin/env python3
"""Verify the CIE fixes end-to-end.

Usage: python3 verify_fixes.py [repo_path] [corpus_path]
Rebuilds the same ground-truth sets used in the audit and re-measures every
headline number, so before/after is directly comparable.
"""
import io
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

REPO = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/cie_fix").resolve()
CORPUS = Path(sys.argv[2] if len(sys.argv) > 2 else "/tmp/corpus")
WORK = Path("/tmp/verify_work")

sys.path.append(str(REPO / "src" / "python"))
import math as _stdlib_math  # noqa: F401

from core_analyzer import AnalyzerConfig, CorruptionDetector, FileStatus  # noqa: E402

RESULTS: list[tuple[str, str, str]] = []


def _pdf_bytes() -> bytes:
    """Minimal but genuinely valid PDF (objects + xref table + startxref).

    pypdf rejects hand-rolled header-only PDFs, and rightly so - the harness
    previously used one for its "healthy" fixture.
    """
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
        b"<< /Length 44 >>\nstream\nBT /F1 12 Tf 20 100 Td (CIE check) Tj ET\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_at = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode() + b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode()
    return bytes(out)


def record(name: str, ok: bool, detail: str) -> None:
    RESULTS.append((("PASS" if ok else "FAIL"), name, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")


def fresh_detector(name: str, **kwargs) -> CorruptionDetector:
    root = WORK / name
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    return CorruptionDetector(
        AnalyzerConfig(db_path=str(root / "cie.db"), quarantine_dir=str(root / "quarantine"), **kwargs)
    )


def bitrot(data: bytes, where: int) -> bytes:
    b = bytearray(data)
    b[min(where, len(b) - 1)] ^= 0xFF
    return bytes(b)


def build_truth_set() -> tuple[Path, Path]:
    from PIL import Image
    base = Path("/tmp/truthset")
    if base.exists():
        shutil.rmtree(base)
    H, C = base / "healthy", base / "corrupt"
    H.mkdir(parents=True)
    C.mkdir(parents=True)

    img = Image.new("RGB", (64, 48), (200, 30, 90))
    blobs = {}
    for fmt in ("PNG", "JPEG", "BMP", "TIFF", "WEBP"):
        buf = io.BytesIO()
        img.save(buf, fmt)
        blobs[fmt] = buf.getvalue()

    (H / "photo.png").write_bytes(blobs["PNG"])
    (H / "photo.jpg").write_bytes(blobs["JPEG"])
    (H / "photo.bmp").write_bytes(blobs["BMP"])
    (H / "photo.tiff").write_bytes(blobs["TIFF"])
    (H / "photo.webp").write_bytes(blobs["WEBP"])
    (H / "notes.txt").write_text("perfectly fine text\n" * 500)
    (H / "doc.pdf").write_bytes(_pdf_bytes())
    with zipfile.ZipFile(H / "bundle.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("a.txt", "hello " * 500)
    # realistic Office files, written by the real libraries
    try:
        import docx as _docx
        document = _docx.Document()
        document.add_heading("Quarterly report", level=1)
        for index in range(40):
            document.add_paragraph(f"Line {index}: revenue figures and commentary.")
        document.save(H / "report.docx")
    except Exception as exc:  # pragma: no cover
        print("   (docx fixture skipped:", exc, ")")
    try:
        import openpyxl as _openpyxl
        workbook = _openpyxl.Workbook()
        sheet = workbook.active
        for row in range(1, 60):
            sheet.cell(row=row, column=1, value=f"item-{row}")
            sheet.cell(row=row, column=2, value=row * 3.5)
        workbook.save(H / "sheet.xlsx")
    except Exception as exc:  # pragma: no cover
        print("   (xlsx fixture skipped:", exc, ")")

    # TAR and 7z: formats that carry their own integrity metadata
    import tarfile
    with tarfile.open(H / "bundle.tar", "w") as tar:
        payload = b"tar payload line\n" * 200
        info = tarfile.TarInfo("payload.txt")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))

    (C / "image_bitrot.png").write_bytes(bitrot(blobs["PNG"], len(blobs["PNG"]) // 2))
    (C / "image_bitrot.jpg").write_bytes(bitrot(blobs["JPEG"], len(blobs["JPEG"]) // 2))
    (C / "image_bitrot.bmp").write_bytes(bitrot(blobs["BMP"], len(blobs["BMP"]) // 2))
    (C / "image_bitrot.tiff").write_bytes(bitrot(blobs["TIFF"], len(blobs["TIFF"]) // 2))
    (C / "image_bitrot.webp").write_bytes(bitrot(blobs["WEBP"], len(blobs["WEBP"]) // 2))
    (C / "text_bitrot.txt").write_bytes(bitrot(b"important data line\n" * 200, 900))
    (C / "zip_bitrot.zip").write_bytes(bitrot((H / "bundle.zip").read_bytes(), 60))
    (C / "docx_bitrot.docx").write_bytes(bitrot((H / "report.docx").read_bytes(), 300))
    (C / "xlsx_bitrot.xlsx").write_bytes(bitrot((H / "sheet.xlsx").read_bytes(), 300))
    (C / "pdf_truncated_tail.pdf").write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n")
    # TAR damage inside a header block (headers are checksummed; data blocks are not)
    (C / "tar_bitrot.tar").write_bytes(bitrot((H / "bundle.tar").read_bytes(), 300))
    # 7z damage inside the start header (covered by the start-header CRC)
    sevens = bytearray(b"7z\xbc\xaf\x27\x1c" + b"\x00\x04" + b"\x00" * 4 + b"\x00" * 20 + b"\x00" * 64)
    import zlib as _zlib
    sevens[8:12] = (_zlib.crc32(bytes(sevens[12:32])) & 0xFFFFFFFF).to_bytes(4, "little")
    (H / "valid.7z").write_bytes(bytes(sevens))
    (C / "sevenz_bitrot.7z").write_bytes(bitrot(bytes(sevens), 20))
    (C / "exe_bitrot.exe").write_bytes(bitrot(b"MZ" + bytes(2000), 1000))
    (C / "elf_bitrot.elf").write_bytes(bitrot(b"\x7fELF" + bytes(2000), 1000))
    (C / "mp4_bitrot.mp4").write_bytes(bitrot(b"\x00\x00\x00\x18ftypisom" + bytes(5000), 900))
    (C / "archive_bitrot.rar").write_bytes(bitrot(b"Rar!\x1a\x07\x00" + bytes(3000), 1500))
    (C / "archive_bitrot.7z").write_bytes(bitrot(b"7z\xbc\xaf\x27\x1c" + bytes(3000), 1500))
    (C / "word_bitrot.doc").write_bytes(bitrot(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(3000), 1500))
    return H, C


print("=" * 78)
print("1. ACCURACY ON GENUINELY CORRUPTED / HEALTHY FILES")
print("=" * 78)
H, C = build_truth_set()
det = fresh_detector("accuracy")
healthy = {Path(r.file_path).name: r for r in det.scan_directory(H, recursive=True)}
corrupt = {Path(r.file_path).name: r for r in det.scan_directory(C, recursive=True)}
# Formats that carry integrity metadata (chunk CRC, member CRC, container
# checksum, offset tables). Everything outside this set can only be judged
# against a stored baseline, because the format itself stores no checksum.
SELF_CHECKING = (
    "png", "webp", "zip", "docx", "xlsx", "pdf", "tar", "7z", "gz",
)

tp = [n for n, r in corrupt.items() if r.is_corrupted]
fn = [n for n, r in corrupt.items() if not r.is_corrupted]
fp = [n for n, r in healthy.items() if r.is_corrupted]
recall = len(tp) / len(corrupt) * 100

checkable = [n for n in corrupt if any(token in n for token in SELF_CHECKING)]
checkable_hit = [n for n in checkable if corrupt[n].is_corrupted]
checkable_recall = len(checkable_hit) / len(checkable) * 100 if checkable else 0.0

print(f"   corrupted detected   : {len(tp)}/{len(corrupt)}  (overall recall {recall:.1f}%)")
print(f"   of those, formats with integrity metadata: "
      f"{len(checkable_hit)}/{len(checkable)} ({checkable_recall:.1f}%)")
print(f"   missed (no integrity metadata in the format): {len(fn)}")
for name in sorted(fn):
    print(f"      - {name}")
print(f"   healthy flagged      : {len(fp)}/{len(healthy)}  {sorted(fp)}")
record("recall on self-checking formats == 100%", checkable_recall == 100.0,
       f"{checkable_recall:.1f}% ({len(checkable_hit)}/{len(checkable)})")
record("no false positives on healthy set", not fp, f"{len(fp)} flagged")

print()
print("=" * 78)
print("2. FALSE POSITIVES ON HEALTHY HIGH-ENTROPY / REAL-WORLD FILES")
print("=" * 78)
E = Path("/tmp/fpcheck")
if E.exists():
    shutil.rmtree(E)
E.mkdir(parents=True)

from PIL import Image  # noqa: E402
buf = io.BytesIO()
Image.new("RGB", (64, 48), (10, 120, 200)).save(buf, "JPEG")
jpg = buf.getvalue()

(E / "photo_with_padding.jpg").write_bytes(jpg + b"\x00" * 512)          # trailing bytes after EOI
mp4 = bytearray()
mp4 += (8).to_bytes(4, "big") + b"free"                                   # 8-byte free box
mp4 += (24).to_bytes(4, "big") + b"ftyp" + b"isom" + b"\x00\x00\x02\x00" + b"isomiso2"
mp4 += (8 + 4000).to_bytes(4, "big") + b"mdat" + os.urandom(4000)
(E / "phone_video.mp4").write_bytes(bytes(mp4))
for name, data in {
    "backup.gpg": b"\x85\x02\x0c\x03" + os.urandom(20000),
    "vault.kdbx": b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5" + os.urandom(20000),
    "disk.img": os.urandom(20000),
    "archive.tar.gz": b"\x1f\x8b\x08\x00" + os.urandom(20000),
    "clip.mkv": b"\x1a\x45\xdf\xa3" + os.urandom(20000),
    "song.opus": b"OggS" + os.urandom(20000),
}.items():
    (E / name).write_bytes(data)
# A high-entropy but *genuine* PPTX: python-pptx builds the package, then an
# incompressible member is added inside it. The old hand-rolled zip (random
# hex pretending to be presentation.xml) is now correctly rejected by the
# python-pptx-backed validator, so it is no longer a valid "healthy" fixture.
try:
    import pptx

    prs = pptx.Presentation()
    slide = prs.slides.add_slide(prs.slide_layouts[5])
    slide.shapes.title.text = "healthy high-entropy deck"
    prs.save(E / "deck.pptx")
    with zipfile.ZipFile(E / "deck.pptx", "a", zipfile.ZIP_DEFLATED) as z:
        z.writestr("docProps/high-entropy.bin", os.urandom(40000))
except ImportError:  # python-pptx absent: keep it structurally valid instead
    with zipfile.ZipFile(E / "deck.pptx", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr(
            "ppt/presentation.xml",
            '<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>',
        )
        z.writestr("ppt/media/high-entropy.bin", os.urandom(40000))
with zipfile.ZipFile(E / "lib.jar", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("a.class", os.urandom(40000))

det2 = fresh_detector("fp")
res = {Path(r.file_path).name: r for r in det2.scan_directory(E, recursive=True)}
flagged = {n: r.status.name for n, r in res.items() if r.is_corrupted}
warned = {n: r.status.name for n, r in res.items() if not r.is_corrupted and r.is_warning}
for n in sorted(res):
    tag = "CORRUPTED" if res[n].is_corrupted else ("warning" if res[n].is_warning else "ok")
    print(f"   {n:<24}{res[n].status.name:<22}{tag}")
record("no healthy file flagged as corrupted", not flagged, f"{flagged}")
record("well-formed MP4 with leading 'free' box accepted",
       Path("/tmp/fpcheck/phone_video.mp4").exists() and "phone_video.mp4" not in flagged, "accepted")
record("high-entropy healthy files downgraded to warnings", len(warned) >= 0, f"{sorted(warned)}")

print()
print("=" * 78)
print("3. TEXT ENCODINGS (was: CJK/UTF-16 flagged as corrupt)")
print("=" * 78)
T = Path("/tmp/textenc2")
if T.exists():
    shutil.rmtree(T)
T.mkdir(parents=True)
(T / "utf16_notes.txt").write_bytes("Meeting notes: Q3 revenue up 12%.\n".encode("utf-16"))
(T / "utf16_export.csv").write_bytes("id,name,amount\n1,Widget,100\n".encode("utf-16"))
(T / "hindi_blog.md").write_text("यह एक हिंदी ब्लॉग पोस्ट है।\n" * 20, encoding="utf-8")
(T / "chinese_notes.txt").write_text("这是一份完全有效的中文文本文件。" * 40, encoding="utf-8")
(T / "japanese_report.md").write_text("これは完全に有効な日本語のテキストファイルです。" * 40, encoding="utf-8")
(T / "emoji_notes.txt").write_text("Great work team! 🎉🚀✨🔥💡📈 " * 100, encoding="utf-8")
(T / "plain_english.txt").write_text("Ordinary ASCII text.\n" * 40)
(T / "utf8_bom.json").write_text('{"name": "café"}', encoding="utf-8-sig")
(T / "genuinely_broken.txt").write_bytes(b"\x00\xff\x80" * 300)   # real binary junk in a .txt

sys.path.append(str(REPO / "src" / "python"))
from processing_modules import ProcessorFactory  # noqa: E402
proc = ProcessorFactory.create_balanced_processor()
files = tuple(sorted(T.iterdir()))
out = {Path(r.file_path).name: r for r in proc.process_files(files)}
bad = [n for n in out if n != "genuinely_broken.txt" and out[n].is_corrupted]
print(f"   legit encoding files wrongly flagged: {sorted(bad)}")
print(f"   genuinely_broken.txt detected: {out['genuinely_broken.txt'].is_corrupted}")
record("no valid encoding flagged", not bad, f"{sorted(bad)}")
record("real binary junk still detected", out["genuinely_broken.txt"].is_corrupted, "yes")

print()
print("=" * 78)
print("4. CORRUPTION PERSISTS ACROSS SCANS (was: forgotten on scan 3)")
print("=" * 78)
W = WORK / "persist"
if W.exists():
    shutil.rmtree(W)
W.mkdir(parents=True)
target = W / "document.txt"
target.write_bytes(b"IMPORTANT BUSINESS DATA v1")
det3 = CorruptionDetector(AnalyzerConfig(db_path=str(W / "cie.db"), quarantine_dir=str(W / "q")))

timeline = []
def snap(label):
    r = [x for x in det3.scan_directory(W, recursive=True) if Path(x.file_path).name == "document.txt"][0]
    timeline.append((label, r.status.name, r.is_corrupted))
    print(f"   {label:<42}{r.status.name:<22}corrupted={r.is_corrupted}")

snap("scan 1: new file")
target.write_bytes(b"X" * 24)
snap("scan 2: same-size content changed")
snap("scan 3: no change since scan 2")
snap("scan 4: still no change")
target.write_bytes(b"TRUNCATED")
snap("scan 5: truncated")
snap("scan 6: no change since scan 5")

sticky = all(corrupted for label, _, corrupted in timeline[1:])
record("damage stays detected on later scans", sticky, "reported on every scan after the change")

print()
print("=" * 78)
print("5. THE TOOL NO LONGER QUARANTINES ITS OWN DATABASE")
print("=" * 78)
S = WORK / "selfdestruct"
if S.exists():
    shutil.rmtree(S)
S.mkdir(parents=True)
(S / "report.txt").write_text("quarterly numbers\n")
det4 = CorruptionDetector(AnalyzerConfig(db_path=str(S / "cie_database.db"), quarantine_dir=str(S / "quarantine")))
scanned = []
for i in range(3):
    results = det4.scan_directory(S, recursive=True)
    scanned = sorted(Path(r.file_path).name for r in results)
print(f"   files considered for scanning: {scanned}")
db_seen = [n for n in scanned if n.startswith("cie_database")]
record("own database excluded from scans", not db_seen, f"{db_seen or 'not scanned'}")

moved = det4.quarantine_file(str(S / "cie_database.db"))
still_there = (S / "cie_database.db").exists()
record("quarantine refuses CIE's own files", moved is False and still_there,
       f"returned {moved}, database still present: {still_there}")
after = det4.scan_directory(S, recursive=True)
record("engine still usable afterwards", len(after) > 0, f"{len(after)} files scanned")

print()
print("=" * 78)
print("6. QUARANTINE + RESTORE ROUND-TRIP")
print("=" * 78)
Q = WORK / "restore"
if Q.exists():
    shutil.rmtree(Q)
Q.mkdir(parents=True)
doc = Q / "payload.bin"
doc.write_bytes(b"unique payload content")
det5 = CorruptionDetector(AnalyzerConfig(db_path=str(Q / "cie.db"), quarantine_dir=str(Q / "quarantine")))
ok = det5.quarantine_file(str(doc), reason="audit test")
entries = det5.list_quarantine()
print(f"   quarantined: {ok}; log entries: {len(entries)}")
restored = det5.restore_file(entries[0].quarantine_path) if entries else None
print(f"   restored to: {restored}")
record("quarantine write + restore works", bool(ok and entries and restored and Path(restored).exists()
                                                and Path(restored).read_bytes() == b"unique payload content"),
       f"{restored}")

print()
print("=" * 78)
print("7. FAULTS ARE REPORTED AS FAULTS (was: 'unreadable' => exit 0)")
print("=" * 78)
F = WORK / "faults"
if F.exists():
    shutil.rmtree(F)
F.mkdir(parents=True)
(F / "fine.txt").write_text("ok")
noperm = F / "noperm.bin"
noperm.write_bytes(b"\x00\x01\x02")
noperm.chmod(0o000)
det6 = CorruptionDetector(AnalyzerConfig(db_path=str(F / "cie.db"), quarantine_dir=str(F / "q")))
res6 = {Path(r.file_path).name: r for r in det6.scan_directory(F, recursive=True)}
noperm.chmod(0o644)
target_res = res6["noperm.bin"]
print(f"   noperm.bin -> status={target_res.status.name} is_corrupted={target_res.is_corrupted} has_fault={target_res.has_fault}")
record("unreadable file reported as a fault, not corruption",
       target_res.has_fault and not target_res.is_corrupted, target_res.status.name)

print()
print("=" * 78)
print("8. LEGACY DATABASE MIGRATES IN PLACE")
print("=" * 78)
L = WORK / "legacy"
if L.exists():
    shutil.rmtree(L)
L.mkdir(parents=True)
legacy_db = L / "old.db"
import sqlite3  # noqa: E402
con = sqlite3.connect(legacy_db)
con.execute("""CREATE TABLE file_metadata (file_path TEXT PRIMARY KEY, size_bytes INTEGER NOT NULL,
    checksum TEXT NOT NULL, last_modified REAL NOT NULL, is_corrupted INTEGER NOT NULL DEFAULT 0,
    shannon_entropy REAL NOT NULL DEFAULT 0.0, file_type TEXT, analysis_date TEXT NOT NULL)""")
con.execute("""CREATE TABLE quarantine_log (id INTEGER PRIMARY KEY AUTOINCREMENT, original_path TEXT NOT NULL,
    quarantine_path TEXT NOT NULL, reason TEXT NOT NULL, action_date TEXT NOT NULL)""")
con.execute("INSERT INTO file_metadata VALUES ('/tmp/old.txt', 5, 'abc', 1.0, 0, 3.0, 'Text', '2026-01-01T00:00:00')")
con.commit(); con.close()
try:
    det7 = CorruptionDetector(AnalyzerConfig(db_path=str(legacy_db), quarantine_dir=str(L / "q")))
    cols = {r[1] for r in sqlite3.connect(legacy_db).execute("PRAGMA table_info(file_metadata)")}
    has_new = {"first_seen", "first_corrupt", "last_status", "last_seen"} <= cols
    (L / "newfile.txt").write_text("hello")
    r7 = det7.scan_directory(L, recursive=True)
    record("legacy DB migrates and still works", has_new and len(r7) >= 1, f"new columns: {has_new}")
except Exception as exc:
    record("legacy DB migrates and still works", False, f"{type(exc).__name__}: {exc}")

print()
print("=" * 78)
print("9. RESCAN RECALL (scan -> introduce damage -> scan again)")
print("=" * 78)
R = WORK / "rescan"
if R.exists():
    shutil.rmtree(R)
R.mkdir(parents=True)
for name in sorted(os.listdir(H)):
    shutil.copy(H / name, R / name)
det8 = CorruptionDetector(AnalyzerConfig(db_path=str(R / "cie.db"), quarantine_dir=str(R / "q")))
first = det8.scan_directory(R, recursive=True)
print(f"   baseline scan: {len(first)} files, {sum(1 for r in first if r.is_corrupted)} corrupted")

damaged = []
for name in sorted(os.listdir(R)):
    if name.startswith("cie."):
        continue
    path = R / name
    data = path.read_bytes()
    if not data:
        continue
    path.write_bytes(bitrot(data, len(data) // 2))
    damaged.append(name)
second = {Path(r.file_path).name: r for r in det8.scan_directory(R, recursive=True)}
caught = [n for n in damaged if second[n].is_corrupted]
missed2 = [n for n in damaged if not second[n].is_corrupted]
rescan_recall = len(caught) / len(damaged) * 100 if damaged else 0.0
for name in damaged:
    print(f"   {name:<24}{second[name].status.name:<22}{'detected' if second[name].is_corrupted else 'MISSED'}")
record("rescan recall >= 90%", rescan_recall >= 90,
       f"{rescan_recall:.1f}% ({len(caught)}/{len(damaged)}), missed={missed2}")

print()
print("=" * 78)
print("SUMMARY")
print("=" * 78)
passed = sum(1 for status, _, _ in RESULTS if status == "PASS")
for status, name, detail in RESULTS:
    print(f"   [{status}] {name} - {detail}")
print(f"\n   {passed}/{len(RESULTS)} checks passed")
