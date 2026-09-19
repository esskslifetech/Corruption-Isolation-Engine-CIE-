#!/usr/bin/env python3
"""Build a realistic corpus of valid / corrupt / high-entropy files for fact-checking CIE."""
import os
import zipfile
from pathlib import Path

c = Path("/tmp/corpus")
if c.exists():
    import shutil
    shutil.rmtree(c)
c.mkdir(parents=True)

png_hex = "89504e470d0a1a0a0000000d4948445200000001000000010806000000" \
          "1f15c4890000000a49444154789c63000100000500010d0a2db4" \
          "0000000049454e44ae426082"
(c / "valid.png").write_bytes(bytes.fromhex(png_hex))
# A real (if tiny) JPEG: the previous 22-byte hand-rolled version was not a
# decodable image at all, so "valid.jpg" being flagged was the corpus's fault.
try:
    from PIL import Image as _Image

    _img = _Image.new("RGB", (8, 8), (200, 30, 30))
    _img.save(c / "valid.jpg", "JPEG", quality=90)
except ImportError:  # pragma: no cover
    (c / "valid.jpg").write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9")
def _pdf_bytes():
    """Minimal but genuinely valid PDF (objects + xref + startxref)."""
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
        b"<< /Length 44 >>\nstream\nBT /F1 12 Tf 20 100 Td (CIE corpus) Tj ET\nendstream",
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


(c / "valid.pdf").write_bytes(_pdf_bytes())
(c / "valid.txt").write_text("hello world\n")
(c / "empty.txt").write_bytes(b"")

# --- deliberately corrupt files ---
(c / "truncated.jpg").write_bytes(b"\xff\xd8\xff\xe0" + b"junk junk junk")
(c / "corrupt.pdf").write_bytes(b"%PDF-1.4\nstuff but no eof marker")
(c / "fake.png").write_bytes(b"this is not a png at all")

# --- genuine ZIP / OOXML containers (high entropy, perfectly healthy) ---
def _real_docx(target):
    from docx import Document

    doc = Document()
    doc.add_paragraph("Quarterly report — genuine DOCX written by python-docx.")
    doc.add_paragraph("x" * 40000)
    doc.save(target)


def _real_xlsx(target):
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws["A1"] = "id"
    ws["B1"] = "name"
    for row in range(2, 400):
        ws.cell(row=row, column=1, value=row)
        ws.cell(row=row, column=2, value=f"row-{row}-{'y' * 40}")
    wb.save(target)


def _real_pptx(target):
    """python-pptx is optional: fall back to a spec-shaped minimal package."""
    try:
        from pptx import Presentation

        prs = Presentation()
        slide = prs.slides.add_slide(prs.slide_layouts[5])
        slide.shapes.title.text = "Genuine PPTX"
        prs.save(target)
        return
    except ImportError:
        pass
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
            "</Types>",
        )
        z.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>'
            "</Relationships>",
        )
        z.writestr(
            "ppt/presentation.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
            "<p:sldIdLst/></p:presentation>",
        )


for ext, builder in (("docx", _real_docx), ("xlsx", _real_xlsx), ("pptx", _real_pptx)):
    try:
        builder(c / f"real.{ext}")
    except ImportError as exc:  # pragma: no cover
        print(f"skipping real.{ext}: {exc}")

with zipfile.ZipFile(c / "real.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("data.bin", os.urandom(60000))

with zipfile.ZipFile(c / "real.jar", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    z.writestr("a.class", os.urandom(60000))

# --- corruption of genuine files: same format, damaged payload ---
def _damage_same_size(src, dst, offset_from_end=64):
    data = bytearray(src.read_bytes())
    pos = max(0, len(data) - offset_from_end)
    for i in range(pos, min(pos + 32, len(data))):
        data[i] ^= 0xFF
    dst.write_bytes(bytes(data))


for name in ("real.docx", "real.xlsx", "real.pptx"):
    if (c / name).exists():
        _damage_same_size(c / name, c / f"damaged_{name}")

if (c / "valid.jpg").exists():
    data = bytearray((c / "valid.jpg").read_bytes())
    if len(data) > 300:
        data[len(data) - 40: len(data) - 8] = b"\x00" * 32   # wipe scan data
        (c / "damaged_valid.jpg").write_bytes(bytes(data))

# --- other real-world high-entropy types ---
(c / "archive.tar.gz").write_bytes(b"\x1f\x8b\x08\x00" + os.urandom(60000))
(c / "clip.mkv").write_bytes(b"\x1a\x45\xdf\xa3" + os.urandom(60000))
(c / "song.opus").write_bytes(b"OggS" + os.urandom(60000))
(c / "encrypted.bin").write_bytes(os.urandom(8192))
(c / "note.locked").write_bytes(os.urandom(8192))

print("corpus built:", len(list(c.iterdir())), "files in", c)
