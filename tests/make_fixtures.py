#!/usr/bin/env python3
"""Generate the committed fixture set used by CI.

``tests/fixtures/`` is what CI scans:

    python3 cie.py --scan tests/fixtures --fail-on-findings

Every file in there must be *genuinely valid*, so that the command exits 0 on
a clean checkout and any regression that makes the scanner flag a healthy file
turns the build red. That is exactly the class of bug the audit found (garbage
files reported healthy, healthy files reported corrupt), so the fixtures are
real documents built by the real libraries rather than hand-rolled bytes.

Run from the repository root:

    python3 tests/make_fixtures.py
"""

from __future__ import annotations

import io
import struct
import sys
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"


def _require(module_name: str, package: str):
    import importlib

    try:
        return importlib.import_module(module_name)
    except ImportError:  # pragma: no cover - depends on the environment
        print(
            f"error: {package} is required to generate the fixtures "
            f"(python3 -m pip install -r requirements.txt)",
            file=sys.stderr,
        )
        raise SystemExit(2)


def _png_bytes() -> bytes:
    """A real PNG, written by Pillow when available, else by hand."""
    try:
        from PIL import Image

        buffer = io.BytesIO()
        Image.new("RGB", (32, 24), (30, 90, 160)).save(buffer, format="PNG")
        return buffer.getvalue()
    except ImportError:
        return _png_by_hand(32, 24)


def _png_by_hand(width: int, height: int) -> bytes:
    """Minimal but *correct* PNG: signature, IHDR, IDAT (zlib), IEND."""
    raw = b"".join(b"\x00" + bytes([30, 90, 160] * width) for _ in range(height))

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def _write_text(path: Path) -> None:
    path.write_text(
        "Corruption Isolation Engine - CI fixture\n"
        "=======================================\n\n"
        "This file is intentionally boring: plain, valid, low-entropy text.\n"
        "CI scans this directory with --fail-on-findings, so nothing here may\n"
        "ever be reported as damaged.\n",
        encoding="utf-8",
    )


def _write_png(path: Path) -> None:
    path.write_bytes(_png_bytes())


def _write_jpeg(path: Path) -> None:
    Image = _require("PIL.Image", "Pillow")
    Image.new("RGB", (64, 48), (200, 120, 40)).save(path, format="JPEG", quality=85)


def _write_pdf(path: Path) -> None:
    pypdf = _require("pypdf", "pypdf")
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=200, height=200)
    with path.open("wb") as handle:
        writer.write(handle)


def _write_docx(path: Path) -> None:
    docx = _require("docx", "python-docx")
    document = docx.Document()
    document.add_heading("CI fixture", level=1)
    document.add_paragraph("A real DOCX package, produced by python-docx.")
    document.save(path)


def _write_xlsx(path: Path) -> None:
    openpyxl = _require("openpyxl", "openpyxl")
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet["A1"] = "file"
    sheet["B1"] = "kind"
    sheet["A2"] = "budget.xlsx"
    sheet["B2"] = "fixture"
    workbook.save(path)


def _write_pptx(path: Path) -> None:
    pptx = _require("pptx", "python-pptx")
    presentation = pptx.Presentation()
    slide = presentation.slides.add_slide(presentation.slide_layouts[5])
    slide.shapes.title.text = "CI fixture"
    presentation.save(path)


def _write_zip(path: Path) -> None:
    import zipfile

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("hello.txt", "plain text inside a zip\n")
        archive.writestr("data/values.csv", "a,b\n1,2\n")


def _write_csv(path: Path) -> None:
    path.write_text("file,status\nreadme.txt,valid\nlogo.png,valid\n", encoding="utf-8")


def main() -> int:
    FIXTURES.mkdir(parents=True, exist_ok=True)

    builders = {
        "readme.txt": _write_text,
        "notes.csv": _write_csv,
        "logo.png": _write_png,
        "photo.jpg": _write_jpeg,
        "report.pdf": _write_pdf,
        "contract.docx": _write_docx,
        "budget.xlsx": _write_xlsx,
        "slides.pptx": _write_pptx,
        "bundle.zip": _write_zip,
    }

    for name, builder in builders.items():
        path = FIXTURES / name
        builder(path)
        print(f"  {name:<16} {path.stat().st_size:>8,} bytes")

    print(f"fixtures written to {FIXTURES}")

    # The whole point of the directory: it must scan clean.
    sys.path.insert(0, str(REPO_ROOT))
    sys.path.insert(0, str(REPO_ROOT / "src" / "python"))
    from format_validators import validate_file  # noqa: E402

    problems = []
    for path in sorted(FIXTURES.iterdir()):
        if path.is_dir() or path.name.startswith("."):
            continue
        result = validate_file(path)
        if result.checked and not result.is_valid:
            problems.append(f"{path.name}: {result.error_message}")

    if problems:
        print("\nerror: fixtures failed validation:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    print(f"all {len(builders)} fixtures validate cleanly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
