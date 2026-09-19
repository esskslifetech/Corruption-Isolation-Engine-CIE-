"""Shared fixtures for the CIE test suite.

These tests exercise the shipped code paths. If the package layout changes,
`conftest` puts the repository root on sys.path so `src.python.*` imports work
from any working directory.
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.python.core_analyzer import AnalyzerConfig, CorruptionDetector  # noqa: E402


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    """Isolated working directory for one test."""
    return tmp_path


@pytest.fixture
def config(workdir: Path) -> AnalyzerConfig:
    return AnalyzerConfig(
        db_path=str(workdir / "cie.db"),
        quarantine_dir=str(workdir / "quarantine"),
        max_workers=2,
    )


@pytest.fixture
def detector(config: AnalyzerConfig) -> CorruptionDetector:
    return CorruptionDetector(config)


@pytest.fixture
def make_file(workdir: Path):
    """Write a file and return its path."""
    def _make(name: str, content: bytes) -> Path:
        path = workdir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path
    return _make


@pytest.fixture
def sample_corpus(tmp_path: Path) -> Path:
    """A small mixed corpus: valid, corrupt and exotic files."""
    root = tmp_path / "corpus"
    root.mkdir()

    png = bytes.fromhex(
        "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
        "1f15c4890000000a49444154789c63000100000500010d0a2db4"
        "0000000049454e44ae426082"
    )
    (root / "valid.png").write_bytes(png)
    (root / "valid.jpg").write_bytes(
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"
    )
    (root / "valid.pdf").write_bytes(make_real_pdf_bytes())
    (root / "notes.txt").write_text("plain text\n")
    (root / "empty.txt").write_bytes(b"")

    (root / "truncated.jpg").write_bytes(b"\xff\xd8\xff\xe0" + b"junk junk junk")
    (root / "corrupt.pdf").write_bytes(b"%PDF-1.4\nno end marker here")
    (root / "fake.png").write_bytes(b"this is not a png at all")

    with zipfile.ZipFile(root / "bundle.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.txt", "hello " * 100)

    return root


def corrupt_byte(data: bytes, index: int) -> bytes:
    """Flip a byte so the result is the same length but different content."""
    buffer = bytearray(data)
    buffer[min(index, len(buffer) - 1)] ^= 0xFF
    return bytes(buffer)


def make_real_pdf_bytes() -> bytes:
    """A minimal *valid* PDF: correct objects, xref table and startxref.

    Hand-rolled PDFs without an ``startxref`` are rejected by pypdf - correctly
    - so fixtures that want "valid PDF" must carry a real cross-reference
    table. Offsets are computed here rather than hard-coded.
    """
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
        b"<< /Length 44 >>\nstream\nBT /F1 12 Tf 20 100 Td (CIE test) Tj ET\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_at = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode()
    return bytes(out)


def make_real_png() -> bytes:
    """A genuine PNG written by Pillow (skipped if Pillow is absent)."""
    Image = pytest.importorskip("PIL.Image")
    buffer = io.BytesIO()
    Image.new("RGB", (32, 24), (12, 34, 56)).save(buffer, "PNG")
    return buffer.getvalue()


def make_real_docx(path: Path) -> Path:
    docx = pytest.importorskip("docx")
    document = docx.Document()
    document.add_heading("Test", level=1)
    document.add_paragraph("body text")
    document.save(path)
    return path


def make_real_tar(path: Path) -> Path:
    payload = b"tar payload\n" * 50
    with tarfile.open(path, "w") as archive:
        info = tarfile.TarInfo("payload.txt")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    return path


@pytest.fixture(autouse=True)
def _quiet_logging():
    """Keep test output readable."""
    import logging

    logging.disable(logging.WARNING)
    yield
    logging.disable(logging.NOTSET)


@pytest.fixture
def clean_env(monkeypatch):
    """Ensure CIE-related environment variables do not leak between tests."""
    for name in ("CIE_CONFIG", "CIE_DB_PATH"):
        monkeypatch.delenv(name, raising=False)
    yield
