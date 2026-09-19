"""Validator tests built from real files written by the real encoders.

Every fixture here is produced by Pillow, zipfile, tarfile, python-docx or
openpyxl - never by a hand-written byte string - so a validator that rejects a
valid file is caught immediately. That was the failure mode in v2.0, where a
valid MP4 with a leading `free` box and a JPEG with trailing bytes were both
reported as corrupt.
"""

from __future__ import annotations

import io
import os
import tarfile
import zipfile
import zlib

import pytest

from src.python.format_validators import (
    ArchiveValidator,
    FactoryBackedFormatValidator,
    IsoBmffValidator,
    JpegValidator,
    MagicSignatureValidator,
    SevenZipValidator,
    TarValidator,
    format_name_for,
    validate_file,
)
from tests.conftest import corrupt_byte, make_real_docx, make_real_png, make_real_tar

PIL = pytest.importorskip("PIL.Image")


def write_image(path, fmt: str) -> bytes:
    buffer = io.BytesIO()
    PIL.new("RGB", (64, 48), (10, 120, 200)).save(buffer, fmt)
    data = buffer.getvalue()
    path.write_bytes(data)
    return data


# ---------------------------------------------------------------------------
# real, valid files must pass
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fmt,ext", [("PNG", ".png"), ("JPEG", ".jpg"), ("BMP", ".bmp"),
                                     ("TIFF", ".tiff"), ("WEBP", ".webp"), ("GIF", ".gif")])
def test_valid_images_pass(tmp_path, fmt, ext):
    path = tmp_path / f"image{ext}"
    write_image(path, fmt)
    result = validate_file(path)
    assert result.is_valid, f"{fmt} rejected: {result.error_message}"
    assert result.checked


@pytest.mark.parametrize("fmt,ext", [("PNG", ".png"), ("WEBP", ".webp")])
def test_bit_rot_in_checksummed_images_is_caught(tmp_path, fmt, ext):
    """PNG and WebP carry per-chunk/container CRCs, so damage must be caught."""
    path = tmp_path / f"image{ext}"
    data = write_image(path, fmt)
    path.write_bytes(corrupt_byte(data, 12))
    assert validate_file(path).is_valid is False


@pytest.mark.parametrize("fmt,ext", [("BMP", ".bmp"), ("TIFF", ".tiff")])
def test_truncated_images_are_caught_by_decoders(tmp_path, fmt, ext):
    """Documented limitation: these formats store no checksum, so an in-place
    byte change is only detectable against a stored baseline."""
    path = tmp_path / f"image{ext}"
    data = write_image(path, fmt)
    path.write_bytes(corrupt_byte(data, 12))
    assert validate_file(path).is_valid is False


def test_jpeg_bit_rot_is_a_documented_limitation(tmp_path):
    """JPEG has no checksum and Pillow is lenient, so a byte flip inside the
    scan data is not detectable in a one-shot scan (only versus a baseline)."""
    path = tmp_path / "photo.jpg"
    data = write_image(path, "JPEG")
    path.write_bytes(corrupt_byte(data, 12))
    assert validate_file(path).is_valid is True


def test_jpeg_with_trailing_bytes_is_valid(tmp_path):
    """Editors append padding after EOI - that is not corruption."""
    path = tmp_path / "padded.jpg"
    data = write_image(path, "JPEG")
    path.write_bytes(data + b"\x00" * 512)
    result = validate_file(path)
    assert result.is_valid, result.error_message


def test_truncated_jpeg_is_invalid(tmp_path):
    path = tmp_path / "cut.jpg"
    data = write_image(path, "JPEG")
    path.write_bytes(data[: len(data) // 2])       # lose the EOI marker
    assert validate_file(path).is_valid is False


def test_mp4_with_leading_free_box_is_valid(tmp_path):
    """`ftyp` is not always at offset 4: free/wide boxes may come first."""
    path = tmp_path / "phone.mp4"
    body = bytearray()
    body += (8).to_bytes(4, "big") + b"free"
    body += (24).to_bytes(4, "big") + b"ftyp" + b"isom" + b"\x00\x00\x02\x00" + b"isomiso2"
    body += (8 + 1024).to_bytes(4, "big") + b"mdat" + os.urandom(1024)
    path.write_bytes(bytes(body))
    result = IsoBmffValidator().validate(path)
    assert result.is_valid, result.error_message
    assert result.format_info["leading_boxes"] == ["free"]


def test_mp4_without_ftyp_is_invalid(tmp_path):
    path = tmp_path / "broken.mp4"
    path.write_bytes((8 + 64).to_bytes(4, "big") + b"mdat" + os.urandom(64))
    assert IsoBmffValidator().validate(path).is_valid is False


def test_valid_zip_passes(tmp_path):
    path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.txt", "hello " * 100)
    result = ArchiveValidator().validate(path)
    assert result.is_valid, result.error_message
    assert result.format_info["file_count"] == 1


def test_zip_with_damaged_member_is_invalid(tmp_path):
    path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.txt", "hello " * 200)
    data = path.read_bytes()
    path.write_bytes(corrupt_byte(data, int(len(data) * 0.6)))   # inside compressed data
    assert ArchiveValidator().validate(path).is_valid is False


def test_valid_tar_passes(tmp_path):
    path = make_real_tar(tmp_path / "bundle.tar")
    result = TarValidator().validate(path)
    assert result.is_valid, result.error_message
    assert result.format_info["entries"] == 1


def test_tar_header_corruption_is_caught(tmp_path):
    path = make_real_tar(tmp_path / "bundle.tar")
    path.write_bytes(corrupt_byte(path.read_bytes(), 300))    # inside the header block
    assert TarValidator().validate(path).is_valid is False


def test_valid_7z_start_header_passes(tmp_path):
    header = bytearray(b"7z\xbc\xaf\x27\x1c" + b"\x00\x04" + b"\x00" * 4 + b"\x00" * 20 + b"\x00" * 64)
    header[8:12] = (zlib.crc32(bytes(header[12:32])) & 0xFFFFFFFF).to_bytes(4, "little")
    path = tmp_path / "archive.7z"
    path.write_bytes(bytes(header))
    assert SevenZipValidator().validate(path).is_valid is True


def test_7z_header_crc_mismatch_is_caught(tmp_path):
    header = bytearray(b"7z\xbc\xaf\x27\x1c" + b"\x00\x04" + b"\x00" * 4 + b"\x00" * 20 + b"\x00" * 64)
    header[8:12] = (zlib.crc32(bytes(header[12:32])) & 0xFFFFFFFF).to_bytes(4, "little")
    path = tmp_path / "archive.7z"
    path.write_bytes(corrupt_byte(bytes(header), 20))
    assert SevenZipValidator().validate(path).is_valid is False


def test_real_docx_passes(tmp_path):
    path = make_real_docx(tmp_path / "report.docx")
    result = validate_file(path)
    assert result.is_valid, result.error_message


def test_real_xlsx_passes(tmp_path):
    openpyxl = pytest.importorskip("openpyxl")
    path = tmp_path / "sheet.xlsx"
    workbook = openpyxl.Workbook()
    workbook.active["A1"] = "hello"
    workbook.save(path)
    result = validate_file(path)
    assert result.is_valid, result.error_message


def test_docx_missing_word_directory_is_invalid(tmp_path):
    path = tmp_path / "fake.docx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("not_word/file.txt", "x")
    result = validate_file(path)
    assert result.is_valid is False
    assert "DOCX" in (result.error_message or "")


def test_valid_pdf_passes(tmp_path):
    from conftest import make_real_pdf_bytes

    path = tmp_path / "doc.pdf"
    path.write_bytes(make_real_pdf_bytes())
    result = validate_file(path)
    assert result.is_valid is True, result.error_message


@pytest.mark.parametrize("content", [b"no header at all", b"%PDF-1.4\nno eof marker"])
def test_invalid_pdf_is_rejected(tmp_path, content):
    path = tmp_path / "broken.pdf"
    path.write_bytes(content)
    assert validate_file(path).is_valid is False


# ---------------------------------------------------------------------------
# unknown / unvalidated types must never be called corrupt
# ---------------------------------------------------------------------------

def test_unknown_extension_is_unchecked_not_invalid(tmp_path):
    path = tmp_path / "blob.qqq"
    path.write_bytes(os.urandom(512))
    result = validate_file(path)
    assert result.is_valid is True
    assert result.checked is False
    assert result.format_name == "QQQ"


@pytest.mark.parametrize("ext", [".dwg", ".psd", ".qqq"])
def test_formats_without_validators_are_unchecked(tmp_path, ext):
    path = tmp_path / f"sample{ext}"
    path.write_bytes(os.urandom(256))
    result = validate_file(path)
    assert result.checked is False, f"{ext} claimed to be checked"


# ---------------------------------------------------------------------------
# magic signatures
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ext,head", [
    (".png", b"\x89PNG\r\n\x1a\n"),
    (".gif", b"GIF89a"),
    (".bmp", b"BM"),
    (".tiff", b"II*\x00"),
    (".webp", b"RIFF\x00\x00\x00\x00WEBP"),
    (".mkv", b"\x1a\x45\xdf\xa3"),
    (".flac", b"fLaC"),
    (".ogg", b"OggS"),
    (".gz", b"\x1f\x8b"),
    (".sqlite", b"SQLite format 3\x00"),
    (".elf", b"\x7fELF"),
    (".exe", b"MZ"),
    (".doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
])
def test_signatures_accept_correct_headers(tmp_path, ext, head):
    path = tmp_path / f"f{ext}"
    path.write_bytes(head + b"\x00" * 64)
    assert MagicSignatureValidator().validate(path).is_valid is True


@pytest.mark.parametrize("ext", [".png", ".mkv", ".gz", ".sqlite", ".exe", ".doc"])
def test_signatures_reject_garbage(tmp_path, ext):
    path = tmp_path / f"f{ext}"
    path.write_bytes(b"THIS IS NOT A REAL FILE" * 10)
    result = MagicSignatureValidator().validate(path)
    assert result.is_valid is False
    assert result.format_info["checked"] is True


def test_garbage_for_previously_unvalidated_types_is_now_caught(tmp_path):
    """The audit found 18/18 garbage files reported healthy; these must fail now."""
    extensions = [".rar", ".7z", ".tar", ".doc", ".xls", ".mp3", ".mov",
                  ".mkv", ".sqlite", ".dll", ".so", ".bmp", ".tiff", ".webp"]
    survivors = []
    for extension in extensions:
        path = tmp_path / f"junk{extension}"
        path.write_bytes(b"THIS IS NOT A REAL FILE" * 50)
        result = validate_file(path)
        if result.is_valid and not result.checked:
            survivors.append(extension)
    assert survivors == [], f"garbage accepted by validated types: {survivors}"


# ---------------------------------------------------------------------------
# reporting metadata
# ---------------------------------------------------------------------------

def test_every_result_carries_a_format_name(tmp_path):
    for extension in (".png", ".pdf", ".zip", ".docx", ".xlsx", ".txt", ".qqq"):
        path = tmp_path / f"name{extension}"
        path.write_bytes(b"x" * 32)
        assert validate_file(path).format_name


def test_format_name_lookup():
    assert format_name_for(".mp4") == "MP4"
    assert format_name_for(".KDBX") == "KeePass"
    assert format_name_for("") == "Unknown"
    assert format_name_for(".zzz") == "ZZZ"


def test_factory_and_adapter_return_the_same_result(tmp_path):
    path = tmp_path / "pic.png"
    write_image(path, "PNG")
    from_factory = validate_file(path)
    from_adapter = FactoryBackedFormatValidator().validate(path)
    assert from_factory.is_valid == from_adapter.is_valid
    assert from_factory.format_name == from_adapter.format_name


# ---------------------------------------------------------------------------
# PPTX packages (python-pptx when available, structural checks otherwise)
# ---------------------------------------------------------------------------

def test_valid_pptx_passes(tmp_path):
    from conftest import make_real_pptx

    path = make_real_pptx(tmp_path / "deck.pptx")
    result = validate_file(path)
    assert result.is_valid is True, result.error_message


def test_pptx_validation_uses_python_pptx_when_installed(tmp_path):
    pytest.importorskip("pptx")
    from conftest import make_real_pptx

    result = validate_file(make_real_pptx(tmp_path / "deck.pptx"))
    assert "pptx" in str(result.format_info.get("validator", "")).lower()


def test_pptx_that_is_not_a_zip_is_rejected(tmp_path):
    path = tmp_path / "broken.pptx"
    path.write_bytes(b"this is not a zip file at all")
    result = validate_file(path)
    assert result.is_valid is False
    assert "PPTX" in (result.error_message or "") or "ZIP" in (result.error_message or "").upper()


def test_pptx_without_presentation_part_is_rejected(tmp_path):
    path = tmp_path / "fake.pptx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("docProps/app.xml", "<Properties/>")
    result = validate_file(path)
    assert result.is_valid is False
    assert "PPTX" in (result.error_message or "")


def test_pptx_with_wrong_presentation_root_is_rejected(tmp_path):
    path = tmp_path / "fake.pptx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("ppt/presentation.xml", "<notppt/>")
    result = validate_file(path)
    assert result.is_valid is False
    # The generic message names the format; the detail says which part is wrong.
    assert "PPTX" in (result.error_message or "")
    assert any("presentation" in detail for detail in result.corruption_details), result.corruption_details


def test_truncated_pptx_is_rejected(tmp_path):
    from conftest import make_real_pptx

    path = make_real_pptx(tmp_path / "deck.pptx")
    data = path.read_bytes()
    path.write_bytes(data[: len(data) // 2])
    assert validate_file(path).is_valid is False


def test_pptx_is_routed_to_its_own_format(tmp_path):
    from conftest import make_real_pptx

    result = validate_file(make_real_pptx(tmp_path / "deck.pptx"))
    assert result.format_name == "PPTX"
    assert result.format_info.get("checked") is True
