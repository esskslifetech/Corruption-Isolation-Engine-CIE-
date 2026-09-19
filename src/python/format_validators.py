#!/usr/bin/env python3
"""
Advanced File Format Validators for CIE
Specialized validation for various file formats using dedicated libraries

This Project Is Made By Kanishk Soni

Goals:
- Strong validation without false negatives when optional libraries are missing
- Clear API contract and immutable result model
- Safe fallbacks using built-in structural checks
- Better library detection and richer format metadata
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
import unittest
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable, Protocol

LOGGER = logging.getLogger(__name__)

FilePath = str | Path

try:
    from PIL import Image, UnidentifiedImageError
    PILLOW_AVAILABLE = True
except ImportError:  # pragma: no cover
    Image = None  # type: ignore[assignment]
    UnidentifiedImageError = Exception  # type: ignore[assignment]
    PILLOW_AVAILABLE = False

# pypdf is the maintained successor of PyPDF2; accept either import name so
# `pip install pypdf` (what requirements.txt asks for) actually enables the
# library-backed PDF check.
try:
    import pypdf as PyPDF2  # type: ignore[import-not-found,no-redef]
    PYPDF2_AVAILABLE = True
    PDF_LIBRARY_NAME = "pypdf"
except ImportError:  # pragma: no cover
    try:
        import PyPDF2  # type: ignore[no-redef]
        PYPDF2_AVAILABLE = True
        PDF_LIBRARY_NAME = "PyPDF2"
    except ImportError:
        PyPDF2 = None  # type: ignore[assignment]
        PYPDF2_AVAILABLE = False
        PDF_LIBRARY_NAME = None

try:
    import docx
    DOCX_AVAILABLE = True
except ImportError:  # pragma: no cover
    docx = None  # type: ignore[assignment]
    DOCX_AVAILABLE = False

try:
    import openpyxl
    OPENPYXL_AVAILABLE = True
except ImportError:  # pragma: no cover
    openpyxl = None  # type: ignore[assignment]
    OPENPYXL_AVAILABLE = False

try:
    import pptx  # python-pptx
    PPTX_AVAILABLE = True
except ImportError:  # pragma: no cover
    pptx = None  # type: ignore[assignment]
    PPTX_AVAILABLE = False

FFPROBE_AVAILABLE = shutil.which("ffprobe") is not None


# Human-readable names per extension. Used for reporting; unknown extensions
# fall back to the uppercased suffix so callers always get a stable label.
FORMAT_NAMES: dict[str, str] = {
    ".pdf": "PDF", ".png": "PNG", ".jpg": "JPEG", ".jpeg": "JPEG", ".gif": "GIF",
    ".bmp": "BMP", ".tiff": "TIFF", ".tif": "TIFF", ".webp": "WebP", ".ico": "ICO",
    ".zip": "ZIP", ".jar": "JAR", ".apk": "APK", ".docx": "DOCX", ".xlsx": "XLSX",
    ".pptx": "PPTX", ".odt": "ODT", ".ods": "ODS", ".doc": "DOC", ".xls": "XLS",
    ".ppt": "PPT", ".exe": "PE", ".dll": "PE", ".elf": "ELF", ".so": "ELF",
    ".mp4": "MP4", ".mov": "MOV", ".mkv": "Matroska", ".webm": "WebM",
    ".avi": "AVI", ".mp3": "MP3", ".wav": "WAV", ".flac": "FLAC", ".ogg": "OGG",
    ".opus": "Opus", ".aac": "AAC", ".m4a": "M4A", ".txt": "Text", ".csv": "CSV",
    ".json": "JSON", ".xml": "XML", ".md": "Markdown", ".log": "Log",
    ".gz": "GZip", ".bz2": "BZip2", ".xz": "XZ", ".zst": "Zstandard",
    ".7z": "7-Zip", ".rar": "RAR", ".tar": "TAR", ".sqlite": "SQLite",
    ".sqlite3": "SQLite", ".db": "SQLite", ".iso": "ISO", ".img": "DiskImage",
    ".gpg": "GnuPG", ".kdbx": "KeePass", ".heic": "HEIC", ".avif": "AVIF",
}


def format_name_for(extension: str) -> str:
    """Best-effort display name for an extension ('' -> 'Unknown')."""
    normalized = extension.lower()
    if not normalized:
        return "Unknown"
    return FORMAT_NAMES.get(normalized, normalized.lstrip(".").upper())


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Immutable file validation result."""

    is_valid: bool
    error_message: str | None = None
    format_info: dict[str, Any] = field(default_factory=dict)
    corruption_details: tuple[str, ...] = field(default_factory=tuple)
    format_name: str | None = None

    @property
    def checked(self) -> bool:
        """True when a validator actually inspected the content (not 'unknown type')."""
        return bool(self.format_info.get("checked", False))

    @classmethod
    def ok(
        cls,
        *,
        format_info: dict[str, Any] | None = None,
        corruption_details: Iterable[str] = (),
        format_name: str | None = None,
    ) -> "ValidationResult":
        return cls(
            is_valid=True,
            error_message=None,
            format_info=dict(format_info or {}),
            corruption_details=tuple(corruption_details),
            format_name=format_name,
        )

    @classmethod
    def invalid(
        cls,
        error_message: str,
        *,
        format_info: dict[str, Any] | None = None,
        corruption_details: Iterable[str] = (),
        format_name: str | None = None,
    ) -> "ValidationResult":
        return cls(
            is_valid=False,
            error_message=error_message,
            format_info=dict(format_info or {}),
            corruption_details=tuple(corruption_details),
            format_name=format_name,
        )

    @classmethod
    def unchecked(
        cls,
        *,
        reason: str,
        format_info: dict[str, Any] | None = None,
        format_name: str | None = None,
    ) -> "ValidationResult":
        payload = dict(format_info or {})
        payload["checked"] = False
        payload["reason"] = reason
        return cls(
            is_valid=True,
            error_message=None,
            format_info=payload,
            corruption_details=(),
            format_name=format_name,
        )


class SupportsValidation(Protocol):
    def validate(self, file_path: FilePath) -> ValidationResult: ...


def _path(value: FilePath) -> Path:
    return Path(value).expanduser().resolve()


def _read_prefix(path: Path, size: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(size)


def _read_suffix(path: Path, size: int) -> bytes:
    file_size = path.stat().st_size
    start = max(0, file_size - size)
    with path.open("rb") as handle:
        handle.seek(start)
        return handle.read()


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _iso_bmff_boxes(prefix: bytes, limit: int = 24) -> list[tuple[int, bytes]]:
    """Walk the top level of an ISO base media file (MP4/MOV/HEIC).

    Returns [(offset, box_type), ...]. Many real recordings start with a `free`
    or `wide` box *before* `ftyp`, so checking offset 4 for b"ftyp" is wrong.
    """
    boxes: list[tuple[int, bytes]] = []
    offset = 0
    total = len(prefix)

    while offset + 8 <= total and len(boxes) < limit:
        size = int.from_bytes(prefix[offset:offset + 4], "big")
        box_type = prefix[offset + 4:offset + 8]
        boxes.append((offset, box_type))

        if size == 0:            # box extends to EOF
            break
        if size == 1:            # 64-bit size follows the type
            if offset + 16 > total:
                break
            size = int.from_bytes(prefix[offset + 8:offset + 16], "big")
        if size < 8:             # malformed
            break
        offset += size

    return boxes


class IsoBmffValidator:
    """MP4/MOV/3GP container validation via box walking."""

    _VALID_BRANDS = (
        b"isom", b"iso2", b"iso4", b"iso5", b"iso6", b"mp41", b"mp42",
        b"avc1", b"dash", b"M4V ", b"M4A ", b"3gp4", b"3gp5", b"qt  ",
        b"heic", b"heix", b"mif1", b"avif",
    )

    def validate(self, file_path: FilePath) -> ValidationResult:
        path = _path(file_path)
        extension = path.suffix.lower()
        format_name = format_name_for(extension)

        try:
            prefix = _read_prefix(path, 4096)
        except OSError as exc:
            return ValidationResult.invalid(
                f"failed to read media header: {exc}",
                format_info={"extension": extension, "validator": "iso-bmff"},
                format_name=format_name,
            )

        boxes = _iso_bmff_boxes(prefix)
        types = [box_type for _, box_type in boxes]

        if b"ftyp" not in types:
            return ValidationResult.invalid(
                f"missing {format_name} ftyp box",
                format_info={
                    "extension": extension, "validator": "iso-bmff", "checked": True,
                    "leading_boxes": [t.decode("latin-1") for t in types[:6]],
                },
                corruption_details=("no ISO base media ftyp box found in the first boxes",),
                format_name=format_name,
            )

        ftyp_index = types.index(b"ftyp")
        ftyp_offset = boxes[ftyp_index][0]
        brand = prefix[ftyp_offset + 8:ftyp_offset + 12]
        leading = [t.decode("latin-1") for t in types[:ftyp_index]]

        if brand not in self._VALID_BRANDS and not brand.startswith(b"iso"):
            return ValidationResult.invalid(
                f"unrecognised {format_name} brand: {brand!r}",
                format_info={
                    "extension": extension, "validator": "iso-bmff", "checked": True,
                    "brand": brand.decode("latin-1", "replace"), "leading_boxes": leading,
                },
                corruption_details=(f"brand {brand!r} is not a known ISO base media brand",),
                format_name=format_name,
            )

        return ValidationResult.ok(
            format_info={
                "extension": extension, "validator": "iso-bmff", "checked": True,
                "brand": brand.decode("latin-1", "replace"),
                "leading_boxes": leading,
                "has_mdat": b"mdat" in types,
            },
            format_name=format_name,
        )


class JpegValidator:
    """JPEG validation that tolerates trailing bytes after EOI (very common)."""

    _TAIL_WINDOW = 64 * 1024

    def validate(self, file_path: FilePath) -> ValidationResult:
        path = _path(file_path)
        format_name = "JPEG"
        try:
            size = path.stat().st_size
            prefix = _read_prefix(path, 3)
            # scan the whole file when small, otherwise the last 64 KB
            suffix = _read_suffix(path, min(self._TAIL_WINDOW, size))
        except OSError as exc:
            return ValidationResult.invalid(
                f"failed to read JPEG: {exc}",
                format_info={"validator": "jpeg"},
                format_name=format_name,
            )

        issues: list[str] = []
        if not prefix.startswith(b"\xff\xd8\xff"):
            issues.append("missing JPEG SOI marker")
        if b"\xff\xd9" not in suffix:
            issues.append("missing JPEG EOI marker")

        if issues:
            return ValidationResult.invalid(
                "invalid JPEG structure",
                format_info={
                    "extension": path.suffix.lower(), "validator": "jpeg",
                    "checked": True, "size": size,
                },
                corruption_details=tuple(issues),
                format_name=format_name,
            )

        # note trailing padding but do not treat it as corruption
        last_eoi = suffix.rfind(b"\xff\xd9")
        trailing = (len(suffix) - (last_eoi + 2)) if last_eoi >= 0 and size > len(suffix) else 0
        warnings = []
        if last_eoi >= 0 and last_eoi + 2 < len(suffix):
            warnings.append("trailing bytes after EOI marker")

        return ValidationResult.ok(
            format_info={
                "extension": path.suffix.lower(), "validator": "jpeg", "checked": True,
                "size": size, "trailing_bytes": max(0, trailing), "warnings": warnings,
            },
            format_name=format_name,
        )


class MagicSignatureValidator:
    """Fallback validator using structural signatures.

    Signatures are (offset, bytes) tuples. Every entry is verified against real
    files in tests/test_validators.py; formats whose layouts cannot be checked
    with a fixed offset (MP4/MOV, JPEG, PDF tails) get a dedicated validator.
    """

    _SIGNATURES: dict[str, tuple[tuple[int, bytes], ...]] = {
        # --- images ---
        ".png": ((0, b"\x89PNG\r\n\x1a\n"),),
        ".jpg": ((0, b"\xff\xd8\xff"),),
        ".jpeg": ((0, b"\xff\xd8\xff"),),
        ".gif": ((0, b"GIF87a"), (0, b"GIF89a")),
        ".bmp": ((0, b"BM"),),
        ".tiff": ((0, b"II*\x00"), (0, b"MM\x00*")),
        ".tif": ((0, b"II*\x00"), (0, b"MM\x00*")),
        ".webp": ((0, b"RIFF"), (8, b"WEBP")),
        ".ico": ((0, b"\x00\x00\x01\x00"),),
        ".heic": ((4, b"ftypheic"), (4, b"ftypheix"), (4, b"ftypmif1")),
        ".avif": ((4, b"ftypavif"),),
        # --- documents / containers ---
        ".pdf": ((0, b"%PDF-"),),
        ".zip": ((0, b"PK\x03\x04"), (0, b"PK\x05\x06"), (0, b"PK\x07\x08")),
        ".jar": ((0, b"PK\x03\x04"),),
        ".apk": ((0, b"PK\x03\x04"),),
        ".docx": ((0, b"PK\x03\x04"),),
        ".xlsx": ((0, b"PK\x03\x04"),),
        ".pptx": ((0, b"PK\x03\x04"),),
        ".odt": ((0, b"PK\x03\x04"),),
        ".ods": ((0, b"PK\x03\x04"),),
        # OLE2 compound files: legacy .doc/.xls/.ppt
        ".doc": ((0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),),
        ".xls": ((0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),),
        ".ppt": ((0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),),
        # --- executables ---
        ".exe": ((0, b"MZ"),),
        ".dll": ((0, b"MZ"),),
        ".elf": ((0, b"\x7fELF"),),
        ".so": ((0, b"\x7fELF"),),
        # --- audio / video with fixed headers ---
        ".wav": ((0, b"RIFF"), (8, b"WAVE")),
        ".avi": ((0, b"RIFF"), (8, b"AVI ")),
        ".mkv": ((0, b"\x1a\x45\xdf\xa3"),),
        ".webm": ((0, b"\x1a\x45\xdf\xa3"),),
        ".flac": ((0, b"fLaC"),),
        ".ogg": ((0, b"OggS"),),
        ".opus": ((0, b"OggS"),),
        ".mp3": ((0, b"ID3"), (0, b"\xff\xfb"), (0, b"\xff\xf3"), (0, b"\xff\xf2")),
        # --- archives / encrypted containers ---
        ".gz": ((0, b"\x1f\x8b"),),
        ".bz2": ((0, b"BZh"),),
        ".xz": ((0, b"\xfd7zXZ\x00"),),
        ".zst": ((0, b"\x28\xb5\x2f\xfd"),),
        ".7z": ((0, b"7z\xbc\xaf\x27\x1c"),),
        ".rar": ((0, b"Rar!\x1a\x07\x00"), (0, b"Rar!\x1a\x07\x01\x00")),
        ".sqlite": ((0, b"SQLite format 3\x00"),),
        ".sqlite3": ((0, b"SQLite format 3\x00"),),
        ".db": ((0, b"SQLite format 3\x00"),),
        ".gpg": ((0, b"\x85\x02"), (0, b"\x8c\x03"), (0, b"\x8d\x04")),
        ".kdbx": ((0, b"\x03\xd9\xa2\x9a"), (0, b"\x9a\xa2\xd9\x03")),
    }

    def validate(self, file_path: FilePath) -> ValidationResult:
        path = _path(file_path)
        extension = path.suffix.lower()
        format_name = format_name_for(extension)
        signatures = self._SIGNATURES.get(extension)

        if not signatures:
            return ValidationResult.unchecked(
                reason="no magic signature validator available",
                format_info={"extension": extension or "<none>", "validator": "magic"},
                format_name=format_name,
            )

        max_required = max(offset + len(signature) for offset, signature in signatures)
        try:
            prefix = _read_prefix(path, max_required)
        except OSError as exc:
            return ValidationResult.invalid(
                f"failed to read file header: {exc}",
                format_info={"extension": extension, "validator": "magic"},
                format_name=format_name,
            )

        for signature_group in signatures:
            offset, signature = signature_group
            if prefix[offset:offset + len(signature)] == signature:
                return ValidationResult.ok(
                    format_info={
                        "extension": extension,
                        "validator": "magic",
                        "checked": True,
                    },
                    format_name=format_name,
                )

        return ValidationResult.invalid(
            f"{extension or 'file'} signature mismatch",
            format_info={"extension": extension, "validator": "magic", "checked": True},
            corruption_details=("file header does not match expected magic signature",),
            format_name=format_name,
        )


class TarValidator:
    """TAR validation using the per-header checksum field.

    Every 512-byte TAR header carries an octal checksum over its own bytes, so
    damaged headers are detectable without any extra metadata.
    """

    BLOCK = 512
    _MAX_RECORDS = 4096

    @staticmethod
    def _parse_octal(field: bytes) -> int | None:
        text = field.split(b"\x00", 1)[0].strip()
        if not text:
            return 0
        try:
            return int(text, 8)
        except ValueError:
            return None

    def validate(self, file_path: FilePath) -> ValidationResult:
        path = _path(file_path)
        format_name = "TAR"

        try:
            size = path.stat().st_size
        except OSError as exc:
            return ValidationResult.invalid(
                f"failed to stat TAR: {exc}", format_info={"validator": "tar"}, format_name=format_name
            )

        if size < self.BLOCK:
            return ValidationResult.invalid(
                "TAR is smaller than one 512-byte block",
                format_info={"validator": "tar", "checked": True, "size": size},
                corruption_details=("truncated TAR archive",),
                format_name=format_name,
            )

        try:
            with path.open("rb") as handle:
                records = 0
                entries = 0
                zero_blocks = 0

                while records < self._MAX_RECORDS:
                    header = handle.read(self.BLOCK)
                    if len(header) < self.BLOCK:
                        if header.strip(b"\x00"):
                            return ValidationResult.invalid(
                                "TAR ends with a partial header block",
                                format_info={"validator": "tar", "checked": True, "entries": entries},
                                corruption_details=("truncated final header block",),
                                format_name=format_name,
                            )
                        break

                    records += 1
                    if header == bytes(self.BLOCK):
                        zero_blocks += 1
                        if zero_blocks >= 2:
                            break
                        continue

                    stored = self._parse_octal(header[148:156])
                    if stored is None:
                        return ValidationResult.invalid(
                            "unreadable TAR checksum field",
                            format_info={"validator": "tar", "checked": True, "entries": entries},
                            corruption_details=(f"header {records} has a malformed checksum field",),
                            format_name=format_name,
                        )

                    # Per POSIX, the checksum is computed with its own field
                    # replaced by eight ASCII spaces.
                    checksum_field = header[148:156]
                    as_spaces = b" " * 8
                    unsigned = sum(header[:148]) + sum(as_spaces) + sum(header[156:])
                    signed = (
                        sum(byte if byte < 128 else byte - 256 for byte in header[:148])
                        + sum(as_spaces)
                        + sum(byte if byte < 128 else byte - 256 for byte in header[156:])
                    )
                    if stored not in (unsigned, signed):
                        return ValidationResult.invalid(
                            "TAR header checksum mismatch",
                            format_info={"validator": "tar", "checked": True, "entries": entries},
                            corruption_details=(
                                f"header {records}: stored checksum {stored}, computed {unsigned}",
                            ),
                            format_name=format_name,
                        )

                    entry_size = self._parse_octal(header[124:136]) or 0
                    entries += 1
                    padding = (self.BLOCK - entry_size % self.BLOCK) % self.BLOCK
                    handle.seek(entry_size + padding, 1)

        except OSError as exc:
            return ValidationResult.invalid(
                f"TAR validation error: {exc}",
                format_info={"validator": "tar", "checked": True},
                format_name=format_name,
            )

        return ValidationResult.ok(
            format_info={"validator": "tar", "checked": True, "entries": entries, "size": size},
            format_name=format_name,
        )


class SevenZipValidator:
    """7-Zip validation using the start-header CRC the format defines."""

    _SIGNATURE = b"7z\xbc\xaf\x27\x1c"
    _START_HEADER_LENGTH = 32

    def validate(self, file_path: FilePath) -> ValidationResult:
        path = _path(file_path)
        format_name = "7-Zip"

        try:
            with path.open("rb") as handle:
                header = handle.read(self._START_HEADER_LENGTH)
        except OSError as exc:
            return ValidationResult.invalid(
                f"failed to read 7z header: {exc}",
                format_info={"validator": "7z"},
                format_name=format_name,
            )

        if not header.startswith(self._SIGNATURE):
            return ValidationResult.invalid(
                "7z signature mismatch",
                format_info={"validator": "7z", "checked": True},
                corruption_details=("file does not start with the 7z signature",),
                format_name=format_name,
            )

        if len(header) < self._START_HEADER_LENGTH:
            return ValidationResult.invalid(
                "truncated 7z start header",
                format_info={"validator": "7z", "checked": True},
                corruption_details=("start header is incomplete",),
                format_name=format_name,
            )

        stored_crc = int.from_bytes(header[8:12], "little")
        computed_crc = zlib.crc32(header[12:32]) & 0xFFFFFFFF
        if stored_crc != computed_crc:
            return ValidationResult.invalid(
                "7z start header CRC mismatch",
                format_info={"validator": "7z", "checked": True},
                corruption_details=(
                    f"stored CRC {stored_crc:#010x}, computed {computed_crc:#010x}",
                ),
                format_name=format_name,
            )

        next_header_offset = int.from_bytes(header[12:20], "little")
        next_header_size = int.from_bytes(header[20:28], "little")
        next_header_crc = int.from_bytes(header[28:32], "little")
        invalid_fields = next_header_offset == 0xFFFFFFFFFFFFFFFF or next_header_size == 0xFFFFFFFFFFFFFFFF

        warnings = []
        if next_header_crc == 0 and next_header_size == 0:
            warnings.append("archive has no end header")

        return ValidationResult.ok(
            format_info={
                "validator": "7z",
                "checked": True,
                "has_end_header": not invalid_fields,
                "warnings": warnings,
            },
            format_name=format_name,
        )


class ImageValidator:
    """Image validation with Pillow and structural fallback.

    JPEGs are always checked structurally first (SOI + EOI) because Pillow
    accepts some truncated files, and because EOI validation must tolerate the
    trailing bytes that many editors append.
    """

    _MAGIC_FALLBACK = MagicSignatureValidator()
    _JPEG = JpegValidator()

    def validate(self, file_path: FilePath) -> ValidationResult:
        path = _path(file_path)
        extension = path.suffix.lower()

        if extension in {".jpg", ".jpeg"}:
            structural = self._JPEG.validate(path)
            if not structural.is_valid:
                return structural

        if not PILLOW_AVAILABLE:
            if extension in {".jpg", ".jpeg"}:
                return structural
            return self._MAGIC_FALLBACK.validate(path)

        try:
            with Image.open(path) as image:
                image.verify()

            with Image.open(path) as image:
                image.load()

                width, height = image.size
                warnings: list[str] = []

                if width < 1 or height < 1:
                    return ValidationResult.invalid(
                        "invalid image dimensions",
                        format_info={
                            "extension": extension,
                            "validator": "pillow",
                            "format": image.format,
                            "mode": image.mode,
                            "size": [width, height],
                            "checked": True,
                        },
                        corruption_details=("image has non-positive dimensions",),
                    )

                if width > 50_000 or height > 50_000:
                    warnings.append("suspiciously large dimensions")

                has_transparency = image.mode in {"RGBA", "LA"} or "transparency" in image.info

                return ValidationResult.ok(
                    format_info={
                        "extension": extension,
                        "validator": "pillow",
                        "checked": True,
                        "format": image.format,
                        "mode": image.mode,
                        "size": [width, height],
                        "has_transparency": has_transparency,
                        "warnings": warnings,
                    },
                    format_name=format_name_for(extension),
                )

        except UnidentifiedImageError as exc:
            return ValidationResult.invalid(
                f"unidentifiable image: {exc}",
                format_info={"extension": extension, "validator": "pillow", "checked": True},
                format_name=format_name_for(extension),
            )
        except OSError as exc:
            return ValidationResult.invalid(
                f"image validation error: {exc}",
                format_info={"extension": extension, "validator": "pillow", "checked": True},
                format_name=format_name_for(extension),
            )


class PDFValidator:
    """PDF validation with PyPDF2 and structural fallback."""

    def validate(self, file_path: FilePath) -> ValidationResult:
        path = _path(file_path)
        extension = path.suffix.lower()

        try:
            prefix = _read_prefix(path, 8)
            suffix = _read_suffix(path, 2048)
        except OSError as exc:
            return ValidationResult.invalid(
                f"failed to read PDF: {exc}",
                format_info={"extension": extension, "validator": "pdf"},
            )

        issues: list[str] = []
        if not prefix.startswith(b"%PDF-"):
            issues.append("missing PDF header")
        if b"%%EOF" not in suffix:
            issues.append("missing PDF EOF marker")

        if PYPDF2_AVAILABLE:
            try:
                with path.open("rb") as handle:
                    reader = PyPDF2.PdfReader(handle)
                    page_count = len(reader.pages)
                    metadata = reader.metadata or {}
                    is_encrypted = bool(reader.is_encrypted)

                    format_info = {
                        "extension": extension,
                        "validator": PDF_LIBRARY_NAME or "pypdf",
                        "checked": True,
                        "page_count": page_count,
                        "is_encrypted": is_encrypted,
                        "has_metadata": bool(metadata),
                        "title": metadata.get("/Title", "") if metadata else "",
                        "author": metadata.get("/Author", "") if metadata else "",
                        "creator": metadata.get("/Creator", "") if metadata else "",
                    }

                    if page_count == 0:
                        issues.append("no pages found")

                    if issues:
                        return ValidationResult.invalid(
                            "invalid PDF structure",
                            format_info=format_info,
                            corruption_details=issues,
                        )

                    return ValidationResult.ok(format_info=format_info)

            except Exception as exc:
                issues.append(str(exc))
                return ValidationResult.invalid(
                    "PDF validation error",
                    format_info={"extension": extension, "validator": PDF_LIBRARY_NAME or "pypdf", "checked": True},
                    corruption_details=issues,
                )

        if issues:
            return ValidationResult.invalid(
                "invalid PDF structure",
                format_info={"extension": extension, "validator": "pdf-fallback", "checked": True},
                corruption_details=issues,
            )

        return ValidationResult.ok(
            format_info={"extension": extension, "validator": "pdf-fallback", "checked": True}
        )


class ArchiveValidator:
    """ZIP-family archive validator."""

    def validate(self, file_path: FilePath) -> ValidationResult:
        path = _path(file_path)
        extension = path.suffix.lower()

        try:
            with zipfile.ZipFile(path, "r") as archive:
                info_list = archive.infolist()
                bad_member = archive.testzip()
                member_names = archive.namelist()

                if bad_member is not None:
                    return ValidationResult.invalid(
                        f"corrupted archive member: {bad_member}",
                        format_info={
                            "extension": extension,
                            "validator": "zipfile",
                            "checked": True,
                        },
                    )

                warnings: list[str] = []
                for member_name in member_names:
                    normalized = member_name.replace("\\", "/")
                    if normalized.startswith("/") or "/../" in f"/{normalized}":
                        warnings.append(f"suspicious path: {member_name}")

                max_depth = max((name.count("/") for name in member_names), default=0)
                if max_depth > 100:
                    warnings.append("suspiciously deep directory structure")

                return ValidationResult.ok(
                    format_info={
                        "extension": extension,
                        "validator": "zipfile",
                        "checked": True,
                        "file_count": len(info_list),
                        "total_uncompressed_size": sum(info.file_size for info in info_list),
                        "total_compressed_size": sum(info.compress_size for info in info_list),
                        "is_encrypted": any(bool(info.flag_bits & 0x1) for info in info_list),
                        "max_directory_depth": max_depth,
                        "warnings": warnings,
                    }
                )

        except zipfile.BadZipFile as exc:
            return ValidationResult.invalid(
                f"bad ZIP file: {exc}",
                format_info={"extension": extension, "validator": "zipfile", "checked": True},
            )
        except OSError as exc:
            return ValidationResult.invalid(
                f"archive validation error: {exc}",
                format_info={"extension": extension, "validator": "zipfile", "checked": True},
            )


def _zip_member_root_tag(path: Path, member: str) -> str | None:
    """Root XML tag of a zip member, or None if it cannot be parsed."""
    import xml.etree.ElementTree as ET

    try:
        with zipfile.ZipFile(path, "r") as archive:
            with archive.open(member) as handle:
                for _event, element in ET.iterparse(handle, events=("start",)):
                    return element.tag
    except Exception:
        return None
    return None


class DocumentValidator:
    """DOCX and XLSX validation with structural and library-aware checks."""

    _archive_validator = ArchiveValidator()

    def validate_docx(self, file_path: FilePath) -> ValidationResult:
        path = _path(file_path)
        base_result = self._archive_validator.validate(path)
        if not base_result.is_valid:
            return base_result

        try:
            with zipfile.ZipFile(path, "r") as archive:
                names = set(archive.namelist())
        except (OSError, zipfile.BadZipFile) as exc:
            return ValidationResult.invalid(
                f"DOCX validation error: {exc}",
                format_info={"extension": ".docx", "validator": "docx-structure", "checked": True},
            )

        issues: list[str] = []
        if "[Content_Types].xml" not in names:
            issues.append("missing [Content_Types].xml")
        if "word/document.xml" not in names:
            issues.append("missing word/document.xml")
        else:
            # A package can carry a file of that name without it being a
            # WordprocessingML document (the audit corpus had a zip with a
            # random payload named word/document.xml that sailed through).
            root_tag = _zip_member_root_tag(path, "word/document.xml")
            if root_tag is None:
                issues.append("word/document.xml is not readable XML")
            elif not root_tag.endswith("}document"):
                issues.append(f"word/document.xml root is {root_tag}, not w:document")

        if issues:
            return ValidationResult.invalid(
                "invalid DOCX structure",
                format_info={"extension": ".docx", "validator": "docx-structure", "checked": True},
                corruption_details=issues,
            )

        format_info = {
            **base_result.format_info,
            "extension": ".docx",
            "validator": "docx-structure",
            "checked": True,
        }

        if DOCX_AVAILABLE:
            try:
                document = docx.Document(path)
                format_info = {
                    **format_info,
                    "validator": "python-docx",
                    "paragraph_count": len(document.paragraphs),
                    "table_count": len(document.tables),
                    "has_core_properties": document.core_properties is not None,
                }
            except Exception as exc:
                # python-docx raises assorted internal errors (e.g. an lxml
                # AttributeError) on malformed packages; report what they mean
                # rather than leaking the library's exception text.
                return ValidationResult.invalid(
                    "python-docx cannot read this DOCX package",
                    format_info={"extension": ".docx", "validator": "python-docx", "checked": True},
                    corruption_details=[f"{type(exc).__name__}: {exc}"],
                )

        return ValidationResult.ok(format_info=format_info)

    def validate_xlsx(self, file_path: FilePath) -> ValidationResult:
        path = _path(file_path)
        base_result = self._archive_validator.validate(path)
        if not base_result.is_valid:
            return base_result

        try:
            with zipfile.ZipFile(path, "r") as archive:
                names = set(archive.namelist())
        except (OSError, zipfile.BadZipFile) as exc:
            return ValidationResult.invalid(
                f"XLSX validation error: {exc}",
                format_info={"extension": ".xlsx", "validator": "xlsx-structure", "checked": True},
            )

        issues: list[str] = []
        if "[Content_Types].xml" not in names:
            issues.append("missing [Content_Types].xml")
        if "xl/workbook.xml" not in names:
            issues.append("missing xl/workbook.xml")
        else:
            root_tag = _zip_member_root_tag(path, "xl/workbook.xml")
            if root_tag is None:
                issues.append("xl/workbook.xml is not readable XML")
            elif not root_tag.endswith("}workbook"):
                issues.append(f"xl/workbook.xml root is {root_tag}, not workbook")

        if issues:
            return ValidationResult.invalid(
                "invalid XLSX structure",
                format_info={"extension": ".xlsx", "validator": "xlsx-structure", "checked": True},
                corruption_details=issues,
            )

        format_info = {
            **base_result.format_info,
            "extension": ".xlsx",
            "validator": "xlsx-structure",
            "checked": True,
        }

        if OPENPYXL_AVAILABLE:
            workbook = None
            try:
                workbook = openpyxl.load_workbook(path, read_only=True, data_only=True)
                format_info = {
                    **format_info,
                    "validator": "openpyxl",
                    "sheet_count": len(workbook.sheetnames),
                    "sheet_names": list(workbook.sheetnames[:10]),
                }
            except Exception as exc:
                return ValidationResult.invalid(
                    "openpyxl cannot read this XLSX package",
                    format_info={"extension": ".xlsx", "validator": "openpyxl", "checked": True},
                    corruption_details=[f"{type(exc).__name__}: {exc}"],
                )
            finally:
                if workbook is not None:
                    workbook.close()

        return ValidationResult.ok(format_info=format_info)

    def validate_pptx(self, file_path: FilePath) -> ValidationResult:
        """PPTX validation: package layout, part root, then python-pptx.

        Before this existed, `.pptx` only received the generic zip/signature
        check, so a PowerPoint file whose presentation part was damaged could
        pass - and the README advertised PPTX as supported.
        """
        path = _path(file_path)
        base_result = self._archive_validator.validate(path)
        if not base_result.is_valid:
            return base_result

        try:
            with zipfile.ZipFile(path, "r") as archive:
                names = set(archive.namelist())
        except (OSError, zipfile.BadZipFile) as exc:
            return ValidationResult.invalid(
                f"PPTX validation error: {exc}",
                format_info={"extension": ".pptx", "validator": "pptx-structure", "checked": True},
            )

        issues: list[str] = []
        if "[Content_Types].xml" not in names:
            issues.append("missing [Content_Types].xml")
        if "ppt/presentation.xml" not in names:
            issues.append("missing ppt/presentation.xml")
        else:
            root_tag = _zip_member_root_tag(path, "ppt/presentation.xml")
            if root_tag is None:
                issues.append("ppt/presentation.xml is not readable XML")
            elif not root_tag.endswith("}presentation"):
                issues.append(f"ppt/presentation.xml root is {root_tag}, not p:presentation")

        if issues:
            return ValidationResult.invalid(
                "invalid PPTX structure",
                format_info={"extension": ".pptx", "validator": "pptx-structure", "checked": True},
                corruption_details=issues,
            )

        format_info = {
            **base_result.format_info,
            "extension": ".pptx",
            "validator": "pptx-structure",
            "checked": True,
        }

        if PPTX_AVAILABLE:
            try:
                presentation = pptx.Presentation(path)
                slide_count = len(presentation.slides)
                format_info = {
                    **format_info,
                    "validator": "python-pptx",
                    "slide_count": slide_count,
                    "slide_width": presentation.slide_width,
                    "slide_height": presentation.slide_height,
                }
            except Exception as exc:
                return ValidationResult.invalid(
                    "python-pptx cannot read this PPTX package",
                    format_info={"extension": ".pptx", "validator": "python-pptx", "checked": True},
                    corruption_details=[f"{type(exc).__name__}: {exc}"],
                )

        return ValidationResult.ok(format_info=format_info)


class MediaValidator:
    """Media validation through ffprobe."""

    def validate(self, file_path: FilePath) -> ValidationResult:
        path = _path(file_path)
        extension = path.suffix.lower()

        if not FFPROBE_AVAILABLE:
            # Without ffprobe the container signature is still checkable, so a
            # garbage file is not silently reported as "unknown but fine".
            fallback = MagicSignatureValidator().validate(path)
            if fallback.checked:
                fallback.format_info["validator"] = "magic (ffprobe unavailable)"
                return fallback
            return ValidationResult.unchecked(
                reason="ffprobe not available and no container signature for this type",
                format_info={"extension": extension, "validator": "ffprobe"},
            )

        command = [
            "ffprobe",
            "-v",
            "error",
            "-show_format",
            "-show_streams",
            "-print_format",
            "json",
            str(path),
        ]

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ValidationResult.invalid(
                f"media validation error: {exc}",
                format_info={"extension": extension, "validator": "ffprobe", "checked": True},
            )

        if completed.returncode != 0:
            stderr = completed.stderr.strip() or "ffprobe failed"
            return ValidationResult.invalid(
                f"FFprobe error: {stderr}",
                format_info={"extension": extension, "validator": "ffprobe", "checked": True},
            )

        try:
            payload = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError as exc:
            return ValidationResult.invalid(
                f"invalid ffprobe output: {exc}",
                format_info={"extension": extension, "validator": "ffprobe", "checked": True},
            )

        streams = payload.get("streams", [])
        format_section = payload.get("format", {})

        video_streams = [stream for stream in streams if stream.get("codec_type") == "video"]
        audio_streams = [stream for stream in streams if stream.get("codec_type") == "audio"]
        subtitle_streams = [stream for stream in streams if stream.get("codec_type") == "subtitle"]

        issues: list[str] = []
        duration = _safe_float(format_section.get("duration"))
        if duration < 0:
            issues.append("negative duration")

        if not video_streams and not audio_streams:
            issues.append("no valid audio or video streams found")

        for stream in video_streams:
            width = _safe_int(stream.get("width"))
            height = _safe_int(stream.get("height"))
            if width <= 0 or height <= 0:
                issues.append("invalid video dimensions")
                break

        format_info = {
            "extension": extension,
            "validator": "ffprobe",
            "checked": True,
            "format_name": format_section.get("format_name", "unknown"),
            "duration": duration,
            "size": _safe_int(format_section.get("size")),
            "bit_rate": _safe_int(format_section.get("bit_rate")),
            "video_streams": len(video_streams),
            "audio_streams": len(audio_streams),
            "subtitle_streams": len(subtitle_streams),
        }

        if issues:
            return ValidationResult.invalid(
                "invalid media structure",
                format_info=format_info,
                corruption_details=issues,
            )

        return ValidationResult.ok(format_info=format_info)


class FormatValidatorFactory:
    """Central registry for extension-based validation."""

    _image_validator = ImageValidator()
    _pdf_validator = PDFValidator()
    _archive_validator = ArchiveValidator()
    _document_validator = DocumentValidator()
    _media_validator = MediaValidator()
    _magic_validator = MagicSignatureValidator()
    _isobmff_validator = IsoBmffValidator()
    _tar_validator = TarValidator()
    _sevenzip_validator = SevenZipValidator()

    _IMAGE_EXTENSIONS = frozenset({".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp", ".ico"})
    _PDF_EXTENSIONS = frozenset({".pdf"})
    _ARCHIVE_EXTENSIONS = frozenset({".zip", ".jar", ".apk"})
    _TAR_EXTENSIONS = frozenset({".tar"})
    _SEVENZIP_EXTENSIONS = frozenset({".7z"})
    _ISOBMFF_EXTENSIONS = frozenset({".mp4", ".m4a", ".m4v", ".mov", ".3gp", ".heic", ".heif", ".avif"})
    _MEDIA_EXTENSIONS = frozenset({".mp4", ".avi", ".mov", ".mkv", ".mp3", ".wav", ".flac", ".aac", ".ogg", ".webm"})
    _DOCX_EXTENSIONS = frozenset({".docx"})
    _XLSX_EXTENSIONS = frozenset({".xlsx"})
    _PPTX_EXTENSIONS = frozenset({".pptx"})

    @classmethod
    def get_validator(cls, file_path: FilePath) -> SupportsValidation | None:
        extension = _path(file_path).suffix.lower()

        if extension in cls._IMAGE_EXTENSIONS:
            return cls._image_validator
        if extension in cls._PDF_EXTENSIONS:
            return cls._pdf_validator
        if extension in cls._ARCHIVE_EXTENSIONS:
            return cls._archive_validator
        if extension in cls._ISOBMFF_EXTENSIONS:
            return cls._isobmff_validator
        if extension in cls._TAR_EXTENSIONS:
            return cls._tar_validator
        if extension in cls._SEVENZIP_EXTENSIONS:
            return cls._sevenzip_validator
        if extension in cls._MEDIA_EXTENSIONS:
            return cls._media_validator
        if extension in cls._DOCX_EXTENSIONS:
            return cls
        if extension in cls._XLSX_EXTENSIONS:
            return cls
        if extension in cls._PPTX_EXTENSIONS:
            return cls
        if extension in MagicSignatureValidator._SIGNATURES:
            return cls._magic_validator

        return None

    @classmethod
    def validate_file(cls, file_path: FilePath) -> ValidationResult:
        path = _path(file_path)
        extension = path.suffix.lower()

        def labelled(result: ValidationResult) -> ValidationResult:
            """Guarantee every result carries a display name for reporting."""
            if result.format_name is not None:
                return result
            return replace(result, format_name=format_name_for(extension))

        try:
            if extension in cls._DOCX_EXTENSIONS:
                return labelled(cls._document_validator.validate_docx(path))
            if extension in cls._XLSX_EXTENSIONS:
                return labelled(cls._document_validator.validate_xlsx(path))
            if extension in cls._PPTX_EXTENSIONS:
                return labelled(cls._document_validator.validate_pptx(path))

            validator = cls.get_validator(path)
            if validator is None:
                return labelled(
                    ValidationResult.unchecked(
                        reason="no specific validator available",
                        format_info={"extension": extension or "<none>", "validator": "none"},
                    )
                )

            return labelled(validator.validate(path))

        except Exception as exc:
            # A file that fails its own format checks is an expected outcome,
            # not a programming error: log it concisely.
            LOGGER.warning("validation failed for %s: %s: %s", path, type(exc).__name__, exc)
            return labelled(
                ValidationResult.invalid(
                    f"validation error: {exc}",
                    format_info={"extension": extension or "<none>", "validator": "factory", "checked": True},
                )
            )

    @classmethod
    def validate_path(cls, path: Path) -> ValidationResult:
        return cls.validate_file(path)


class FactoryBackedFormatValidator:
    """
    Adapter for core_analyzer.py.

    Matches the `validate(Path) -> ValidationResult` contract.
    """

    def validate(self, path: Path) -> ValidationResult:
        return FormatValidatorFactory.validate_path(path)


def validate_file(file_path: FilePath) -> ValidationResult:
    return FormatValidatorFactory.validate_file(file_path)


def validate_many(
    file_paths: Iterable[FilePath],
    *,
    max_workers: int | None = None,
) -> dict[str, ValidationResult]:
    """
    Concurrent batch validation.
    Returns a deterministic path->result mapping.
    """

    paths = sorted({_path(file_path) for file_path in file_paths}, key=lambda item: str(item).casefold())
    results: dict[str, ValidationResult] = {}

    worker_count = max_workers if max_workers is not None else min(32, (len(paths) or 1))
    worker_count = max(1, worker_count)

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {executor.submit(validate_file, path): path for path in paths}
        for future in as_completed(futures):
            path = futures[future]
            try:
                results[str(path)] = future.result()
            except Exception as exc:
                LOGGER.exception("batch validation failed for %s", path)
                results[str(path)] = ValidationResult.invalid(
                    f"batch validation error: {exc}",
                    format_info={"extension": path.suffix.lower(), "validator": "batch", "checked": True},
                )

    return dict(sorted(results.items(), key=lambda item: item[0].casefold()))


def get_library_status() -> dict[str, bool]:
    return {
        "Built-in Magic Validator": True,
        "Pillow (Images)": PILLOW_AVAILABLE,
        (f"{PDF_LIBRARY_NAME} (PDFs)" if PYPDF2_AVAILABLE else "pypdf (PDFs)"): PYPDF2_AVAILABLE,
        "python-pptx (PowerPoint)": PPTX_AVAILABLE,
        "ffprobe (Media)": FFPROBE_AVAILABLE,
        "python-docx (Word)": DOCX_AVAILABLE,
        "openpyxl (Excel)": OPENPYXL_AVAILABLE,
    }


class TestFormatValidators(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_zip_validation_success(self) -> None:
        archive_path = self.root / "sample.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("hello.txt", "hello")

        result = validate_file(archive_path)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.format_info["validator"], "zipfile")
        self.assertEqual(result.format_info["file_count"], 1)

    def test_invalid_png_signature(self) -> None:
        image_path = self.root / "broken.png"
        image_path.write_bytes(b"not a png")

        result = validate_file(image_path)
        self.assertFalse(result.is_valid)

    def test_docx_structure_failure(self) -> None:
        docx_path = self.root / "broken.docx"
        with zipfile.ZipFile(docx_path, "w") as archive:
            archive.writestr("not_word/file.txt", "x")

        result = validate_file(docx_path)
        self.assertFalse(result.is_valid)
        self.assertIn("invalid DOCX structure", result.error_message or "")

    def test_unknown_extension_is_not_false_negative(self) -> None:
        binary_path = self.root / "blob.bin"
        binary_path.write_bytes(b"\x00\x01\x02\x03")

        result = validate_file(binary_path)
        self.assertTrue(result.is_valid)
        self.assertFalse(result.format_info["checked"])

    def test_batch_validation_returns_all_paths(self) -> None:
        first = self.root / "a.bin"
        second = self.root / "b.bin"
        first.write_bytes(b"a")
        second.write_bytes(b"b")

        results = validate_many([first, second], max_workers=2)
        self.assertEqual(len(results), 2)
        self.assertIn(str(first.resolve()), results)
        self.assertIn(str(second.resolve()), results)

    def test_library_status_contains_expected_keys(self) -> None:
        status = get_library_status()
        self.assertIn("Built-in Magic Validator", status)
        self.assertIn("Pillow (Images)", status)
        self.assertTrue(any("PDF" in key for key in status), status)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    unittest.main(verbosity=2)