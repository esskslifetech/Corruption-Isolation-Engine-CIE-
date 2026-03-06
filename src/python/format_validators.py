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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
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

try:
    import PyPDF2
    PYPDF2_AVAILABLE = True
except ImportError:  # pragma: no cover
    PyPDF2 = None  # type: ignore[assignment]
    PYPDF2_AVAILABLE = False

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

FFPROBE_AVAILABLE = shutil.which("ffprobe") is not None


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Immutable file validation result."""

    is_valid: bool
    error_message: str | None = None
    format_info: dict[str, Any] = field(default_factory=dict)
    corruption_details: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def ok(
        cls,
        *,
        format_info: dict[str, Any] | None = None,
        corruption_details: Iterable[str] = (),
    ) -> "ValidationResult":
        return cls(
            is_valid=True,
            error_message=None,
            format_info=dict(format_info or {}),
            corruption_details=tuple(corruption_details),
        )

    @classmethod
    def invalid(
        cls,
        error_message: str,
        *,
        format_info: dict[str, Any] | None = None,
        corruption_details: Iterable[str] = (),
    ) -> "ValidationResult":
        return cls(
            is_valid=False,
            error_message=error_message,
            format_info=dict(format_info or {}),
            corruption_details=tuple(corruption_details),
        )

    @classmethod
    def unchecked(
        cls,
        *,
        reason: str,
        format_info: dict[str, Any] | None = None,
    ) -> "ValidationResult":
        payload = dict(format_info or {})
        payload["checked"] = False
        payload["reason"] = reason
        return cls(
            is_valid=True,
            error_message=None,
            format_info=payload,
            corruption_details=(),
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


class MagicSignatureValidator:
    """Fallback validator using structural signatures."""

    _SIGNATURES: dict[str, tuple[tuple[int, bytes], ...]] = {
        ".png": ((0, b"\x89PNG\r\n\x1a\n"),),
        ".jpg": ((0, b"\xff\xd8\xff"),),
        ".jpeg": ((0, b"\xff\xd8\xff"),),
        ".gif": ((0, b"GIF87a"), (0, b"GIF89a")),
        ".bmp": ((0, b"BM"),),
        ".tiff": ((0, b"II*\x00"), (0, b"MM\x00*")),
        ".webp": ((0, b"RIFF"), (8, b"WEBP")),
        ".ico": ((0, b"\x00\x00\x01\x00"),),
        ".pdf": ((0, b"%PDF-"),),
        ".zip": ((0, b"PK\x03\x04"), (0, b"PK\x05\x06"), (0, b"PK\x07\x08")),
        ".jar": ((0, b"PK\x03\x04"),),
        ".apk": ((0, b"PK\x03\x04"),),
        ".exe": ((0, b"MZ"),),
        ".elf": ((0, b"\x7fELF"),),
        ".wav": ((0, b"RIFF"), (8, b"WAVE")),
        ".avi": ((0, b"RIFF"), (8, b"AVI ")),
        ".mp4": ((4, b"ftyp"),),
    }

    def validate(self, file_path: FilePath) -> ValidationResult:
        path = _path(file_path)
        extension = path.suffix.lower()
        signatures = self._SIGNATURES.get(extension)

        if not signatures:
            return ValidationResult.unchecked(
                reason="no magic signature validator available",
                format_info={"extension": extension or "<none>", "validator": "magic"},
            )

        max_required = max(offset + len(signature) for offset, signature in signatures)
        try:
            prefix = _read_prefix(path, max_required)
        except OSError as exc:
            return ValidationResult.invalid(
                f"failed to read file header: {exc}",
                format_info={"extension": extension, "validator": "magic"},
            )

        for signature_group in signatures:
            offset, signature = signature_group
            if prefix[offset:offset + len(signature)] == signature:
                return ValidationResult.ok(
                    format_info={
                        "extension": extension,
                        "validator": "magic",
                        "checked": True,
                    }
                )

        return ValidationResult.invalid(
            f"{extension or 'file'} signature mismatch",
            format_info={"extension": extension, "validator": "magic", "checked": True},
            corruption_details=("file header does not match expected magic signature",),
        )


class ImageValidator:
    """Image validation with Pillow and magic-signature fallback."""

    _MAGIC_FALLBACK = MagicSignatureValidator()

    def validate(self, file_path: FilePath) -> ValidationResult:
        path = _path(file_path)
        extension = path.suffix.lower()

        if not PILLOW_AVAILABLE:
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
                    }
                )

        except UnidentifiedImageError as exc:
            return ValidationResult.invalid(
                f"unidentifiable image: {exc}",
                format_info={"extension": extension, "validator": "pillow", "checked": True},
            )
        except OSError as exc:
            return ValidationResult.invalid(
                f"image validation error: {exc}",
                format_info={"extension": extension, "validator": "pillow", "checked": True},
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
                        "validator": "pypdf2",
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
                    format_info={"extension": extension, "validator": "pypdf2", "checked": True},
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
                return ValidationResult.invalid(
                    f"DOCX validation error: {exc}",
                    format_info={"extension": ".docx", "validator": "python-docx", "checked": True},
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
                    f"XLSX validation error: {exc}",
                    format_info={"extension": ".xlsx", "validator": "openpyxl", "checked": True},
                )
            finally:
                if workbook is not None:
                    workbook.close()

        return ValidationResult.ok(format_info=format_info)


class MediaValidator:
    """Media validation through ffprobe."""

    def validate(self, file_path: FilePath) -> ValidationResult:
        path = _path(file_path)
        extension = path.suffix.lower()

        if not FFPROBE_AVAILABLE:
            return ValidationResult.unchecked(
                reason="ffprobe not available",
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

    _IMAGE_EXTENSIONS = frozenset({".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp", ".ico"})
    _PDF_EXTENSIONS = frozenset({".pdf"})
    _ARCHIVE_EXTENSIONS = frozenset({".zip", ".jar", ".apk"})
    _MEDIA_EXTENSIONS = frozenset({".mp4", ".avi", ".mov", ".mkv", ".mp3", ".wav", ".flac", ".aac", ".ogg", ".webm"})
    _DOCX_EXTENSIONS = frozenset({".docx"})
    _XLSX_EXTENSIONS = frozenset({".xlsx"})

    @classmethod
    def get_validator(cls, file_path: FilePath) -> SupportsValidation | None:
        extension = _path(file_path).suffix.lower()

        if extension in cls._IMAGE_EXTENSIONS:
            return cls._image_validator
        if extension in cls._PDF_EXTENSIONS:
            return cls._pdf_validator
        if extension in cls._ARCHIVE_EXTENSIONS:
            return cls._archive_validator
        if extension in cls._MEDIA_EXTENSIONS:
            return cls._media_validator
        if extension in cls._DOCX_EXTENSIONS:
            return cls
        if extension in cls._XLSX_EXTENSIONS:
            return cls
        if extension in MagicSignatureValidator._SIGNATURES:
            return cls._magic_validator

        return None

    @classmethod
    def validate_file(cls, file_path: FilePath) -> ValidationResult:
        path = _path(file_path)
        extension = path.suffix.lower()

        try:
            if extension in cls._DOCX_EXTENSIONS:
                return cls._document_validator.validate_docx(path)
            if extension in cls._XLSX_EXTENSIONS:
                return cls._document_validator.validate_xlsx(path)

            validator = cls.get_validator(path)
            if validator is None:
                return ValidationResult.unchecked(
                    reason="no specific validator available",
                    format_info={"extension": extension or "<none>", "validator": "none"},
                )

            return validator.validate(path)

        except Exception as exc:
            LOGGER.exception("validation error for %s", path)
            return ValidationResult.invalid(
                f"validation error: {exc}",
                format_info={"extension": extension or "<none>", "validator": "factory", "checked": True},
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
        "PyPDF2 (PDFs)": PYPDF2_AVAILABLE,
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
        self.assertIn("PyPDF2 (PDFs)", status)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    unittest.main(verbosity=2)