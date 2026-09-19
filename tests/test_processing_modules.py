"""Tests for the modular processor pipeline.

The audit's headline false positive lived here: a 70% non-ASCII rule flagged
every CJK, Devanagari, emoji and UTF-16 file as corrupted. Encoding tests below
are the regression guard.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from src.python.processing_modules import (
    BasicFileProcessor,
    NullBytePatternProcessor,
    ProcessorFactory,
    StructureValidatorProcessor,
    TextEncodingProcessor,
    decode_as_text,
)


# ---------------------------------------------------------------------------
# text encodings
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,text,encoding", [
    ("plain.txt", "Ordinary ASCII text.\n" * 40, "utf-8"),
    ("hindi.md", "यह एक हिंदी ब्लॉग पोस्ट है। यह मान्य यूनिकोड है।\n" * 20, "utf-8"),
    ("chinese.txt", "这是一份完全有效的中文文本文件。" * 40, "utf-8"),
    ("japanese.md", "これは完全に有効な日本語のテキストファイルです。" * 40, "utf-8"),
    ("russian.txt", "Это полностью корректный текстовый файл.\n" * 30, "utf-8"),
    ("arabic.txt", "هذا ملف نصي صالح تمامًا.\n" * 30, "utf-8"),
    ("emoji.txt", "Great work team! 🎉🚀✨🔥💡📈 " * 100, "utf-8"),
    ("bom.json", '{"name": "café"}', "utf-8-sig"),
    ("utf16_notes.txt", "Meeting notes: revenue up 12%.\n" * 20, "utf-16"),
    ("utf16_export.csv", "id,name,amount\n1,Widget,100\n" * 20, "utf-16"),
])
def test_valid_text_encodings_are_not_corrupt(tmp_path, name, text, encoding):
    path = tmp_path / name
    path.write_bytes(text.encode(encoding))
    processor = ProcessorFactory.create_balanced_processor()
    result = processor.process_files((path,))[0]
    assert result.is_corrupted is False, f"{name} flagged: {result.error_message}"


def test_genuinely_binary_text_is_flagged(tmp_path):
    path = tmp_path / "broken.txt"
    path.write_bytes(b"\x00\xff\x80" * 300)
    result = ProcessorFactory.create_balanced_processor().process_files((path,))[0]
    assert result.is_corrupted is True


def test_decode_as_text_accepts_utf16_and_rejects_noise():
    assert decode_as_text("hello world".encode("utf-16")) in {"utf-16-le", "utf-16-be", "utf-8-sig", "utf-8"}
    assert decode_as_text(b"\x00\xff\x80" * 300) is None
    assert decode_as_text(b"") is None


def test_decode_as_text_accepts_utf8_bom():
    assert decode_as_text("café".encode("utf-8-sig")) in {"utf-8-sig", "utf-8"}


# ---------------------------------------------------------------------------
# other processors
# ---------------------------------------------------------------------------

def test_empty_file_is_not_corrupt(tmp_path):
    path = tmp_path / "empty.txt"
    path.write_bytes(b"")
    result = ProcessorFactory.create_balanced_processor().process_files((path,))[0]
    assert result.is_corrupted is False
    assert "empty file" in " ".join(result.details)


def test_null_heavy_file_is_flagged(tmp_path):
    path = tmp_path / "nulls.bin"
    path.write_bytes(b"\x00" * 4096)
    result = ProcessorFactory.create_fast_processor().process_files((path,))[0]
    assert result.is_corrupted is True


def test_bad_image_header_is_flagged(tmp_path):
    path = tmp_path / "bad.jpg"
    path.write_bytes(b"not a jpeg at all")
    result = ProcessorFactory.create_balanced_processor().process_files((path,))[0]
    assert result.is_corrupted is True


def test_structure_processor_catches_corrupt_pdf(tmp_path):
    path = tmp_path / "broken.pdf"
    path.write_bytes(b"%PDF-1.4 but no end marker")
    result = StructureValidatorProcessor(full=True).process(path)
    assert result.is_corrupted is True


def test_basic_processor_computes_real_checksum(tmp_path):
    import hashlib

    path = tmp_path / "data.bin"
    payload = b"checksum me" * 100
    path.write_bytes(payload)
    result = BasicFileProcessor(text=None) if False else BasicFileProcessor().process(path)
    assert result.checksum == hashlib.sha256(payload).hexdigest()
    assert result.file_size == len(payload)


def test_sampled_hash_is_labelled(tmp_path):
    path = tmp_path / "big.bin"
    path.write_bytes(os.urandom(4096))
    result = BasicFileProcessor(max_hashed_bytes=1024).process(path)
    assert result.checksum.startswith("sampled:")
    assert any("sampled" in detail for detail in result.details)


# ---------------------------------------------------------------------------
# strategies agree with each other
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("strategy", ["fast", "balanced", "deep"])
def test_strategies_agree_on_a_real_corpus(tmp_path, strategy):
    """Same files, three strategies: verdicts must not contradict each other."""
    import io

    Image = pytest.importorskip("PIL.Image")
    buffer = io.BytesIO()
    Image.new("RGB", (32, 32), (1, 2, 3)).save(buffer, "PNG")
    real_png = buffer.getvalue()

    files = {
        "valid.png": real_png,
        "fake.png": b"not a png",
        "broken.pdf": b"%PDF-1.4 without eof",
        "notes.txt": "text\n".encode(),
    }
    paths = []
    for name, content in files.items():
        path = tmp_path / name
        path.write_bytes(content)
        paths.append(path)

    factory = getattr(ProcessorFactory, f"create_{strategy}_processor")
    results = {Path(r.file_path).name: r.is_corrupted for r in factory().process_files(tuple(paths))}

    assert results["valid.png"] is False
    assert results["fake.png"] is True
    assert results["broken.pdf"] is True
    assert results["notes.txt"] is False


def test_results_are_deterministic(tmp_path):
    paths = []
    for name in ("b.txt", "a.txt", "c.txt"):
        path = tmp_path / name
        path.write_text("content")
        paths.append(path)
    processor = ProcessorFactory.create_fast_processor()
    first = [r.file_path for r in processor.process_files(tuple(reversed(paths)))]
    second = [r.file_path for r in processor.process_files(tuple(paths))]
    assert first == second == sorted(first)


def test_performance_stats_are_sane(tmp_path):
    path = tmp_path / "text.txt"
    path.write_text("hello world")
    processor = ProcessorFactory.create_fast_processor()
    results = processor.process_files((path,))
    stats = processor.get_performance_stats(results)
    assert stats["total_files"] == 1
    assert stats["files_per_second"] > 0
    assert stats["processors_used"] >= 1


def test_custom_processor_requires_processors():
    with pytest.raises(ValueError):
        ProcessorFactory.create_custom_processor([])


def test_custom_processor_works(tmp_path):
    path = tmp_path / "sample.txt"
    path.write_text("hello")
    processor = ProcessorFactory.create_custom_processor([TextEncodingProcessor()], name="text-only")
    results = processor.process_files((path,))
    assert len(results) == 1
    assert results[0].checksum


def test_null_byte_processor_bounds_are_clamped():
    processor = NullBytePatternProcessor(null_ratio_threshold=5.0)
    assert processor.null_ratio_threshold == 1.0
    processor = NullBytePatternProcessor(null_ratio_threshold=-1.0)
    assert processor.null_ratio_threshold == 0.0
