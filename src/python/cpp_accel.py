"""C++ acceleration for the metrics pass (optional, degrades gracefully).

The engine hashes and histogrammes every byte of every scanned file. In pure
Python that loop runs at roughly 20 MB/s; the same work in the C++ core
(`src/cpp/file_analyzer.cpp`, exposed through `src/cpp/cie_accel.cpp`) runs at
100+ MB/s. This module loads that shared library with :mod:`ctypes` and lets
`core_analyzer.MetricsCalculator` drive it chunk by chunk, so:

* Python keeps the file I/O, the error mapping (`OSError` -> `FileAccessError`)
  and the cancellation checks (between chunks, exactly as before);
* C++ does the per-byte work (SHA-256 + 256-bin histogram + byte statistics);
* if the library is missing, was built for another ABI, or fails at runtime,
  the caller falls back to the pure-Python loop and produces identical results.

Nothing here raises on import: `available()` simply returns False when the
library has not been built (`make cpp`).

Build::

    make cpp          # -> build/libcie_accel.so (+ build/file_analyzer)

Overrides for unusual layouts::

    CIE_ACCEL_LIBRARY=/path/to/libcie_accel.so
    CIE_ACCEL_BUILD_DIR=/path/to/build
"""

from __future__ import annotations

import ctypes
import logging
import os
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path

LOGGER = logging.getLogger(__name__)

#: Bump alongside CIE_ACCEL_API_VERSION in src/cpp/cie_accel.cpp.
EXPECTED_API_VERSION = 1

LIBRARY_BASENAMES = ("libcie_accel.so", "libcie_accel.dylib", "cie_accel.dll")
LIBRARY_ENV_VAR = "CIE_ACCEL_LIBRARY"
BUILD_DIR_ENV_VAR = "CIE_ACCEL_BUILD_DIR"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BUILD_DIR = REPO_ROOT / "build"


class AccelUnavailable(RuntimeError):
    """Raised only by the explicit constructors, never by :func:`available`."""


class _Stats(ctypes.Structure):
    """Mirror of ``struct cie_accel_stats`` in src/cpp/cie_accel.cpp."""

    _fields_ = [
        ("size_bytes", ctypes.c_uint64),
        ("null_bytes", ctypes.c_uint64),
        ("printable_bytes", ctypes.c_uint64),
        ("unique_bytes", ctypes.c_uint64),
        ("max_run_length", ctypes.c_uint64),
        ("shannon_entropy", ctypes.c_double),
        ("sha256_hex", ctypes.c_char * 65),
    ]


@dataclass(frozen=True, slots=True)
class AccelStats:
    """Result of hashing one file (or any byte stream) through the C++ core."""

    size_bytes: int
    sha256: str
    shannon_entropy: float
    null_bytes: int = 0
    printable_bytes: int = 0
    unique_bytes: int = 0
    max_run_length: int = 0


def candidate_paths() -> tuple[Path, ...]:
    """Where the library is looked for, in order."""
    paths: list[Path] = []

    override = os.environ.get(LIBRARY_ENV_VAR)
    if override:
        paths.append(Path(override).expanduser())

    build_dir = os.environ.get(BUILD_DIR_ENV_VAR)
    directory = Path(build_dir).expanduser() if build_dir else DEFAULT_BUILD_DIR
    paths.extend(directory / name for name in LIBRARY_BASENAMES)

    return tuple(dict.fromkeys(paths))


def find_library() -> Path | None:
    """Return the first existing library path, or None."""
    for path in candidate_paths():
        try:
            if path.is_file():
                return path
        except OSError:  # unreadable directory, permission problems, ...
            continue
    return None


_LIBRARY: ctypes.CDLL | None = None
_LIBRARY_LOADED = False
_LIBRARY_ERROR: str | None = None


def load_library() -> ctypes.CDLL | None:
    """Load (once) and return the acceleration library, or None."""
    global _LIBRARY, _LIBRARY_LOADED, _LIBRARY_ERROR

    if _LIBRARY_LOADED:
        return _LIBRARY

    _LIBRARY_LOADED = True
    path = find_library()
    if path is None:
        _LIBRARY_ERROR = "not built (run 'make cpp')"
        return None

    try:
        library = ctypes.CDLL(str(path))
        library.cie_accel_api_version.restype = ctypes.c_int
        library.cie_accel_api_version.argtypes = []
        version = library.cie_accel_api_version()
        if version != EXPECTED_API_VERSION:
            _LIBRARY_ERROR = f"ABI mismatch: library reports v{version}, expected v{EXPECTED_API_VERSION}"
            LOGGER.warning("ignoring %s - %s (rebuild with 'make cpp')", path, _LIBRARY_ERROR)
            return None

        library.cie_accel_ctx_create.restype = ctypes.c_void_p
        library.cie_accel_ctx_create.argtypes = []
        library.cie_accel_ctx_update.restype = ctypes.c_int
        library.cie_accel_ctx_update.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
        library.cie_accel_ctx_finish.restype = ctypes.c_int
        library.cie_accel_ctx_finish.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Stats)]
        library.cie_accel_ctx_free.restype = None
        library.cie_accel_ctx_free.argtypes = [ctypes.c_void_p]
        library.cie_accel_selftest.restype = ctypes.c_int
        library.cie_accel_selftest.argtypes = []
    except (OSError, AttributeError) as exc:
        _LIBRARY_ERROR = f"could not load {path}: {exc}"
        LOGGER.warning("%s", _LIBRARY_ERROR)
        return None

    _LIBRARY = library
    _LIBRARY_ERROR = None
    return _LIBRARY


def library_path() -> Path | None:
    return find_library()


def available() -> bool:
    """True when the C++ core can be used. Never raises."""
    return load_library() is not None


def unavailable_reason() -> str:
    """Human-readable explanation for `available() is False`."""
    if load_library() is not None:
        return ""
    return _LIBRARY_ERROR or "unavailable"


def selftest() -> int:
    """Run the library's own checks; 0 means it agrees with known values.

    Returns ``-1`` when the library is not available at all.
    """
    library = load_library()
    if library is None:
        return -1
    return int(library.cie_accel_selftest())


class AccelHasher:
    """Chunk-driven SHA-256 + byte statistics, computed by the C++ core.

    Usage::

        with AccelHasher() as hasher:
            for chunk in chunks:
                hasher.update(chunk)
            stats = hasher.finish()
    """

    __slots__ = ("_library", "_context")

    def __init__(self, library: ctypes.CDLL | None = None) -> None:
        self._library = library if library is not None else load_library()
        if self._library is None:
            raise AccelUnavailable(unavailable_reason())

        self._context = self._library.cie_accel_ctx_create()
        if not self._context:
            raise AccelUnavailable("cie_accel_ctx_create() returned NULL")

    def update(self, chunk: bytes) -> None:
        if self._context is None:
            raise AccelUnavailable("hasher is closed")
        # ctypes keeps the bytes object alive for the duration of the call; NUL
        # bytes are fine because the length is passed explicitly.
        status = self._library.cie_accel_ctx_update(self._context, chunk, len(chunk))
        if status != 0:
            raise AccelUnavailable(f"cie_accel_ctx_update() failed with status {status}")

    def finish(self) -> AccelStats:
        if self._context is None:
            raise AccelUnavailable("hasher is closed")

        stats = _Stats()
        status = self._library.cie_accel_ctx_finish(self._context, ctypes.byref(stats))
        if status != 0:
            raise AccelUnavailable(f"cie_accel_ctx_finish() failed with status {status}")

        return AccelStats(
            size_bytes=int(stats.size_bytes),
            sha256=stats.sha256_hex.decode("ascii"),
            shannon_entropy=float(stats.shannon_entropy),
            null_bytes=int(stats.null_bytes),
            printable_bytes=int(stats.printable_bytes),
            unique_bytes=int(stats.unique_bytes),
            max_run_length=int(stats.max_run_length),
        )

    def close(self) -> None:
        if self._context is not None:
            self._library.cie_accel_ctx_free(self._context)
            self._context = None

    def __enter__(self) -> "AccelHasher":
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - interpreter shutdown safety
        try:
            self.close()
        except Exception:
            pass


def hash_bytes(data: bytes, chunk_size: int = 1 << 16) -> AccelStats:
    """Convenience wrapper used by the tests and the self-test."""
    with AccelHasher() as hasher:
        for start in range(0, max(len(data), 1), max(1, chunk_size)):
            hasher.update(data[start:start + chunk_size])
        return hasher.finish()


# ==============================================================================
# SELF-TEST
# ==============================================================================

class TestCppAccel(unittest.TestCase):
    """Self-checks: `python3 cpp_accel.py` (also covered by tests/test_cpp_accel.py)."""

    def setUp(self) -> None:
        if not available():
            self.skipTest(f"C++ acceleration library not available: {unavailable_reason()}")

    def test_library_selftest_passes(self) -> None:
        self.assertEqual(selftest(), 0, "the C++ core failed its own checks")

    def test_known_sha256(self) -> None:
        import hashlib

        stats = hash_bytes(b"abc")
        self.assertEqual(stats.sha256, hashlib.sha256(b"abc").hexdigest())
        self.assertEqual(stats.size_bytes, 3)

    def test_matches_python_entropy(self) -> None:
        import hashlib
        import math

        data = bytes(range(256)) * 40
        stats = hash_bytes(data)
        self.assertEqual(stats.sha256, hashlib.sha256(data).hexdigest())
        self.assertAlmostEqual(stats.shannon_entropy, math.log2(256), places=12)
        self.assertEqual(stats.unique_bytes, 256)

    def test_chunking_does_not_change_the_digest(self) -> None:
        import hashlib

        data = bytes(range(256)) * 300
        whole = hash_bytes(data, chunk_size=len(data))
        split = hash_bytes(data, chunk_size=7)
        self.assertEqual(whole.sha256, split.sha256)
        self.assertEqual(whole.sha256, hashlib.sha256(data).hexdigest())

    def test_empty_input(self) -> None:
        stats = hash_bytes(b"")
        self.assertEqual(
            stats.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        self.assertEqual(stats.size_bytes, 0)
        self.assertEqual(stats.shannon_entropy, 0.0)


def main(argv: list[str] | None = None) -> int:
    print(f"C++ acceleration library : {library_path() or 'not built (run make cpp)'}")
    if not available():
        print(f"status                   : unavailable ({unavailable_reason()})")
        return 1
    result = selftest()
    print(f"C++ core self-test       : {'OK' if result == 0 else f'FAILED ({result})'}")

    runner = unittest.main(argv=[sys.argv[0], *(argv or [])], exit=False)
    failed = not runner.result.wasSuccessful()
    return 0 if (result == 0 and not failed) else 1


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    raise SystemExit(main())
