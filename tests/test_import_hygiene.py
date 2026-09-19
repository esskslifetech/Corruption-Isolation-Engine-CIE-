"""Regression tests for the module-loading bugs found in the v2.0 audit.

The original code put `src/python` on sys.path, where `math.py` shadowed the
standard library and broke every entry point. These tests fail loudly if that
(or a similar import-order trap) ever comes back.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PY_SRC = REPO_ROOT / "src" / "python"


def run_python(script: str, *, cwd: Path | None = None,
               args: tuple[str, ...] = ()) -> subprocess.CompletedProcess:
    """Run a Python file (not -c) so relative imports behave as at the CLI."""
    return subprocess.run(
        [sys.executable, script, *args],
        cwd=str(cwd or REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )


def run_snippet(code: str, *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run an inline snippet with -c."""
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(cwd or REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_no_module_shadows_a_stdlib_name():
    """No file in src/python may collide with a standard-library module name."""
    stdlib_names = set(sys.stdlib_module_names)
    offenders = sorted(
        path.stem
        for path in PY_SRC.glob("*.py")
        if path.stem in stdlib_names
    )
    assert offenders == [], (
        f"{offenders} shadow the Python standard library; rename them "
        "(this is exactly what broke `python3 cie.py --scan`)"
    )


def test_core_analyzer_imports_with_src_python_first_on_path():
    """The original failure mode: src/python at sys.path[0]."""
    result = run_snippet(
        "import sys;"
        f"sys.path.insert(0, {str(PY_SRC)!r});"
        "import core_analyzer;"
        "print('ok')"
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout


def test_every_source_module_imports_standalone():
    """Each module must import with its own directory on sys.path."""
    modules = [p.stem for p in sorted(PY_SRC.glob("*.py"))]
    code = (
        "import sys, importlib;"
        f"sys.path.insert(0, {str(PY_SRC)!r});"
        f"mods = {modules!r};"
        "[importlib.import_module(m) for m in mods];"
        "print('ok')"
    )
    result = run_snippet(code)
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout


def test_modules_import_from_source_directory_directly():
    """Running from inside src/python must work too (no package context)."""
    result = run_snippet(
        "import core_analyzer, processing_modules, modular_scanner, format_validators, cie_math;"
        "print('ok')",
        cwd=PY_SRC,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "module",
    ["core_analyzer", "processing_modules", "format_validators", "cie_math", "cpp_accel"],
)
def test_module_selftest_suites_pass(module: str):
    """Every module with a __main__ self-test block must pass it."""
    result = run_python(f"{module}.py", cwd=PY_SRC)
    if result.returncode != 0 and "runpy" in result.stderr:
        pytest.skip(f"{module} has no self-test block")
    assert result.returncode == 0, result.stdout + result.stderr


def test_cie_entrypoint_imports_runtime():
    """`--library-status` exercises the real runtime import path."""
    result = subprocess.run(
        [sys.executable, "cie.py", "--library-status"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Bibli" in result.stdout or "Library" in result.stdout
