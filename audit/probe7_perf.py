#!/usr/bin/env python3
"""Probe 7: throughput of the Python engine vs the C++ engine on identical data."""
import os
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path("/tmp/cie_wt")
sys.path.append(str(REPO / "src" / "python"))
import math  # noqa: F401
from core_analyzer import AnalyzerConfig, CorruptionDetector  # noqa: E402

PDF = Path("/tmp/perfdata")
if PDF.exists():
    shutil.rmtree(PDF)
PDF.mkdir(parents=True)
random.seed(7)
TOTAL = 100 * 1024 * 1024        # 100 MB across 20 files
PER = TOTAL // 20
print(f"building {TOTAL/1048576:.0f} MB ({PER/1048576:.0f} MB x 20 files) ...")
payload = os.urandom(PER)
for i in range(20):
    (PDF / f"blob_{i:02d}.bin").write_bytes(payload)

WORK = Path("/tmp/perfwork")

from core_analyzer import CorruptionDetector  # noqa: E402


def run_python(use_cpp_accel: bool = True):
    if WORK.exists():
        shutil.rmtree(WORK)
    det = CorruptionDetector(
        AnalyzerConfig(
            db_path=str(WORK / "cie.db"),
            quarantine_dir=str(WORK / "q"),
            use_cpp_accel=use_cpp_accel,
        )
    )
    backend = "unknown"
    try:
        backend = det._engine._calculator.backend
    except Exception:
        pass
    t0 = time.perf_counter()
    res = det.scan_directory(PDF, recursive=True)
    return time.perf_counter() - t0, len(res), backend

print("\n" + "=" * 74)
print("J. PYTHON ENGINE THROUGHPUT (core_analyzer, the real CLI engine)")
print("=" * 74)
py_times = []
backend = "unknown"
for i in range(2):
    dt, n, backend = run_python(use_cpp_accel=True)
    py_times.append(dt)
    print(f"   run {i+1}: {dt:6.2f} s for {n} files -> {TOTAL/1048576/dt:6.2f} MB/s   ({n/dt:6.2f} files/s)  [backend: {backend}]")

pure_times = []
for i in range(2):
    dt, n, _ = run_python(use_cpp_accel=False)
    pure_times.append(dt)
    print(f"   pure-Python fallback run {i+1}: {dt:6.2f} s -> {TOTAL/1048576/dt:6.2f} MB/s")

print("\n" + "=" * 74)
print("K. C++ ENGINE THROUGHPUT (same files, built with -std=c++20)")
print("=" * 74)
cxx = "/tmp/cie_cpp20"
if not Path(cxx).exists():
    subprocess.run(["g++", "-std=c++20", "-O2", str(REPO / "src/cpp/file_analyzer.cpp"), "-o", cxx], check=True)
for i in range(2):
    t0 = time.perf_counter()
    r = subprocess.run([cxx, str(PDF), "--no-duplicates"], capture_output=True, text=True)
    dt = time.perf_counter() - t0
    print(f"   run {i+1}: {dt:6.2f} s -> {TOTAL/1048576/dt:6.2f} MB/s")

print("\n" + "=" * 74)
print("L. VERDICT")
print("=" * 74)
best_py = min(py_times)
best_pure = min(pure_times)
t0 = time.perf_counter(); subprocess.run([cxx, str(PDF), "--no-duplicates"], capture_output=True); best_cxx = time.perf_counter() - t0
print(f"   Python engine (backend: {backend}) : {TOTAL/1048576/best_py:6.2f} MB/s")
print(f"   Python engine (pure Python)        : {TOTAL/1048576/best_pure:6.2f} MB/s")
print(f"   standalone C++ analyzer            : {TOTAL/1048576/best_cxx:6.2f} MB/s")
if backend == "cpp":
    print(f"   -> OK: the Python application now calls the C++ core "
          f"({best_pure/best_py:.1f}x faster than the pure-Python path);")
    print("      the pure-Python implementation remains as the fallback when the")
    print("      library is not built.")
else:
    print("   -> the Python engine is still using the pure-Python metrics path")
    print("      (build/libcie_accel.so missing? run 'make cpp').")
