#!/usr/bin/env python3
"""Probe 4: (a) pin down the stdlib-math shadowing trigger, (b) expose the bug
hidden behind it in cie.py --modular-scan."""
import subprocess
import sys
from pathlib import Path

REPO = "/tmp/cie_wt"

print("=" * 74)
print("E. WHEN DOES src/python/math.py SHADOW THE STDLIB?")
print("=" * 74)
cases = {
    "sys.path.insert(0, 'src/python'); import math":      "import sys; sys.path.insert(0,%r); import math; print('   file =', math.__file__)",
    "sys.path.insert(0, 'src/python'); import core_analyzer": "import sys; sys.path.insert(0,%r); import core_analyzer; print('   core_analyzer imported OK')",
    "stdlib math imported FIRST, then shadow path":       "import math; import sys; sys.path.insert(0,%r); import core_analyzer; print('   core_analyzer imported OK, math =', math.__file__)",
}
sp = f"{REPO}/src/python"
for label, code in cases.items():
    r = subprocess.run([sys.executable, "-c", code % sp], capture_output=True, text=True, cwd=REPO)
    status = "OK" if r.returncode == 0 else "FAILS"
    tail = (r.stdout.strip() or r.stderr.strip().splitlines()[-1])[:95]
    print(f"  [{status:<5}] {label}\n            {tail}")

print()
print("=" * 74)
print("F. cie.py --modular-scan: BUG HIDDEN BEHIND THE IMPORT FAILURE")
print("=" * 74)
sys.path.insert(0, REPO)
import math  # noqa: F401  (load stdlib first so cie.py can import at all)
import cie  # noqa: E402

class FakeRuntime:            # stand in for a successful load_runtime()
    class AnalyzerConfig:
        def __init__(self, **kw): pass
    class CorruptionDetector:
        def __init__(self, *a, **k): pass
    core_module = gui_module = None
    CIEMainWindow = None

cie.load_runtime = lambda *, require_gui: FakeRuntime()   # bypass the math.py bug
print("  calling cie.main(['--modular-scan', '/tmp/corpus']) ...")
try:
    code = cie.main(["--modular-scan", "/tmp/corpus"])
    print("  returned:", code)
except Exception as exc:
    print(f"  RAISED {type(exc).__name__}: {exc}")
    import traceback
    tb = traceback.format_exc().strip().splitlines()
    print("  ", tb[-3].strip())
    print("  ", tb[-2].strip())

print()
print("  what the code intends to run:")
print("    os.path.join(os.path.dirname(__file__), 'modular_scanner.py')")
print(f"    -> {REPO}/modular_scanner.py   exists? {Path(REPO, 'modular_scanner.py').exists()}")
print(f"    actual location:              {REPO}/src/python/modular_scanner.py  exists? "
      f"{Path(REPO, 'src/python/modular_scanner.py').exists()}")
