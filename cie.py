#!/usr/bin/env python3
"""
Main entry point for Corruption Isolation Engine (CIE)
Provides command-line interface and launches GUI

This Project Is Made By Kanishk Soni
- Command-line scanning
- JSON or text reporting
- Configurable analyzer settings
- Optional quarantine of corrupted files
- Import self-checks and lightweight self-tests
"""

from __future__ import annotations

import argparse
import importlib
import json
import logging
import sys
import unittest
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Protocol, Sequence

APP_NAME = "Corruption Isolation Engine"
APP_VERSION = "2.0"

LOGGER = logging.getLogger(__name__)


# ==============================================================================
# 1. RUNTIME CONTRACTS
# ==============================================================================

class FormatValidationLike(Protocol):
    is_valid: bool
    error_message: str | None
    format_info: Any
    corruption_details: Any


class FileAnalysisResultLike(Protocol):
    file_path: str
    file_size: int
    file_type: str | None
    checksum: str | None
    error_message: str | None
    is_corrupted: bool
    status: Any
    format_validation: FormatValidationLike | None
    shannon_entropy: float


@dataclass(frozen=True, slots=True)
class RuntimeBundle:
    core_module: ModuleType
    gui_module: ModuleType | None
    CorruptionDetector: type[Any]
    AnalyzerConfig: type[Any]
    CIEMainWindow: type[Any] | None


@dataclass(frozen=True, slots=True)
class ScanSummary:
    total_files: int
    corrupted_files: int
    healthy_files: int
    total_bytes: int
    unreadable_files: int
    largest_file_bytes: int
    corruption_rate_percent: float
    top_file_types: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class QuarantineSummary:
    attempted: int = 0
    succeeded: int = 0
    failed: int = 0


# ==============================================================================
# 2. IMPORT BOOTSTRAP
# ==============================================================================

def _configure_import_paths() -> Path:
    project_root = Path(__file__).resolve().parent
    src_dir = project_root / "src"
    extra_paths = (src_dir, src_dir / "python", src_dir / "gui")

    for path in extra_paths:
        if path.exists():
            path_text = str(path)
            if path_text not in sys.path:
                sys.path.insert(0, path_text)

    return project_root


def _import_first(module_names: Sequence[str]) -> ModuleType:
    last_error: Exception | None = None

    for module_name in module_names:
        try:
            return importlib.import_module(module_name)
        except Exception as exc:
            last_error = exc

    names = ", ".join(module_names)
    raise ImportError(f"failed to import any of: {names}") from last_error


def load_runtime(*, require_gui: bool) -> RuntimeBundle:
    _configure_import_paths()

    core_module = _import_first(("python.core_analyzer", "core_analyzer"))

    gui_module: ModuleType | None = None
    if require_gui:
        gui_module = _import_first(("gui.main_window", "main_window"))

    CorruptionDetector = getattr(core_module, "CorruptionDetector")
    AnalyzerConfig = getattr(core_module, "AnalyzerConfig")
    CIEMainWindow = getattr(gui_module, "CIEMainWindow") if gui_module is not None else None

    return RuntimeBundle(
        core_module=core_module,
        gui_module=gui_module,
        CorruptionDetector=CorruptionDetector,
        AnalyzerConfig=AnalyzerConfig,
        CIEMainWindow=CIEMainWindow,
    )


# ==============================================================================
# 3. PURE REPORTING HELPERS
# ==============================================================================

def format_bytes(size_bytes: int) -> str:
    size = float(max(0, size_bytes))
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    index = 0

    while size >= 1024.0 and index < len(units) - 1:
        size /= 1024.0
        index += 1

    if index == 0:
        return f"{int(size)} {units[index]}"
    return f"{size:.2f} {units[index]}"


def status_name(result: FileAnalysisResultLike) -> str:
    status = getattr(result, "status", None)
    if status is None:
        return "UNKNOWN"
    return getattr(status, "name", str(status))


def file_type_name(result: FileAnalysisResultLike) -> str:
    return str(getattr(result, "file_type", None) or "Unknown")


def result_path(result: FileAnalysisResultLike) -> str:
    return str(getattr(result, "file_path", "") or "")


def format_status(result: FileAnalysisResultLike) -> str:
    validation = getattr(result, "format_validation", None)
    if validation is None:
        return "N/A"
    return "Valid" if bool(getattr(validation, "is_valid", False)) else "Invalid"


def result_to_dict(result: FileAnalysisResultLike) -> dict[str, Any]:
    validation = getattr(result, "format_validation", None)

    if validation is None:
        validation_payload: dict[str, Any] | None = None
    else:
        raw_format_info = getattr(validation, "format_info", None)
        raw_corruption_details = getattr(validation, "corruption_details", None)

        format_info: Any
        if isinstance(raw_format_info, dict):
            format_info = dict(raw_format_info)
        else:
            format_info = raw_format_info

        corruption_details: list[str]
        if raw_corruption_details is None:
            corruption_details = []
        else:
            corruption_details = [str(item) for item in raw_corruption_details]

        validation_payload = {
            "is_valid": bool(getattr(validation, "is_valid", False)),
            "error_message": getattr(validation, "error_message", None),
            "format_info": format_info,
            "corruption_details": corruption_details,
        }

    return {
        "file_path": result_path(result),
        "file_size": int(getattr(result, "file_size", 0) or 0),
        "file_type": file_type_name(result),
        "checksum": str(getattr(result, "checksum", "") or ""),
        "status": status_name(result),
        "is_corrupted": bool(getattr(result, "is_corrupted", False)),
        "error_message": getattr(result, "error_message", None),
        "format_status": format_status(result),
        "shannon_entropy": float(getattr(result, "shannon_entropy", 0.0) or 0.0),
        "format_validation": validation_payload,
    }


def build_summary(results: Sequence[FileAnalysisResultLike]) -> ScanSummary:
    total_files = len(results)
    corrupted_files = sum(1 for result in results if bool(getattr(result, "is_corrupted", False)))
    healthy_files = total_files - corrupted_files
    total_bytes = sum(int(getattr(result, "file_size", 0) or 0) for result in results)
    unreadable_files = sum(1 for result in results if status_name(result) == "UNREADABLE")
    largest_file_bytes = max((int(getattr(result, "file_size", 0) or 0) for result in results), default=0)
    corruption_rate_percent = (corrupted_files / total_files * 100.0) if total_files else 0.0

    type_counts = Counter(file_type_name(result) for result in results)

    return ScanSummary(
        total_files=total_files,
        corrupted_files=corrupted_files,
        healthy_files=healthy_files,
        total_bytes=total_bytes,
        unreadable_files=unreadable_files,
        largest_file_bytes=largest_file_bytes,
        corruption_rate_percent=corruption_rate_percent,
        top_file_types=tuple(sorted(type_counts.items(), key=lambda item: (-item[1], item[0]))),
    )


def build_text_report(
    results: Sequence[FileAnalysisResultLike],
    summary: ScanSummary,
    *,
    verbose: bool,
    summary_only: bool,
    quarantine_summary: QuarantineSummary | None = None,
) -> str:
    lines = [
        f"{APP_NAME} Report",
        "=" * (len(APP_NAME) + 7),
        f"Generated at       : {datetime.now(timezone.utc).isoformat()}",
        f"Total files        : {summary.total_files}",
        f"Corrupted files    : {summary.corrupted_files}",
        f"Healthy files      : {summary.healthy_files}",
        f"Unreadable files   : {summary.unreadable_files}",
        f"Total bytes        : {summary.total_bytes:,} ({format_bytes(summary.total_bytes)})",
        f"Largest file       : {summary.largest_file_bytes:,} ({format_bytes(summary.largest_file_bytes)})",
        f"Corruption rate    : {summary.corruption_rate_percent:.2f}%",
    ]

    if quarantine_summary is not None and quarantine_summary.attempted > 0:
        lines.extend(
            (
                f"Quarantine tried   : {quarantine_summary.attempted}",
                f"Quarantine success : {quarantine_summary.succeeded}",
                f"Quarantine failed  : {quarantine_summary.failed}",
            )
        )

    if summary.top_file_types:
        lines.append("")
        lines.append("Top File Types")
        lines.append("--------------")
        for file_type, count in summary.top_file_types[:10]:
            lines.append(f"{file_type:<20} {count}")

    if summary_only:
        return "\n".join(lines) + "\n"

    sorted_results = sorted(results, key=lambda item: result_path(item).casefold())
    visible_results = sorted_results if verbose else [result for result in sorted_results if result.is_corrupted]

    lines.append("")
    lines.append("Detailed Results")
    lines.append("----------------")

    if not visible_results:
        lines.append("No corrupted files detected.")
        return "\n".join(lines) + "\n"

    for result in visible_results:
        lines.append(f"[{status_name(result)}] {result_path(result)}")
        lines.append(f"  Size           : {int(getattr(result, 'file_size', 0) or 0):,} bytes")
        lines.append(f"  Type           : {file_type_name(result)}")
        lines.append(f"  Checksum       : {str(getattr(result, 'checksum', '') or 'N/A')}")
        lines.append(f"  Entropy        : {float(getattr(result, 'shannon_entropy', 0.0) or 0.0):.4f}")
        lines.append(f"  Format Status  : {format_status(result)}")

        error_message = getattr(result, "error_message", None)
        if error_message:
            lines.append(f"  Error          : {error_message}")

        validation = getattr(result, "format_validation", None)
        if validation is not None:
            details = getattr(validation, "corruption_details", None) or ()
            if details:
                lines.append("  Validation Notes:")
                for detail in details:
                    lines.append(f"    - {detail}")

        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def build_json_report(
    results: Sequence[FileAnalysisResultLike],
    summary: ScanSummary,
    *,
    quarantine_summary: QuarantineSummary | None = None,
) -> dict[str, Any]:
    return {
        "application": APP_NAME,
        "version": APP_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_files": summary.total_files,
            "corrupted_files": summary.corrupted_files,
            "healthy_files": summary.healthy_files,
            "unreadable_files": summary.unreadable_files,
            "total_bytes": summary.total_bytes,
            "largest_file_bytes": summary.largest_file_bytes,
            "corruption_rate_percent": summary.corruption_rate_percent,
            "top_file_types": [
                {"file_type": file_type, "count": count}
                for file_type, count in summary.top_file_types
            ],
        },
        "quarantine": None
        if quarantine_summary is None
        else {
            "attempted": quarantine_summary.attempted,
            "succeeded": quarantine_summary.succeeded,
            "failed": quarantine_summary.failed,
        },
        "results": [result_to_dict(result) for result in results],
    }


# ==============================================================================
# 4. CLI EXECUTION
# ==============================================================================

def build_detector(runtime: RuntimeBundle, args: argparse.Namespace) -> Any:
    config = runtime.AnalyzerConfig(
        db_path=args.db_path,
        quarantine_dir=args.quarantine_dir,
        chunk_size=args.chunk_size,
        max_workers=args.max_workers,
        entropy_threshold=args.entropy_threshold,
        detect_ransomware=not args.disable_ransomware_detection,
    )
    return runtime.CorruptionDetector(config)


def print_library_status(detector: Any) -> int:
    status = detector.get_library_status()

    print("Library Status")
    print("==============")
    for library_name in sorted(status):
        availability = "Available" if status[library_name] else "Not Available"
        print(f"{library_name:<28} {availability}")

    return 0


def apply_quarantine(detector: Any, results: Sequence[FileAnalysisResultLike]) -> QuarantineSummary:
    corrupted_results = [result for result in results if result.is_corrupted]

    attempted = len(corrupted_results)
    succeeded = 0
    failed = 0

    for result in corrupted_results:
        try:
            if detector.quarantine_file(result.file_path):
                succeeded += 1
            else:
                failed += 1
        except Exception as exc:
            failed += 1
            LOGGER.error("failed to quarantine %s: %s", result.file_path, exc)

    return QuarantineSummary(
        attempted=attempted,
        succeeded=succeeded,
        failed=failed,
    )


def write_output(payload: str, output_path: Path | None) -> None:
    if output_path is None:
        print(payload, end="" if payload.endswith("\n") else "\n")
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(payload, encoding="utf-8")


def run_cli_scan(runtime: RuntimeBundle, args: argparse.Namespace) -> int:
    directory = Path(args.scan).expanduser().resolve()

    if not directory.exists():
        print(f"Error: directory does not exist: {directory}", file=sys.stderr)
        return 1
    if not directory.is_dir():
        print(f"Error: path is not a directory: {directory}", file=sys.stderr)
        return 1

    detector = build_detector(runtime, args)

    if args.verbose:
        LOGGER.info("starting scan: %s", directory)
        LOGGER.info("recursive: %s", not args.no_recursive)
        LOGGER.info("quarantine after scan: %s", args.quarantine)

    try:
        results = detector.scan_directory(str(directory), recursive=not args.no_recursive)
    except Exception as exc:
        LOGGER.exception("scan failed")
        print(f"Error: scan failed: {exc}", file=sys.stderr)
        return 1

    summary = build_summary(results)

    quarantine_summary: QuarantineSummary | None = None
    if args.quarantine and summary.corrupted_files > 0:
        quarantine_summary = apply_quarantine(detector, results)

    if args.json:
        json_payload = build_json_report(results, summary, quarantine_summary=quarantine_summary)
        write_output(json.dumps(json_payload, indent=2), Path(args.output).expanduser() if args.output else None)
    else:
        text_payload = build_text_report(
            results,
            summary,
            verbose=args.verbose,
            summary_only=args.summary_only,
            quarantine_summary=quarantine_summary,
        )
        write_output(text_payload, Path(args.output).expanduser() if args.output else None)

    if args.fail_on_findings and summary.corrupted_files > 0:
        return 2

    return 0


# ==============================================================================
# 5. GUI EXECUTION
# ==============================================================================

def run_gui(runtime: RuntimeBundle, args: argparse.Namespace) -> int:
    try:
        import tkinter as tk
        from tkinter import TclError
    except Exception as exc:
        print(f"Error: tkinter is not available: {exc}", file=sys.stderr)
        return 1

    try:
        root = tk.Tk()
        detector_factory = lambda: build_detector(runtime, args)

        try:
            runtime.CIEMainWindow(root, detector_factory=detector_factory)
        except TypeError:
            runtime.CIEMainWindow(root)

        root.mainloop()
        return 0
    except TclError as exc:
        print(f"Error: failed to start GUI: {exc}", file=sys.stderr)
        return 1


# ==============================================================================
# 6. ARGUMENT PARSING
# ==============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} - detect and isolate corrupted files",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --gui\n"
            "  %(prog)s --scan /data\n"
            "  %(prog)s --scan /data --no-recursive --summary-only\n"
            "  %(prog)s --scan /data --json --output report.json\n"
            "  %(prog)s --scan /data --quarantine --fail-on-findings\n"
            "  %(prog)s --library-status\n"
        ),
    )

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--gui", action="store_true", help="launch the graphical interface")
    mode_group.add_argument("--scan", metavar="DIRECTORY", help="scan a directory from the command line")
    mode_group.add_argument("--modular-scan", metavar="DIRECTORY", help="use modular processing system")
    mode_group.add_argument("--fast-scan", metavar="DIRECTORY", help="FAST scan mode (optimized for speed)")
    mode_group.add_argument("--library-status", action="store_true", help="show validator library availability")
    mode_group.add_argument("--self-test", action="store_true", help="run built-in launcher tests")

    parser.add_argument("--no-recursive", action="store_true", help="scan only the top-level directory")
    parser.add_argument("--quarantine", action="store_true", help="quarantine corrupted files after scanning")
    parser.add_argument("--summary-only", action="store_true", help="print only the summary section")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--output", metavar="FILE", help="write report output to a file")
    parser.add_argument("--fail-on-findings", action="store_true", help="return exit code 2 if corruption is found")

    parser.add_argument("--db-path", default="cie_database.db", help="SQLite database path")
    parser.add_argument("--quarantine-dir", default="quarantine", help="quarantine directory path")
    parser.add_argument("--chunk-size", type=int, default=256 * 1024, help="streaming read chunk size in bytes")
    parser.add_argument("--max-workers", type=int, default=max(1, min(32, 4 + 1)), help="maximum worker threads")
    parser.add_argument("--entropy-threshold", type=float, default=7.95, help="high-entropy ransomware threshold")
    parser.add_argument(
        "--disable-ransomware-detection",
        action="store_true",
        help="disable entropy-based ransomware heuristics",
    )

    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument("--verbose", "-v", action="store_true", help="enable verbose logging and reporting")
    verbosity_group.add_argument("--quiet", "-q", action="store_true", help="suppress non-error logs")

    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")

    return parser


def normalize_args(args: argparse.Namespace) -> argparse.Namespace:
    if args.max_workers < 1:
        raise ValueError("--max-workers must be at least 1")
    if args.chunk_size < 1:
        raise ValueError("--chunk-size must be at least 1")
    if args.entropy_threshold < 0.0 or args.entropy_threshold > 8.0:
        raise ValueError("--entropy-threshold must be between 0.0 and 8.0")
    return args


def configure_logging(args: argparse.Namespace) -> None:
    level = logging.WARNING
    if args.verbose:
        level = logging.INFO
    elif args.quiet:
        level = logging.ERROR

    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")


# ==============================================================================
# 7. SELF TESTS
# ==============================================================================

@dataclass(frozen=True, slots=True)
class _FakeValidation:
    is_valid: bool
    error_message: str | None = None
    format_info: dict[str, Any] | None = None
    corruption_details: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _FakeStatus:
    name: str


@dataclass(frozen=True, slots=True)
class _FakeResult:
    file_path: str
    file_size: int
    file_type: str | None
    checksum: str | None
    error_message: str | None
    is_corrupted: bool
    status: _FakeStatus
    format_validation: _FakeValidation | None = None
    shannon_entropy: float = 0.0


class TestCieHelpers(unittest.TestCase):
    def test_build_summary_counts(self) -> None:
        results = (
            _FakeResult(
                file_path="/tmp/a.txt",
                file_size=100,
                file_type="Text",
                checksum="abc",
                error_message=None,
                is_corrupted=False,
                status=_FakeStatus("VALID"),
            ),
            _FakeResult(
                file_path="/tmp/b.bin",
                file_size=200,
                file_type="Binary",
                checksum="def",
                error_message="checksum mismatch",
                is_corrupted=True,
                status=_FakeStatus("CORRUPTED_CHECKSUM"),
            ),
        )

        summary = build_summary(results)
        self.assertEqual(summary.total_files, 2)
        self.assertEqual(summary.corrupted_files, 1)
        self.assertEqual(summary.healthy_files, 1)
        self.assertEqual(summary.total_bytes, 300)

    def test_result_to_dict_shape(self) -> None:
        result = _FakeResult(
            file_path="/tmp/a.pdf",
            file_size=50,
            file_type="PDF",
            checksum="123",
            error_message="bad pdf",
            is_corrupted=True,
            status=_FakeStatus("CORRUPTED_FORMAT"),
            format_validation=_FakeValidation(
                is_valid=False,
                error_message="invalid PDF structure",
                format_info={"validator": "pdf"},
                corruption_details=("missing EOF",),
            ),
            shannon_entropy=7.2,
        )

        payload = result_to_dict(result)
        self.assertEqual(payload["file_path"], "/tmp/a.pdf")
        self.assertEqual(payload["status"], "CORRUPTED_FORMAT")
        self.assertFalse(payload["format_validation"]["is_valid"])

    def test_build_text_report_contains_summary(self) -> None:
        results = (
            _FakeResult(
                file_path="/tmp/a.txt",
                file_size=100,
                file_type="Text",
                checksum="abc",
                error_message=None,
                is_corrupted=False,
                status=_FakeStatus("VALID"),
            ),
        )

        summary = build_summary(results)
        report = build_text_report(results, summary, verbose=False, summary_only=False)
        self.assertIn("Total files", report)
        self.assertIn("No corrupted files detected.", report)


def run_self_tests() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestCieHelpers)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


# ==============================================================================
# 8. MAIN
# ==============================================================================

def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        normalize_args(args)
    except ValueError as exc:
        parser.error(str(exc))

    configure_logging(args)

    if args.self_test:
        return run_self_tests()

    require_gui = bool(args.gui or (not args.scan and not args.library_status))
    try:
        runtime = load_runtime(require_gui=require_gui)
    except Exception as exc:
        print(f"Error importing runtime modules: {exc}", file=sys.stderr)
        print("Run this from the project root directory or verify the src layout.", file=sys.stderr)
        return 1

    if args.library_status:
        detector = build_detector(runtime, args)
        return print_library_status(detector)

    if args.modular_scan:
        # Use modular scanner
        import subprocess
        modular_script = os.path.join(os.path.dirname(__file__), 'modular_scanner.py')
        cmd = [modular_script, args.modular_scan]
        if args.no_recursive:
            cmd.append('--no-recursive')
        return subprocess.call(cmd)

    if args.scan:
        return run_cli_scan(runtime, args)

    return run_gui(runtime, args)


if __name__ == "__main__":
    raise SystemExit(main())