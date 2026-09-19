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
import os
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
    #: files that could not be analysed (permissions, I/O, database) - the
    #: scan is incomplete when this is non-zero
    failed_files: int = 0
    #: non-corrupt advisories (empty files, high entropy, ...)
    warning_files: int = 0
    #: files whose content looks encrypted / renamed by a ransomware family.
    #: These are counted inside corrupted_files (they are findings) but listed
    #: separately here so "7 corrupted" can be read back as 6 structural
    #: corruptions + 1 ransomware suspicion.
    suspected_ransomware_files: int = 0


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

    first_corrupt = getattr(result, "first_corrupt_at", None)
    baseline_size = getattr(result, "baseline_size_bytes", None)

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
        "warnings": [str(item) for item in (getattr(result, "warnings", ()) or ())],
        "first_corrupted_at": first_corrupt.isoformat() if first_corrupt is not None else None,
        "baseline_size_bytes": int(baseline_size) if baseline_size is not None else None,
        "format_validation": validation_payload,
    }


_FAULT_STATUS_NAMES = frozenset({"UNREADABLE", "ERROR", "MISSING"})
_WARNING_STATUS_NAMES = frozenset({"SUSPICIOUS_EMPTY", "SUSPICIOUS_HIGH_ENTROPY"})


def is_fault(result: FileAnalysisResultLike) -> bool:
    """True when the file could not be analysed (scan is incomplete)."""
    fault = getattr(result, "has_fault", None)
    if fault is not None:
        return bool(fault)
    return status_name(result) in _FAULT_STATUS_NAMES


def is_warning(result: FileAnalysisResultLike) -> bool:
    """True for non-corrupt advisories worth printing."""
    warning = getattr(result, "is_warning", None)
    if warning is not None:
        return bool(warning)
    return status_name(result) in _WARNING_STATUS_NAMES or bool(getattr(result, "warnings", ()))


def build_summary(results: Sequence[FileAnalysisResultLike]) -> ScanSummary:
    total_files = len(results)
    corrupted_files = sum(1 for result in results if bool(getattr(result, "is_corrupted", False)))
    suspected_ransomware_files = sum(
        1 for result in results if status_name(result) == "SUSPECTED_RANSOMWARE"
    )
    healthy_files = total_files - corrupted_files
    total_bytes = sum(int(getattr(result, "file_size", 0) or 0) for result in results)
    unreadable_files = sum(1 for result in results if is_fault(result))
    warning_files = sum(
        1 for result in results
        if is_warning(result) and not bool(getattr(result, "is_corrupted", False))
    )
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
        failed_files=unreadable_files,
        warning_files=warning_files,
        suspected_ransomware_files=suspected_ransomware_files,
    )


def build_secondary_sections(results: Sequence[FileAnalysisResultLike]) -> str:
    """Render the 'not analysed' and 'warnings' sections.

    Kept separate from the corruption list so a heuristic warning (empty file,
    high entropy) is never confused with damage, and so a scan that could not
    read half the files cannot look clean.
    """
    ordered = sorted(results, key=lambda item: result_path(item).casefold())
    fault_results = [r for r in ordered if is_fault(r)]
    warning_results = [
        r for r in ordered
        if is_warning(r) and not is_fault(r) and not bool(getattr(r, "is_corrupted", False))
    ]

    lines: list[str] = []
    if fault_results:
        lines.append("Not Analysed (scan incomplete for these files)")
        lines.append("--------------------------------------------")
        for result in fault_results:
            lines.append(f"[{status_name(result)}] {result_path(result)}")
            message = getattr(result, "error_message", None)
            if message:
                lines.append(f"    {message}")
        lines.append("")

    if warning_results:
        lines.append("Warnings (not corruption)")
        lines.append("-------------------------")
        for result in warning_results:
            lines.append(f"[{status_name(result)}] {result_path(result)}")
            for item in (getattr(result, "warnings", ()) or ()):
                lines.append(f"    - {item}")
        lines.append("")

    return "\n".join(lines)


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
        f"Not analysed       : {summary.failed_files}",
        f"Warnings           : {summary.warning_files}",
        f"Total bytes        : {summary.total_bytes:,} ({format_bytes(summary.total_bytes)})",
        f"Largest file       : {summary.largest_file_bytes:,} ({format_bytes(summary.largest_file_bytes)})",
        f"Corruption rate    : {summary.corruption_rate_percent:.2f}%",
    ]

    if summary.suspected_ransomware_files:
        count = summary.suspected_ransomware_files
        verb = "looks" if count == 1 else "look"
        lines.append(
            f"  (of the corrupted files, {count} {verb} like ransomware rather "
            "than format damage)"
        )

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
        lines.append("")
        lines.append(build_secondary_sections(results))
        return "\n".join(lines).rstrip() + "\n"

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

        first_corrupt = getattr(result, "first_corrupt_at", None)
        if first_corrupt is not None:
            lines.append(f"  Corrupt since  : {first_corrupt.isoformat()}")

        baseline_size = getattr(result, "baseline_size_bytes", None)
        if baseline_size is not None:
            lines.append(f"  Baseline size  : {int(baseline_size):,} bytes")

        validation = getattr(result, "format_validation", None)
        if validation is not None:
            details = getattr(validation, "corruption_details", None) or ()
            if details:
                lines.append("  Validation Notes:")
                for detail in details:
                    lines.append(f"    - {detail}")

        lines.append("")

    lines.append(build_secondary_sections(results).rstrip())
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
            "suspected_ransomware_files": summary.suspected_ransomware_files,
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
    """Create the detector, layering CLI flags over config/cie_config.json."""
    core_module = runtime.core_module
    load_config_file = getattr(core_module, "load_config_file", None)
    config_from_mapping = getattr(core_module, "config_from_mapping", None)

    file_config: dict[str, Any] = {}
    if load_config_file is not None and not getattr(args, "no_config", False):
        try:
            file_config = load_config_file(getattr(args, "config", None))
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.warning("could not read config file: %s", exc)

    overrides = {
        "db_path": args.db_path,
        "quarantine_dir": args.quarantine_dir,
        "chunk_size": args.chunk_size,
        "max_workers": args.max_workers,
        "entropy_threshold": args.entropy_threshold,
        "detect_ransomware": (
            False if args.disable_ransomware_detection else None
        ),
        "advanced_validators": False if getattr(args, "no_deep_validation", False) else None,
    }

    if config_from_mapping is not None:
        config = config_from_mapping(file_config, **overrides)
    else:
        config = runtime.AnalyzerConfig(
            **{key: value for key, value in overrides.items() if value is not None}
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

    # A scan that could not analyse every file is not a clean scan. Previously
    # these failures were reported as "unreadable" and the tool still exited 0,
    # so a broken run looked identical to a healthy directory.
    if summary.failed_files > 0:
        print(
            f"Warning: {summary.failed_files} file(s) could not be analysed; "
            f"the scan is incomplete.",
            file=sys.stderr,
        )
        return 3

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
    mode_group.add_argument("--fast-scan", metavar="DIRECTORY", help="modular FAST strategy scan")
    mode_group.add_argument("--library-status", action="store_true", help="show validator library availability")
    mode_group.add_argument("--list-quarantine", action="store_true", help="list quarantined files")
    mode_group.add_argument("--restore", metavar="FILE", action="append", help="restore a quarantined file (repeatable)")
    mode_group.add_argument(
        "--rebaseline",
        metavar="PATH",
        action="append",
        help="accept the current content of PATH (file or directory) as the new "
             "baseline, clearing existing corruption findings; repeatable",
    )
    mode_group.add_argument("--self-test", action="store_true", help="run built-in launcher tests")

    parser.add_argument(
        "--strategy",
        choices=("fast", "balanced", "deep"),
        default="fast",
        help="strategy used by --modular-scan (default: fast)",
    )
    parser.add_argument("--no-recursive", action="store_true", help="scan only the top-level directory")
    parser.add_argument("--quarantine", action="store_true", help="quarantine corrupted files after scanning")
    parser.add_argument("--summary-only", action="store_true", help="print only the summary section")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--output", metavar="FILE", help="write report output to a file")
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="return exit code 2 if corruption is found, 3 if files could not be analysed",
    )

    parser.add_argument("--db-path", default=None, help="SQLite database path")
    parser.add_argument("--quarantine-dir", default=None, help="quarantine directory path")
    parser.add_argument("--chunk-size", type=int, default=None, help="streaming read chunk size in bytes")
    parser.add_argument(
        "--max-workers",
        type=int,
        default=None,
        help="maximum worker threads (default: from config, else CPU count x2)",
    )
    parser.add_argument("--entropy-threshold", type=float, default=None, help="high-entropy warning threshold")
    parser.add_argument(
        "--disable-ransomware-detection",
        action="store_true",
        help="disable ransomware heuristics",
    )
    parser.add_argument(
        "--no-deep-validation",
        action="store_true",
        help="use header/signature checks only (skip Pillow/PyPDF2/openpyxl/ffprobe)",
    )
    parser.add_argument(
        "--rebaseline-force",
        action="store_true",
        help="with --rebaseline: also accept files that fail format validation "
             "(use only after checking them yourself)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="with --rebaseline: report what would change without writing to the database",
    )
    parser.add_argument("--config", metavar="FILE", help="path to cie_config.json (default: config/cie_config.json)")
    parser.add_argument("--no-config", action="store_true", help="ignore the configuration file")

    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument("--verbose", "-v", action="store_true", help="enable verbose logging and reporting")
    verbosity_group.add_argument("--quiet", "-q", action="store_true", help="suppress non-error logs")

    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")

    return parser


def normalize_args(args: argparse.Namespace) -> argparse.Namespace:
    # None means "not supplied on the command line" so the config file can win.
    if args.max_workers is not None and args.max_workers < 1:
        raise ValueError("--max-workers must be at least 1")
    if args.chunk_size is not None and args.chunk_size < 1:
        raise ValueError("--chunk-size must be at least 1")
    if args.entropy_threshold is not None and not 0.0 <= args.entropy_threshold <= 8.0:
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

def run_modular_scan(args: argparse.Namespace, *, default_strategy: str | None = None) -> int:
    """Run the modular scanner in-process.

    v2.0 tried to exec `<repo>/modular_scanner.py`, which does not exist (the
    file is in src/python), without an interpreter or exec bit, and used the
    un-imported `os` module. Importing it directly removes that whole class of
    failure.
    """
    project_root = Path(__file__).resolve().parent
    modular_dir = project_root / "src" / "python"
    if str(modular_dir) not in sys.path:
        sys.path.append(str(modular_dir))

    try:
        import modular_scanner
    except Exception as exc:
        print(f"Error: modular scanner unavailable: {exc}", file=sys.stderr)
        return 1

    directory = args.modular_scan or args.fast_scan
    if not directory:
        print("Error: no directory supplied for the modular scan", file=sys.stderr)
        return 1

    strategy = default_strategy or getattr(args, "strategy", "fast")
    argv = [str(directory), "--strategy", strategy]
    if args.no_recursive:
        argv.append("--no-recursive")
    if args.json:
        argv.append("--json")
    if args.output:
        argv += ["--output", args.output]

    return modular_scanner.main(argv)


def run_restore(runtime: RuntimeBundle, args: argparse.Namespace) -> int:
    detector = build_detector(runtime, args)
    failures = 0
    for target in args.restore:
        try:
            restored = detector.restore_file(target)
        except Exception as exc:
            print(f"Error: could not restore {target}: {exc}", file=sys.stderr)
            failures += 1
        else:
            print(f"Restored {target} -> {restored}")
    return 1 if failures else 0


def run_rebaseline(runtime: RuntimeBundle, args: argparse.Namespace) -> int:
    """Accept the current content of the given paths as their new baseline.

    Files whose *structure* the validators reject are refused unless
    --rebaseline-force is given, so this command cannot be used to quietly
    bless a broken file. Exit codes: 0 all accepted, 1 nothing accepted
    (bad paths / refused), 3 partial (some accepted, some refused).
    """
    detector = build_detector(runtime, args)
    dry_run = bool(getattr(args, "dry_run", False))

    if dry_run:
        print("Dry run: no changes will be written to the database.", file=sys.stdout)

    outcomes = detector.rebaseline(
        tuple(args.rebaseline),
        recursive=not args.no_recursive,
        force=bool(args.rebaseline_force),
        dry_run=dry_run,
    )

    accepted = [o for o in outcomes if o.action == "rebaselined"]
    refused = [o for o in outcomes if o.action == "refused"]
    missing = [o for o in outcomes if o.action == "missing"]

    if args.json:
        payload = {
            "application": APP_NAME,
            "version": APP_VERSION,
            "dry_run": dry_run,
            "rebaselined": [o.path for o in accepted],
            "refused": [{"path": o.path, "reason": o.reason} for o in refused],
            "missing": [{"path": o.path, "reason": o.reason} for o in missing],
        }
        text = json.dumps(payload, indent=2)
    else:
        lines = [f"{APP_NAME} Re-baseline", "=" * (len(APP_NAME) + 12)]
        if accepted:
            lines.append("")
            lines.append(f"Accepted as new baseline ({len(accepted)}):")
            for outcome in accepted:
                previous = f" (was {outcome.previous_status})" if outcome.previous_status else ""
                lines.append(f"  {outcome.path}{previous}")
        if refused:
            lines.append("")
            lines.append(f"Refused - still failing validation ({len(refused)}):")
            for outcome in refused:
                lines.append(f"  {outcome.path}")
                if outcome.reason:
                    lines.append(f"      {outcome.reason}")
            lines.append("")
            lines.append("  Review these files; pass --rebaseline-force only if you are sure.")
        if missing:
            lines.append("")
            lines.append(f"Not found ({len(missing)}):")
            for outcome in missing:
                lines.append(f"  {outcome.path}")
                if outcome.reason:
                    lines.append(f"      {outcome.reason}")
        if not outcomes:
            lines.append("")
            lines.append("Nothing to do: no files matched the given paths.")
        text = "\n".join(lines)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(text + "\n")
        except OSError as exc:
            print(f"Error: could not write {args.output}: {exc}", file=sys.stderr)
            return 1
        if not args.json:
            print(text)
    else:
        print(text)

    if refused and accepted:
        return 3
    if refused or missing or not outcomes:
        return 1
    return 0


def print_quarantine_listing(detector: Any) -> int:
    try:
        entries = detector.list_quarantine(include_restored=False)
    except Exception as exc:
        print(f"Error: could not read the quarantine log: {exc}", file=sys.stderr)
        return 1

    print("Quarantined Files")
    print("=================")
    if not entries:
        print("(none)")
        return 0

    for entry in entries:
        when = entry.quarantined_at.isoformat() if entry.quarantined_at else "unknown"
        print(f"{entry.quarantine_path}")
        print(f"    original : {entry.original_path}")
        print(f"    reason   : {entry.reason}")
        print(f"    when     : {when}")
    print()
    print("Restore with: cie.py --restore <path>")
    return 0


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

    # The GUI is only imported when the GUI is actually requested; previously
    # --library-status/--modular-scan/--fast-scan all pulled in tkinter.
    gui_mode = bool(args.gui or (not any([
        args.scan,
        args.modular_scan,
        args.fast_scan,
        args.library_status,
        args.list_quarantine,
        args.restore,
        args.rebaseline,
    ])))

    try:
        runtime = load_runtime(require_gui=gui_mode)
    except Exception as exc:
        print(f"Error importing runtime modules: {exc}", file=sys.stderr)
        print("Run this from the project root directory or verify the src layout.", file=sys.stderr)
        return 1

    if args.list_quarantine:
        return print_quarantine_listing(build_detector(runtime, args))

    if args.restore:
        return run_restore(runtime, args)

    if args.rebaseline:
        return run_rebaseline(runtime, args)

    if args.library_status:
        return print_library_status(build_detector(runtime, args))

    if args.fast_scan:
        return run_modular_scan(args, default_strategy="fast")

    if args.modular_scan:
        return run_modular_scan(args)

    if args.scan:
        return run_cli_scan(runtime, args)

    return run_gui(runtime, args)


if __name__ == "__main__":
    raise SystemExit(main())