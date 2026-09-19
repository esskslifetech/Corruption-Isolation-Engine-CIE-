#!/usr/bin/env python3
"""
Modular scanner for CIE.

Features:
- Deterministic file collection and reporting
- Multiple strategies: fast, balanced, deep
- Comparison mode across strategies
- Repeated benchmark mode on the same file set
- JSON or text output
- Safer error handling and cleaner architecture
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import unittest
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from statistics import fmean
from typing import Any, Mapping, Protocol, Sequence

LOGGER = logging.getLogger(__name__)

DEFAULT_STRATEGY = "fast"
SUPPORTED_STRATEGIES = ("fast", "balanced", "deep")
_PROCESSOR_FACTORY: Any | None = None


# ==============================================================================
# 1. RUNTIME IMPORTS
# ==============================================================================

def _configure_import_path() -> None:
    project_root = Path(__file__).resolve().parent
    candidate_paths = (
        project_root / "src",
        project_root / "src" / "python",
    )

    for candidate in candidate_paths:
        if candidate.exists():
            candidate_str = str(candidate)
            if candidate_str not in sys.path:
                sys.path.insert(0, candidate_str)


def _load_processor_factory() -> Any:
    global _PROCESSOR_FACTORY

    if _PROCESSOR_FACTORY is not None:
        return _PROCESSOR_FACTORY

    _configure_import_path()

    processor_factory = None

    # Try every plausible way of locating the sibling module: direct import,
    # package import, then loading it by file path. v2.0 depended on a single
    # spelling and broke whenever the launcher changed.
    for loader in (
        lambda: __import__("core_analyzer").load_sibling_module("processing_modules").ProcessorFactory,
        lambda: __import__("processing_modules").ProcessorFactory,
        lambda: __import__("src.python.processing_modules", fromlist=["x"]).ProcessorFactory,
        _load_by_path,
    ):
        try:
            processor_factory = loader()
            break
        except Exception:
            continue

    if processor_factory is None:
        raise RuntimeError("failed to import ProcessorFactory from processing_modules")

    _PROCESSOR_FACTORY = processor_factory
    return _PROCESSOR_FACTORY


def _load_by_path() -> Any:
    """Load processing_modules.py from this file's directory."""
    import importlib.util

    candidate = Path(__file__).resolve().parent / "processing_modules.py"
    spec = importlib.util.spec_from_file_location("cie_processing_modules", candidate)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {candidate}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.ProcessorFactory


# ==============================================================================
# 2. PROTOCOLS AND MODELS
# ==============================================================================

class ScanResultLike(Protocol):
    file_path: str | Path
    is_corrupted: bool
    error_message: str | None


class ProcessorLike(Protocol):
    processors: Sequence[Any]

    def process_files(self, files: Sequence[Path]) -> Sequence[ScanResultLike]: ...
    def get_performance_stats(self, results: Sequence[ScanResultLike]) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class ScanTimings:
    collection_seconds: float
    processing_seconds: float

    @property
    def total_seconds(self) -> float:
        return self.collection_seconds + self.processing_seconds


@dataclass(frozen=True, slots=True)
class PerformanceStats:
    total_files: int
    corrupted_files: int
    total_size_bytes: int
    files_per_second: float
    mb_per_second: float
    corruption_rate_percent: float
    processors_used: int


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    strategy: str
    directory: Path
    recursive: bool
    files: tuple[Path, ...]
    results: tuple[Any, ...]
    corrupted_results: tuple[Any, ...]
    stats: PerformanceStats
    timings: ScanTimings


@dataclass(frozen=True, slots=True)
class BenchmarkRun:
    strategy: str
    run_index: int
    elapsed_seconds: float
    stats: PerformanceStats


@dataclass(frozen=True, slots=True)
class BenchmarkSummary:
    strategy: str
    file_count: int
    repeat_count: int
    processors_used: int
    corrupted_files: int
    average_seconds: float
    best_seconds: float
    average_files_per_second: float
    average_mb_per_second: float


# ==============================================================================
# 3. HELPERS
# ==============================================================================

def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _result_path(result: Any) -> str:
    return str(getattr(result, "file_path", "") or "")


def _result_is_corrupted(result: Any) -> bool:
    return bool(getattr(result, "is_corrupted", False))


def _result_error_message(result: Any) -> str:
    return str(getattr(result, "error_message", "") or "")


def _result_size_bytes(result: Any) -> int:
    for attribute_name in ("file_size", "size_bytes", "size"):
        if hasattr(result, attribute_name):
            return _safe_int(getattr(result, attribute_name), 0)
    return 0


def _top_extensions(paths: Sequence[Path], limit: int = 5) -> tuple[tuple[str, int], ...]:
    counts = Counter((path.suffix.lower() or "<none>") for path in paths)
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return tuple(ranked[:limit])


def _normalize_stats(
    raw_stats: Mapping[str, Any] | None,
    *,
    files: Sequence[Path],
    results: Sequence[Any],
    processing_seconds: float,
    processors_used: int,
) -> PerformanceStats:
    stats = dict(raw_stats or {})

    total_files = _safe_int(stats.get("total_files"), len(results))
    corrupted_files = _safe_int(
        stats.get("corrupted_files"),
        sum(1 for result in results if _result_is_corrupted(result)),
    )

    total_size_bytes = _safe_int(stats.get("total_size"))
    if total_size_bytes <= 0:
        total_size_bytes = sum(_result_size_bytes(result) for result in results)
    if total_size_bytes <= 0:
        total_size_bytes = sum(path.stat().st_size for path in files if path.exists())

    files_per_second = _safe_float(stats.get("files_per_second"))
    if files_per_second <= 0.0:
        files_per_second = total_files / processing_seconds if processing_seconds > 0 else 0.0

    mb_per_second = _safe_float(stats.get("mb_per_second"))
    if mb_per_second <= 0.0:
        mb_per_second = (total_size_bytes / (1024.0 * 1024.0)) / processing_seconds if processing_seconds > 0 else 0.0

    corruption_rate_percent = _safe_float(stats.get("corruption_rate"))
    if corruption_rate_percent <= 0.0 and total_files > 0:
        corruption_rate_percent = corrupted_files / total_files * 100.0

    normalized_processors_used = _safe_int(stats.get("processors_used"), processors_used)
    if normalized_processors_used <= 0:
        normalized_processors_used = max(1, processors_used)

    return PerformanceStats(
        total_files=total_files,
        corrupted_files=corrupted_files,
        total_size_bytes=total_size_bytes,
        files_per_second=files_per_second,
        mb_per_second=mb_per_second,
        corruption_rate_percent=corruption_rate_percent,
        processors_used=normalized_processors_used,
    )


def collect_files(
    directory: Path,
    *,
    recursive: bool,
    include_hidden: bool,
    follow_symlinks: bool,
) -> tuple[Path, ...]:
    if not directory.exists():
        raise FileNotFoundError(f"directory does not exist: {directory}")
    if not directory.is_dir():
        raise NotADirectoryError(f"path is not a directory: {directory}")

    def include_name(name: str) -> bool:
        return include_hidden or not name.startswith(".")

    discovered: list[Path] = []

    if recursive:
        def on_error(exc: OSError) -> None:
            LOGGER.warning("skipping inaccessible path: %s", exc)

        for root, dirnames, filenames in os.walk(
            directory,
            topdown=True,
            followlinks=follow_symlinks,
            onerror=on_error,
        ):
            root_path = Path(root)

            dirnames[:] = [name for name in dirnames if include_name(name)]

            for filename in filenames:
                if not include_name(filename):
                    continue

                candidate = root_path / filename
                try:
                    if candidate.is_file():
                        discovered.append(candidate.resolve())
                except OSError:
                    LOGGER.warning("skipping inaccessible file: %s", candidate)
    else:
        for candidate in directory.iterdir():
            if not include_name(candidate.name):
                continue

            try:
                if candidate.is_file():
                    discovered.append(candidate.resolve())
            except OSError:
                LOGGER.warning("skipping inaccessible file: %s", candidate)

    return tuple(sorted(discovered, key=lambda item: str(item).casefold()))


def build_processor(strategy: str) -> ProcessorLike:
    normalized_strategy = strategy.lower()
    factory = _load_processor_factory()

    creators = {
        "fast": factory.create_fast_processor,
        "balanced": factory.create_balanced_processor,
        "deep": factory.create_deep_processor,
    }

    creator = creators.get(normalized_strategy)
    if creator is None:
        supported = ", ".join(SUPPORTED_STRATEGIES)
        raise ValueError(f"unknown strategy: {strategy}. supported strategies: {supported}")

    processor = creator()
    return processor


def serialize_result(result: Any) -> dict[str, Any]:
    payload = {
        "file_path": _result_path(result),
        "is_corrupted": _result_is_corrupted(result),
        "error_message": _result_error_message(result) or None,
        "size_bytes": _result_size_bytes(result),
    }

    for attribute_name in ("checksum", "file_type", "status", "entropy", "shannon_entropy"):
        if hasattr(result, attribute_name):
            value = getattr(result, attribute_name)
            if attribute_name == "status":
                payload[attribute_name] = getattr(value, "name", str(value))
            else:
                payload[attribute_name] = value

    return payload


def render_scan_text(outcome: ScanOutcome, *, show_corrupted_limit: int) -> str:
    top_extensions = _top_extensions(outcome.files)
    top_errors = Counter(
        _result_error_message(result)
        for result in outcome.corrupted_results
        if _result_error_message(result)
    )

    lines = [
        "Modular Scanner for CIE",
        "=" * 24,
        f"Strategy            : {outcome.strategy}",
        f"Directory           : {outcome.directory}",
        f"Recursive           : {outcome.recursive}",
        f"Files discovered    : {len(outcome.files):,}",
        f"Processors used     : {outcome.stats.processors_used}",
        f"Collection time     : {outcome.timings.collection_seconds:.3f}s",
        f"Processing time     : {outcome.timings.processing_seconds:.3f}s",
        f"Total time          : {outcome.timings.total_seconds:.3f}s",
        f"Files per second    : {outcome.stats.files_per_second:.0f}",
        f"MB per second       : {outcome.stats.mb_per_second:.2f}",
        f"Total size          : {outcome.stats.total_size_bytes:,} bytes ({outcome.stats.total_size_bytes / (1024 * 1024):.2f} MB)",
        f"Corrupted files     : {outcome.stats.corrupted_files}",
        f"Corruption rate     : {outcome.stats.corruption_rate_percent:.2f}%",
        "",
    ]

    if top_extensions:
        lines.append("Top Extensions")
        lines.append("--------------")
        for extension, count in top_extensions:
            lines.append(f"{extension:<12} {count}")
        lines.append("")

    if outcome.corrupted_results:
        lines.append(f"Corrupted Files (showing up to {show_corrupted_limit})")
        lines.append("----------------------------------------")
        for result in outcome.corrupted_results[:show_corrupted_limit]:
            lines.append(f"- {_result_path(result)}")
            error_message = _result_error_message(result)
            if error_message:
                lines.append(f"  Error: {error_message}")

        remaining = len(outcome.corrupted_results) - min(show_corrupted_limit, len(outcome.corrupted_results))
        if remaining > 0:
            lines.append(f"... and {remaining} more")
        lines.append("")
    else:
        lines.append("No corrupted files detected.")
        lines.append("")

    if top_errors:
        lines.append("Top Error Messages")
        lines.append("------------------")
        for error_message, count in top_errors.most_common(5):
            lines.append(f"{count:>5}  {error_message}")
        lines.append("")

    if outcome.stats.files_per_second >= 1000:
        lines.append("Performance verdict : EXCELLENT")
    elif outcome.stats.files_per_second >= 500:
        lines.append("Performance verdict : GOOD")
    elif outcome.stats.files_per_second >= 100:
        lines.append("Performance verdict : MODERATE")
    else:
        lines.append("Performance verdict : SLOW")

    return "\n".join(lines) + "\n"


def render_comparison_text(outcomes: Sequence[ScanOutcome]) -> str:
    sorted_outcomes = sorted(outcomes, key=lambda item: item.strategy)
    fastest = max(sorted_outcomes, key=lambda item: item.stats.files_per_second)
    smallest_time = min(sorted_outcomes, key=lambda item: item.timings.total_seconds)

    lines = [
        "Strategy Comparison",
        "=" * 19,
        f"{'Strategy':<12} {'Files/sec':>12} {'MB/sec':>12} {'Corrupted':>12} {'Time(s)':>12}",
        "-" * 64,
    ]

    for outcome in sorted_outcomes:
        lines.append(
            f"{outcome.strategy:<12} "
            f"{outcome.stats.files_per_second:>12.0f} "
            f"{outcome.stats.mb_per_second:>12.2f} "
            f"{outcome.stats.corrupted_files:>12} "
            f"{outcome.timings.total_seconds:>12.3f}"
        )

    lines.extend(
        (
            "",
            f"Fastest by throughput : {fastest.strategy}",
            f"Fastest by total time : {smallest_time.strategy}",
        )
    )

    corrupted_counts = {outcome.stats.corrupted_files for outcome in sorted_outcomes}
    if len(corrupted_counts) == 1:
        lines.append("Corruption agreement  : consistent across strategies")
    else:
        lines.append("Corruption agreement  : inconsistent across strategies")

    return "\n".join(lines) + "\n"


def render_benchmark_text(benchmarks: Sequence[BenchmarkSummary]) -> str:
    sorted_benchmarks = sorted(benchmarks, key=lambda item: item.strategy)
    winner = max(sorted_benchmarks, key=lambda item: item.average_files_per_second)

    lines = [
        "Benchmark Results",
        "=" * 17,
        f"{'Strategy':<12} {'Avg sec':>10} {'Best sec':>10} {'Avg files/sec':>16} {'Avg MB/sec':>14} {'Corrupted':>12}",
        "-" * 80,
    ]

    for benchmark in sorted_benchmarks:
        lines.append(
            f"{benchmark.strategy:<12} "
            f"{benchmark.average_seconds:>10.3f} "
            f"{benchmark.best_seconds:>10.3f} "
            f"{benchmark.average_files_per_second:>16.0f} "
            f"{benchmark.average_mb_per_second:>14.2f} "
            f"{benchmark.corrupted_files:>12}"
        )

    lines.extend(
        (
            "",
            f"Benchmark winner: {winner.strategy}",
        )
    )

    return "\n".join(lines) + "\n"


def serialize_outcome(outcome: ScanOutcome) -> dict[str, Any]:
    return {
        "strategy": outcome.strategy,
        "directory": str(outcome.directory),
        "recursive": outcome.recursive,
        "files_discovered": len(outcome.files),
        "timings": {
            "collection_seconds": outcome.timings.collection_seconds,
            "processing_seconds": outcome.timings.processing_seconds,
            "total_seconds": outcome.timings.total_seconds,
        },
        "stats": {
            "total_files": outcome.stats.total_files,
            "corrupted_files": outcome.stats.corrupted_files,
            "total_size_bytes": outcome.stats.total_size_bytes,
            "files_per_second": outcome.stats.files_per_second,
            "mb_per_second": outcome.stats.mb_per_second,
            "corruption_rate_percent": outcome.stats.corruption_rate_percent,
            "processors_used": outcome.stats.processors_used,
        },
        "results": [serialize_result(result) for result in outcome.results],
    }


def serialize_benchmark_summary(summary: BenchmarkSummary) -> dict[str, Any]:
    return {
        "strategy": summary.strategy,
        "file_count": summary.file_count,
        "repeat_count": summary.repeat_count,
        "processors_used": summary.processors_used,
        "corrupted_files": summary.corrupted_files,
        "average_seconds": summary.average_seconds,
        "best_seconds": summary.best_seconds,
        "average_files_per_second": summary.average_files_per_second,
        "average_mb_per_second": summary.average_mb_per_second,
    }


def write_output(text: str, output_path: Path | None) -> None:
    if output_path is None:
        print(text, end="" if text.endswith("\n") else "\n")
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")


# ==============================================================================
# 4. SCANNER
# ==============================================================================

class ModularScanner:
    """Scanner that delegates file processing to a selected strategy."""

    def __init__(
        self,
        strategy: str = DEFAULT_STRATEGY,
        *,
        include_hidden: bool = True,
        follow_symlinks: bool = False,
    ):
        self.strategy = strategy.lower()
        self.include_hidden = include_hidden
        self.follow_symlinks = follow_symlinks
        self.processor = build_processor(self.strategy)

    def scan_directory(self, directory: str | Path, recursive: bool = True) -> ScanOutcome:
        directory_path = Path(directory).expanduser().resolve()

        collection_start = time.perf_counter()
        files = collect_files(
            directory_path,
            recursive=recursive,
            include_hidden=self.include_hidden,
            follow_symlinks=self.follow_symlinks,
        )
        collection_seconds = time.perf_counter() - collection_start

        results: tuple[Any, ...] = ()
        processing_seconds = 0.0

        if files:
            processing_start = time.perf_counter()
            raw_results = tuple(self.processor.process_files(files))
            processing_seconds = time.perf_counter() - processing_start
            results = tuple(sorted(raw_results, key=lambda item: _result_path(item).casefold()))

        corrupted_results = tuple(result for result in results if _result_is_corrupted(result))
        raw_stats = self.processor.get_performance_stats(results) if results else {}

        processor_count = len(getattr(self.processor, "processors", ()) or ()) or 1
        stats = _normalize_stats(
            raw_stats,
            files=files,
            results=results,
            processing_seconds=processing_seconds,
            processors_used=processor_count,
        )

        return ScanOutcome(
            strategy=self.strategy,
            directory=directory_path,
            recursive=recursive,
            files=files,
            results=results,
            corrupted_results=corrupted_results,
            stats=stats,
            timings=ScanTimings(
                collection_seconds=collection_seconds,
                processing_seconds=processing_seconds,
            ),
        )


# ==============================================================================
# 5. COMPARISON AND BENCHMARKS
# ==============================================================================

def run_strategy_comparison(
    directory: Path,
    *,
    strategies: Sequence[str],
    recursive: bool,
    include_hidden: bool,
    follow_symlinks: bool,
) -> tuple[ScanOutcome, ...]:
    outcomes: list[ScanOutcome] = []

    for strategy in strategies:
        scanner = ModularScanner(
            strategy=strategy,
            include_hidden=include_hidden,
            follow_symlinks=follow_symlinks,
        )
        outcomes.append(scanner.scan_directory(directory, recursive=recursive))

    return tuple(outcomes)


def run_benchmark(
    directory: Path,
    *,
    strategies: Sequence[str],
    recursive: bool,
    include_hidden: bool,
    follow_symlinks: bool,
    limit: int,
    repeats: int,
) -> tuple[BenchmarkSummary, ...]:
    all_files = collect_files(
        directory,
        recursive=recursive,
        include_hidden=include_hidden,
        follow_symlinks=follow_symlinks,
    )

    benchmark_files = all_files[:max(0, limit)]
    if not benchmark_files:
        return ()

    summaries: list[BenchmarkSummary] = []

    for strategy in strategies:
        runs: list[BenchmarkRun] = []

        for run_index in range(1, repeats + 1):
            scanner = ModularScanner(
                strategy=strategy,
                include_hidden=include_hidden,
                follow_symlinks=follow_symlinks,
            )

            started = time.perf_counter()
            raw_results = tuple(scanner.processor.process_files(benchmark_files))
            elapsed_seconds = time.perf_counter() - started

            processor_count = len(getattr(scanner.processor, "processors", ()) or ()) or 1
            raw_stats = scanner.processor.get_performance_stats(raw_results)
            stats = _normalize_stats(
                raw_stats,
                files=benchmark_files,
                results=raw_results,
                processing_seconds=elapsed_seconds,
                processors_used=processor_count,
            )

            runs.append(
                BenchmarkRun(
                    strategy=strategy,
                    run_index=run_index,
                    elapsed_seconds=elapsed_seconds,
                    stats=stats,
                )
            )

        summaries.append(
            BenchmarkSummary(
                strategy=strategy,
                file_count=len(benchmark_files),
                repeat_count=repeats,
                processors_used=runs[0].stats.processors_used,
                corrupted_files=runs[0].stats.corrupted_files,
                average_seconds=fmean(run.elapsed_seconds for run in runs),
                best_seconds=min(run.elapsed_seconds for run in runs),
                average_files_per_second=fmean(run.stats.files_per_second for run in runs),
                average_mb_per_second=fmean(run.stats.mb_per_second for run in runs),
            )
        )

    return tuple(sorted(summaries, key=lambda item: item.strategy))


# ==============================================================================
# 6. CLI
# ==============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Modular Scanner for CIE")

    parser.add_argument("directory", nargs="?", help="directory to scan")
    parser.add_argument(
        "--strategy",
        choices=SUPPORTED_STRATEGIES,
        default=DEFAULT_STRATEGY,
        help=f"default strategy for normal scan (default: {DEFAULT_STRATEGY})",
    )
    parser.add_argument(
        "--strategies",
        nargs="+",
        choices=SUPPORTED_STRATEGIES,
        help="strategies for compare or benchmark modes",
    )
    parser.add_argument("--no-recursive", action="store_true", help="scan only the top-level directory")
    parser.add_argument("--compare", action="store_true", help="compare selected strategies")
    parser.add_argument("--benchmark", action="store_true", help="benchmark selected strategies")
    parser.add_argument("--benchmark-limit", type=int, default=1000, help="maximum files used in benchmark mode")
    parser.add_argument("--benchmark-repeats", type=int, default=3, help="benchmark repetitions per strategy")
    parser.add_argument("--exclude-hidden", action="store_true", help="exclude dotfiles and dot-directories")
    parser.add_argument("--follow-symlinks", action="store_true", help="follow directory symlinks during recursive scans")
    parser.add_argument("--show-corrupted", type=int, default=10, help="number of corrupted files to print")
    parser.add_argument("--json", action="store_true", help="output JSON")
    parser.add_argument("--output", help="write output to file instead of stdout")
    parser.add_argument("--quiet", action="store_true", help="reduce log output")
    parser.add_argument("--self-test", action="store_true", help="run built-in tests")
    parser.add_argument("--version", action="version", version="CIE Modular Scanner 2.0")

    return parser


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.self_test:
        return

    if not args.directory:
        parser.error("directory is required unless --self-test is used")

    if args.benchmark_limit < 1:
        parser.error("--benchmark-limit must be at least 1")

    if args.benchmark_repeats < 1:
        parser.error("--benchmark-repeats must be at least 1")

    if args.show_corrupted < 0:
        parser.error("--show-corrupted must be at least 0")

    if args.compare and args.benchmark:
        parser.error("--compare and --benchmark cannot be used together")


def configure_logging(quiet: bool) -> None:
    logging.basicConfig(
        level=logging.ERROR if quiet else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )


def selected_strategies(args: argparse.Namespace) -> tuple[str, ...]:
    if args.strategies:
        ordered_unique: list[str] = []
        seen: set[str] = set()
        for strategy in args.strategies:
            if strategy not in seen:
                seen.add(strategy)
                ordered_unique.append(strategy)
        return tuple(ordered_unique)

    if args.compare or args.benchmark:
        return SUPPORTED_STRATEGIES

    return (args.strategy,)


def run_normal_scan(args: argparse.Namespace) -> int:
    directory = Path(args.directory).expanduser().resolve()

    scanner = ModularScanner(
        strategy=args.strategy,
        include_hidden=not args.exclude_hidden,
        follow_symlinks=args.follow_symlinks,
    )
    outcome = scanner.scan_directory(directory, recursive=not args.no_recursive)

    if args.json:
        payload = json.dumps(serialize_outcome(outcome), indent=2)
    else:
        payload = render_scan_text(outcome, show_corrupted_limit=args.show_corrupted)

    write_output(payload, Path(args.output).expanduser() if args.output else None)
    return 0


def run_compare_mode(args: argparse.Namespace) -> int:
    directory = Path(args.directory).expanduser().resolve()
    outcomes = run_strategy_comparison(
        directory,
        strategies=selected_strategies(args),
        recursive=not args.no_recursive,
        include_hidden=not args.exclude_hidden,
        follow_symlinks=args.follow_symlinks,
    )

    if args.json:
        payload = json.dumps(
            {
                "mode": "compare",
                "directory": str(directory),
                "recursive": not args.no_recursive,
                "outcomes": [serialize_outcome(outcome) for outcome in outcomes],
            },
            indent=2,
        )
    else:
        payload = render_comparison_text(outcomes)

    write_output(payload, Path(args.output).expanduser() if args.output else None)
    return 0


def run_benchmark_mode(args: argparse.Namespace) -> int:
    directory = Path(args.directory).expanduser().resolve()
    summaries = run_benchmark(
        directory,
        strategies=selected_strategies(args),
        recursive=not args.no_recursive,
        include_hidden=not args.exclude_hidden,
        follow_symlinks=args.follow_symlinks,
        limit=args.benchmark_limit,
        repeats=args.benchmark_repeats,
    )

    if args.json:
        payload = json.dumps(
            {
                "mode": "benchmark",
                "directory": str(directory),
                "recursive": not args.no_recursive,
                "limit": args.benchmark_limit,
                "repeats": args.benchmark_repeats,
                "benchmarks": [serialize_benchmark_summary(summary) for summary in summaries],
            },
            indent=2,
        )
    else:
        payload = render_benchmark_text(summaries)

    write_output(payload, Path(args.output).expanduser() if args.output else None)
    return 0


# ==============================================================================
# 7. TESTS
# ==============================================================================

@dataclass(frozen=True, slots=True)
class _FakeResult:
    file_path: str
    is_corrupted: bool
    error_message: str | None = None
    file_size: int = 0


class _FakeProcessor:
    def __init__(self, results: Sequence[_FakeResult]) -> None:
        self.processors = ("a", "b")
        self._results = tuple(results)

    def process_files(self, files: Sequence[Path]) -> Sequence[_FakeResult]:
        if not files:
            return ()
        return self._results[: len(files)]

    def get_performance_stats(self, results: Sequence[_FakeResult]) -> Mapping[str, Any]:
        return {
            "total_files": len(results),
            "corrupted_files": sum(1 for result in results if result.is_corrupted),
            "total_size": sum(result.file_size for result in results),
            "processors_used": len(self.processors),
        }


class TestModularScannerHelpers(unittest.TestCase):
    def test_normalize_stats_fallbacks(self) -> None:
        files = ()
        results = (
            _FakeResult("a", False, file_size=100),
            _FakeResult("b", True, file_size=300),
        )

        stats = _normalize_stats(
            {},
            files=files,
            results=results,
            processing_seconds=2.0,
            processors_used=2,
        )

        self.assertEqual(stats.total_files, 2)
        self.assertEqual(stats.corrupted_files, 1)
        self.assertEqual(stats.total_size_bytes, 400)
        self.assertAlmostEqual(stats.files_per_second, 1.0)
        self.assertAlmostEqual(stats.mb_per_second, (400 / (1024 * 1024)) / 2.0)

    def test_render_scan_text_mentions_corruption(self) -> None:
        outcome = ScanOutcome(
            strategy="fast",
            directory=Path("/tmp"),
            recursive=True,
            files=(Path("/tmp/a.txt"),),
            results=(_FakeResult("/tmp/a.txt", True, "bad checksum", 12),),
            corrupted_results=(_FakeResult("/tmp/a.txt", True, "bad checksum", 12),),
            stats=PerformanceStats(
                total_files=1,
                corrupted_files=1,
                total_size_bytes=12,
                files_per_second=10.0,
                mb_per_second=0.1,
                corruption_rate_percent=100.0,
                processors_used=2,
            ),
            timings=ScanTimings(collection_seconds=0.1, processing_seconds=0.2),
        )

        report = render_scan_text(outcome, show_corrupted_limit=10)
        self.assertIn("Corrupted files", report)
        self.assertIn("/tmp/a.txt", report)
        self.assertIn("bad checksum", report)

    def test_top_extensions(self) -> None:
        paths = (
            Path("/tmp/a.txt"),
            Path("/tmp/b.txt"),
            Path("/tmp/c.bin"),
        )
        top = _top_extensions(paths)
        self.assertEqual(top[0], (".txt", 2))


def run_self_tests() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestModularScannerHelpers)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


# ==============================================================================
# 8. MAIN
# ==============================================================================

def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    validate_args(args, parser)
    configure_logging(args.quiet)

    if args.self_test:
        return run_self_tests()

    directory = Path(args.directory).expanduser().resolve()
    if not directory.exists():
        print(f"Error: directory not found: {directory}", file=sys.stderr)
        return 1
    if not directory.is_dir():
        print(f"Error: not a directory: {directory}", file=sys.stderr)
        return 1

    try:
        if args.compare:
            return run_compare_mode(args)
        if args.benchmark:
            return run_benchmark_mode(args)
        return run_normal_scan(args)
    except Exception as exc:
        LOGGER.exception("scanner execution failed")
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())