#!/usr/bin/env python3
"""
Tkinter GUI for Corruption Isolation Engine (CIE).

Design goals:
- Keep Tkinter work on the main thread.
- Isolate background scanning from UI updates.
- Keep file actions centralized and reusable.
- Provide safer OS integration and export support.
- Keep pure formatting and reporting logic testable.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any, Callable, Mapping, Protocol, Sequence

LOGGER = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PYTHON_SOURCE_DIR = PROJECT_ROOT / "python"

if PYTHON_SOURCE_DIR.exists():
    sys.path.insert(0, str(PYTHON_SOURCE_DIR))

CORE_ANALYZER_IMPORT_ERROR: Exception | None = None
try:
    from core_analyzer import CorruptionDetector
except Exception as exc:  # pragma: no cover
    CorruptionDetector = None  # type: ignore[assignment]
    CORE_ANALYZER_IMPORT_ERROR = exc


class FormatValidationLike(Protocol):
    is_valid: bool
    error_message: str | None
    format_info: Mapping[str, Any] | None
    corruption_details: Sequence[str] | None


class FileAnalysisResultLike(Protocol):
    file_path: str
    file_size: int
    file_type: str | None
    checksum: str | None
    is_corrupted: bool
    error_message: str | None
    format_validation: FormatValidationLike | None


@dataclass(frozen=True, slots=True)
class TreeColumn:
    key: str
    title: str
    width: int
    stretch: bool = True


@dataclass(frozen=True, slots=True)
class ScanSummary:
    total_files: int
    corrupted_files: int
    healthy_files: int
    total_bytes: int
    largest_file_bytes: int
    corruption_rate_percent: float
    file_type_counts: tuple[tuple[str, int], ...]
    corrupted_type_counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class ScanCompletedEvent:
    token: int
    results: list[FileAnalysisResultLike]


@dataclass(frozen=True, slots=True)
class ScanFailedEvent:
    token: int
    error_message: str


ScanEvent = ScanCompletedEvent | ScanFailedEvent

TREE_COLUMNS: tuple[TreeColumn, ...] = (
    TreeColumn("path", "File Path", 360),
    TreeColumn("size", "Size", 110, False),
    TreeColumn("type", "Type", 120, False),
    TreeColumn("checksum", "Checksum", 240),
    TreeColumn("format", "Format Status", 120, False),
    TreeColumn("status", "Status", 120, False),
    TreeColumn("error", "Error", 260),
)

UI_EVENT_POLL_MS = 100


def result_path(result: FileAnalysisResultLike) -> str:
    return str(getattr(result, "file_path", "") or "")


def result_size(result: FileAnalysisResultLike) -> int:
    try:
        return int(getattr(result, "file_size", 0) or 0)
    except (TypeError, ValueError):
        return 0


def result_type(result: FileAnalysisResultLike) -> str:
    return str(getattr(result, "file_type", "") or "Unknown")


def result_checksum(result: FileAnalysisResultLike) -> str:
    return str(getattr(result, "checksum", "") or "")


def result_is_corrupted(result: FileAnalysisResultLike) -> bool:
    return bool(getattr(result, "is_corrupted", False))


def result_error(result: FileAnalysisResultLike) -> str:
    return str(getattr(result, "error_message", "") or "")


def result_validation(result: FileAnalysisResultLike) -> FormatValidationLike | None:
    return getattr(result, "format_validation", None)


def format_validation_status(result: FileAnalysisResultLike) -> str:
    validation = result_validation(result)
    if validation is None:
        return "N/A"
    return "Valid" if bool(getattr(validation, "is_valid", False)) else "Invalid"


def result_status_label(result: FileAnalysisResultLike) -> str:
    return "CORRUPTED" if result_is_corrupted(result) else "OK"


def humanize_bytes(size_bytes: int) -> str:
    size = float(max(size_bytes, 0))
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    unit_index = 0

    while size >= 1024.0 and unit_index < len(units) - 1:
        size /= 1024.0
        unit_index += 1

    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    return f"{size:.2f} {units[unit_index]}"


def build_scan_summary(results: Sequence[FileAnalysisResultLike]) -> ScanSummary:
    total_files = len(results)
    corrupted_files = sum(1 for result in results if result_is_corrupted(result))
    healthy_files = total_files - corrupted_files
    total_bytes = sum(result_size(result) for result in results)
    largest_file_bytes = max((result_size(result) for result in results), default=0)
    corruption_rate_percent = (corrupted_files / total_files * 100.0) if total_files else 0.0

    file_type_counts = Counter(result_type(result) for result in results)
    corrupted_type_counts = Counter(result_type(result) for result in results if result_is_corrupted(result))

    return ScanSummary(
        total_files=total_files,
        corrupted_files=corrupted_files,
        healthy_files=healthy_files,
        total_bytes=total_bytes,
        largest_file_bytes=largest_file_bytes,
        corruption_rate_percent=corruption_rate_percent,
        file_type_counts=tuple(sorted(file_type_counts.items(), key=lambda item: (-item[1], item[0]))),
        corrupted_type_counts=tuple(sorted(corrupted_type_counts.items(), key=lambda item: (-item[1], item[0]))),
    )


def format_summary_text(summary: ScanSummary) -> str:
    lines = [
        "Scan Summary",
        "============",
        f"Total files scanned : {summary.total_files}",
        f"Corrupted files     : {summary.corrupted_files}",
        f"Healthy files       : {summary.healthy_files}",
        f"Total bytes         : {summary.total_bytes:,} ({humanize_bytes(summary.total_bytes)})",
        f"Largest file        : {summary.largest_file_bytes:,} ({humanize_bytes(summary.largest_file_bytes)})",
        f"Corruption rate     : {summary.corruption_rate_percent:.2f}%",
        "",
    ]

    if summary.file_type_counts:
        lines.append("Top File Types")
        lines.append("--------------")
        for file_type, count in summary.file_type_counts[:10]:
            lines.append(f"{file_type:<20} {count}")
        lines.append("")

    if summary.corrupted_type_counts:
        lines.append("Corrupted File Types")
        lines.append("--------------------")
        for file_type, count in summary.corrupted_type_counts[:10]:
            lines.append(f"{file_type:<20} {count}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def build_format_details(result: FileAnalysisResultLike) -> str:
    validation = result_validation(result)
    lines = [
        f"File: {result_path(result)}",
        f"Size: {result_size(result):,} bytes ({humanize_bytes(result_size(result))})",
        f"Type: {result_type(result)}",
        f"Checksum: {result_checksum(result) or 'N/A'}",
        f"Status: {result_status_label(result)}",
        f"Error: {result_error(result) or 'None'}",
        "",
    ]

    if validation is None:
        lines.append("Format Validation: N/A")
        return "\n".join(lines)

    lines.append("Format Validation")
    lines.append("=================")
    lines.append(f"Valid: {bool(getattr(validation, 'is_valid', False))}")
    lines.append(f"Validation Error: {getattr(validation, 'error_message', None) or 'None'}")

    format_info = getattr(validation, "format_info", None)
    if format_info:
        lines.append("")
        lines.append("Format Information")
        lines.append("------------------")
        for key, value in sorted(format_info.items(), key=lambda item: str(item[0])):
            lines.append(f"{key}: {value}")

    corruption_details = getattr(validation, "corruption_details", None)
    if corruption_details:
        lines.append("")
        lines.append("Corruption Details")
        lines.append("------------------")
        for detail in corruption_details:
            lines.append(f"- {detail}")

    return "\n".join(lines)


def filter_results(
    results: Sequence[FileAnalysisResultLike],
    query: str = "",
    corrupted_only: bool = False,
) -> list[FileAnalysisResultLike]:
    normalized_query = query.strip().casefold()

    def matches(result: FileAnalysisResultLike) -> bool:
        if corrupted_only and not result_is_corrupted(result):
            return False

        if not normalized_query:
            return True

        haystack = " ".join(
            (
                result_path(result),
                result_type(result),
                result_checksum(result),
                result_error(result),
                format_validation_status(result),
                result_status_label(result),
            )
        ).casefold()

        return normalized_query in haystack

    return [result for result in results if matches(result)]


def result_to_export_dict(result: FileAnalysisResultLike) -> dict[str, Any]:
    validation = result_validation(result)
    validation_payload: dict[str, Any] | None = None

    if validation is not None:
        format_info = getattr(validation, "format_info", None)
        corruption_details = getattr(validation, "corruption_details", None)

        validation_payload = {
            "is_valid": bool(getattr(validation, "is_valid", False)),
            "error_message": getattr(validation, "error_message", None),
            "format_info": dict(format_info) if isinstance(format_info, Mapping) else format_info,
            "corruption_details": list(corruption_details or ()),
        }

    return {
        "file_path": result_path(result),
        "file_size": result_size(result),
        "file_type": result_type(result),
        "checksum": result_checksum(result),
        "status": result_status_label(result),
        "is_corrupted": result_is_corrupted(result),
        "error_message": result_error(result) or None,
        "format_status": format_validation_status(result),
        "format_validation": validation_payload,
    }


def build_export_payload(results: Sequence[FileAnalysisResultLike]) -> dict[str, Any]:
    summary = build_scan_summary(results)
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_files": summary.total_files,
            "corrupted_files": summary.corrupted_files,
            "healthy_files": summary.healthy_files,
            "total_bytes": summary.total_bytes,
            "largest_file_bytes": summary.largest_file_bytes,
            "corruption_rate_percent": summary.corruption_rate_percent,
            "file_type_counts": [
                {"file_type": file_type, "count": count}
                for file_type, count in summary.file_type_counts
            ],
            "corrupted_type_counts": [
                {"file_type": file_type, "count": count}
                for file_type, count in summary.corrupted_type_counts
            ],
        },
        "results": [result_to_export_dict(result) for result in results],
    }


def build_text_report(results: Sequence[FileAnalysisResultLike]) -> str:
    summary_text = format_summary_text(build_scan_summary(results))
    details = []

    for result in sorted(results, key=lambda item: result_path(item).casefold()):
        details.append(build_format_details(result))
        details.append("-" * 80)

    detail_text = "\n".join(details).rstrip()
    if detail_text:
        return f"{summary_text}\nDetailed Results\n================\n{detail_text}\n"
    return summary_text


def set_readonly_text(widget: scrolledtext.ScrolledText, text: str) -> None:
    widget.configure(state=tk.NORMAL)
    widget.delete("1.0", tk.END)
    widget.insert(tk.END, text)
    widget.configure(state=tk.DISABLED)


class CIEMainWindow:
    def __init__(
        self,
        root: tk.Tk,
        detector_factory: Callable[[], Any] | None = None,
    ) -> None:
        if detector_factory is None:
            if CORE_ANALYZER_IMPORT_ERROR is not None or CorruptionDetector is None:
                messagebox.showerror(
                    "Import Error",
                    f"Failed to import core analyzer:\n{CORE_ANALYZER_IMPORT_ERROR}",
                )
                root.destroy()
                return

            detector_factory = CorruptionDetector

        self.root = root
        self.detector_factory = detector_factory
        self.detector = detector_factory()

        self.root.title("Corruption Isolation Engine (CIE) - by Kanishk Soni")
        self.root.geometry("1000x700")
        self.root.minsize(960, 640)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.target_directory = tk.StringVar()
        self.search_query = tk.StringVar()
        self.scan_recursive = tk.BooleanVar(value=True)
        self.auto_quarantine = tk.BooleanVar(value=False)
        self.show_only_corrupted_in_all = tk.BooleanVar(value=False)
        self.status_text = tk.StringVar(value="Ready - Corruption Isolation Engine by Kanishk Soni")

        self.current_results: list[FileAnalysisResultLike] = []
        self.scan_running = False
        self._scan_token = 0
        self._cancelled_tokens: set[int] = set()
        self._event_queue: queue.Queue[ScanEvent] = queue.Queue()
        self._active_scan_detector: Any | None = None
        self._active_scan_detector_lock = threading.Lock()
        self._sort_state: dict[str, tuple[str, bool]] = {
            "corrupted": ("path", False),
            "all": ("path", False),
        }

        self._build_style()
        self.create_widgets()
        self.create_menu()
        self._bind_events()
        self._set_scan_state(False)
        self._refresh_text_views()
        self._schedule_event_poll()

    def _build_style(self) -> None:
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")

    def create_menu(self) -> None:
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Select Directory", command=self.select_directory)
        file_menu.add_command(label="Export Report", command=self.export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        tools_menu = tk.Menu(menubar, tearoff=False)
        tools_menu.add_command(label="View Quarantine", command=self.view_quarantine)
        tools_menu.add_command(label="Library Status", command=self.show_library_status)
        tools_menu.add_command(label="Clear Database", command=self.clear_database)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

    def create_widgets(self) -> None:
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.grid(row=0, column=0, sticky="nsew")

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(6, weight=1)

        ttk.Label(main_frame, text="Target Directory:").grid(row=0, column=0, sticky="w", pady=(0, 6))
        ttk.Entry(main_frame, textvariable=self.target_directory).grid(
            row=0, column=1, sticky="ew", padx=(6, 6), pady=(0, 6)
        )
        ttk.Button(main_frame, text="Browse...", command=self.select_directory).grid(row=0, column=2, pady=(0, 6))

        options_frame = ttk.LabelFrame(main_frame, text="Scan Options", padding=8)
        options_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=6)
        options_frame.columnconfigure(3, weight=1)

        ttk.Checkbutton(options_frame, text="Recursive scan", variable=self.scan_recursive).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Checkbutton(options_frame, text="Auto-quarantine corrupted files", variable=self.auto_quarantine).grid(
            row=0, column=1, sticky="w", padx=(16, 0)
        )
        ttk.Checkbutton(
            options_frame,
            text="Show only corrupted in All Files tab",
            variable=self.show_only_corrupted_in_all,
        ).grid(row=0, column=2, sticky="w", padx=(16, 0))

        ttk.Label(options_frame, text="Search:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(options_frame, textvariable=self.search_query).grid(
            row=1, column=1, columnspan=3, sticky="ew", padx=(6, 0), pady=(8, 0)
        )

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=3, sticky="w", pady=(8, 6))

        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 6))

        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 6))

        self.clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=(0, 6))

        self.export_button = ttk.Button(button_frame, text="Export Report", command=self.export_report)
        self.export_button.pack(side=tk.LEFT)

        action_frame = ttk.Frame(main_frame)
        action_frame.grid(row=3, column=0, columnspan=3, sticky="w", pady=(0, 6))

        self.quarantine_selected_button = ttk.Button(
            action_frame, text="Quarantine Selected", command=self.quarantine_selected
        )
        self.quarantine_selected_button.pack(side=tk.LEFT, padx=(0, 6))

        self.delete_selected_button = ttk.Button(
            action_frame, text="Delete Selected", command=self.delete_selected
        )
        self.delete_selected_button.pack(side=tk.LEFT, padx=(0, 6))

        self.quarantine_all_button = ttk.Button(
            action_frame, text="Quarantine All Corrupted", command=self.quarantine_all_corrupted
        )
        self.quarantine_all_button.pack(side=tk.LEFT, padx=(0, 6))

        self.delete_all_button = ttk.Button(
            action_frame, text="Delete All Corrupted", command=self.delete_all_corrupted
        )
        self.delete_all_button.pack(side=tk.LEFT)

        self.progress_bar = ttk.Progressbar(main_frame, mode="indeterminate")
        self.progress_bar.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(0, 6))

        ttk.Label(main_frame, textvariable=self.status_text).grid(row=5, column=0, columnspan=3, sticky="w")
        
        # Author credit label
        author_label = ttk.Label(main_frame, text="Created by Kanishk Soni", font=('TkDefaultFont', 8))
        author_label.grid(row=5, column=2, sticky="e", padx=(0, 5))

        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=6, column=0, columnspan=3, sticky="nsew", pady=(8, 0))

        self.summary_frame = ttk.Frame(self.notebook)
        self.corrupted_frame = ttk.Frame(self.notebook)
        self.all_files_frame = ttk.Frame(self.notebook)
        self.format_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.summary_frame, text="Summary")
        self.notebook.add(self.corrupted_frame, text="Corrupted Files")
        self.notebook.add(self.all_files_frame, text="All Files")
        self.notebook.add(self.format_frame, text="Format Details")

        self.summary_text = scrolledtext.ScrolledText(self.summary_frame, wrap=tk.WORD)
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self.corrupted_tree = self._build_tree(self.corrupted_frame, "corrupted")
        self.all_files_tree = self._build_tree(self.all_files_frame, "all")

        self.format_text = scrolledtext.ScrolledText(self.format_frame, wrap=tk.WORD)
        self.format_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self._setup_context_menu()

    def _build_tree(self, parent: ttk.Frame, tree_key: str) -> ttk.Treeview:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)

        tree = ttk.Treeview(
            parent,
            columns=[column.key for column in TREE_COLUMNS],
            show="headings",
            selectmode="extended",
        )

        for column in TREE_COLUMNS:
            tree.heading(
                column.key,
                text=column.title,
                command=lambda current_key=tree_key, current_column=column.key: self._toggle_sort(
                    current_key, current_column
                ),
            )
            tree.column(column.key, width=column.width, stretch=column.stretch)

        vertical_scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=tree.yview)
        horizontal_scrollbar = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=vertical_scrollbar.set, xscrollcommand=horizontal_scrollbar.set)

        tree.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)
        vertical_scrollbar.grid(row=0, column=1, sticky="ns", pady=6)
        horizontal_scrollbar.grid(row=1, column=0, sticky="ew", padx=6)

        tree.tag_configure("healthy", background="#f3fff3")
        tree.tag_configure("corrupted", background="#fff2f2")

        return tree

    def _setup_context_menu(self) -> None:
        self.context_menu = tk.Menu(self.root, tearoff=False)
        self.context_menu.add_command(label="Quarantine", command=self.quarantine_selected)
        self.context_menu.add_command(label="Delete", command=self.delete_selected)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="View Format Details", command=self.show_format_details)
        self.context_menu.add_command(label="Open File Location", command=self.open_file_location)
        self.context_menu.add_command(label="Copy Path", command=self.copy_file_path)

    def _bind_events(self) -> None:
        self.search_query.trace_add("write", lambda *_: self.refresh_views())
        self.show_only_corrupted_in_all.trace_add("write", lambda *_: self.refresh_views())

        for tree in (self.corrupted_tree, self.all_files_tree):
            tree.bind("<<TreeviewSelect>>", self._on_tree_selection_changed)
            tree.bind("<Double-1>", lambda _event: self.show_format_details())
            tree.bind("<Button-3>", self.show_context_menu)
            tree.bind("<Control-Button-1>", self.show_context_menu)

    def _schedule_event_poll(self) -> None:
        self.root.after(UI_EVENT_POLL_MS, self._process_ui_events)

    def _process_ui_events(self) -> None:
        try:
            while True:
                event = self._event_queue.get_nowait()
                if isinstance(event, ScanCompletedEvent):
                    self._handle_scan_completed(event)
                else:
                    self._handle_scan_failed(event)
        except queue.Empty:
            pass
        finally:
            try:
                self._schedule_event_poll()
            except tk.TclError:
                return

    def _set_scan_state(self, running: bool) -> None:
        self.scan_running = running
        self.scan_button.config(state=tk.DISABLED if running else tk.NORMAL)
        self.stop_button.config(state=tk.NORMAL if running else tk.DISABLED)

        other_buttons_state = tk.DISABLED if running else tk.NORMAL
        for button in (
            self.clear_button,
            self.export_button,
            self.quarantine_selected_button,
            self.delete_selected_button,
            self.quarantine_all_button,
            self.delete_all_button,
        ):
            button.config(state=other_buttons_state)

        if running:
            self.progress_bar.start(12)
        else:
            self.progress_bar.stop()

    def _set_status(self, message: str) -> None:
        self.status_text.set(message)

    def _refresh_text_views(self) -> None:
        summary = format_summary_text(build_scan_summary(self.current_results))
        set_readonly_text(self.summary_text, summary)
        set_readonly_text(self.format_text, "Select a file to view format details.")

    def _toggle_sort(self, tree_key: str, column_key: str) -> None:
        current_column, descending = self._sort_state[tree_key]
        next_descending = not descending if current_column == column_key else False
        self._sort_state[tree_key] = (column_key, next_descending)
        self.refresh_views()

    def _sorted_results(
        self,
        results: Sequence[FileAnalysisResultLike],
        tree_key: str,
    ) -> list[FileAnalysisResultLike]:
        column_key, descending = self._sort_state[tree_key]

        def sort_key(result: FileAnalysisResultLike) -> Any:
            if column_key == "path":
                return result_path(result).casefold()
            if column_key == "size":
                return result_size(result)
            if column_key == "type":
                return result_type(result).casefold()
            if column_key == "checksum":
                return result_checksum(result).casefold()
            if column_key == "format":
                return format_validation_status(result).casefold()
            if column_key == "status":
                return result_status_label(result).casefold()
            if column_key == "error":
                return result_error(result).casefold()
            return result_path(result).casefold()

        return sorted(results, key=sort_key, reverse=descending)

    def _tree_values(self, result: FileAnalysisResultLike) -> tuple[str, str, str, str, str, str, str]:
        return (
            result_path(result),
            f"{result_size(result):,}",
            result_type(result),
            result_checksum(result),
            format_validation_status(result),
            result_status_label(result),
            result_error(result),
        )

    def _populate_tree(
        self,
        tree: ttk.Treeview,
        results: Sequence[FileAnalysisResultLike],
        tree_key: str,
    ) -> None:
        tree.delete(*tree.get_children())
        for result in self._sorted_results(results, tree_key):
            tags = ("corrupted",) if result_is_corrupted(result) else ("healthy",)
            tree.insert("", tk.END, values=self._tree_values(result), tags=tags)

    def refresh_views(self) -> None:
        filtered_results = filter_results(self.current_results, query=self.search_query.get())
        corrupted_results = [result for result in filtered_results if result_is_corrupted(result)]

        all_tab_results = (
            corrupted_results if self.show_only_corrupted_in_all.get() else filtered_results
        )

        self._populate_tree(self.corrupted_tree, corrupted_results, "corrupted")
        self._populate_tree(self.all_files_tree, all_tab_results, "all")

        summary = build_scan_summary(self.current_results)
        summary_text = format_summary_text(summary)
        visible_note = (
            f"\nVisible rows: {len(filtered_results)} of {len(self.current_results)}"
            if self.search_query.get().strip() or self.show_only_corrupted_in_all.get()
            else ""
        )
        set_readonly_text(self.summary_text, summary_text.rstrip() + visible_note + "\n")

        self._set_status(
            f"Ready | Files: {summary.total_files} | Corrupted: {summary.corrupted_files} | Visible: {len(filtered_results)}"
        )

    def select_directory(self) -> None:
        directory = filedialog.askdirectory(title="Select Target Directory")
        if directory:
            self.target_directory.set(directory)

    def start_scan(self) -> None:
        directory_text = self.target_directory.get().strip()
        if not directory_text:
            messagebox.showerror("Error", "Please select a target directory.")
            return

        directory = Path(directory_text)
        if not directory.exists() or not directory.is_dir():
            messagebox.showerror("Error", "Invalid directory path.")
            return

        self.clear_results(silent=True)
        self._scan_token += 1
        token = self._scan_token

        self._set_scan_state(True)
        self._set_status(f"Scanning {directory} ...")

        worker = threading.Thread(
            target=self._scan_directory_worker,
            args=(token, directory, self.scan_recursive.get()),
            daemon=True,
            name=f"cie-scan-{token}",
        )
        worker.start()

    def _scan_directory_worker(self, token: int, directory: Path, recursive: bool) -> None:
        scan_detector = self.detector_factory()

        with self._active_scan_detector_lock:
            self._active_scan_detector = scan_detector

        try:
            results = list(scan_detector.scan_directory(str(directory), recursive))
            self._event_queue.put(ScanCompletedEvent(token=token, results=results))
        except Exception as exc:
            LOGGER.exception("Directory scan failed")
            self._event_queue.put(ScanFailedEvent(token=token, error_message=str(exc)))
        finally:
            with self._active_scan_detector_lock:
                if self._active_scan_detector is scan_detector:
                    self._active_scan_detector = None

    def _handle_scan_completed(self, event: ScanCompletedEvent) -> None:
        if event.token != self._scan_token:
            return

        cancelled = event.token in self._cancelled_tokens
        self._cancelled_tokens.discard(event.token)
        self._set_scan_state(False)

        if cancelled:
            self._set_status("Scan stopped.")
            return

        self.current_results = sorted(event.results, key=lambda result: result_path(result).casefold())
        auto_quarantined = 0

        if self.auto_quarantine.get():
            corrupted_paths = [result_path(result) for result in self.current_results if result_is_corrupted(result)]
            if corrupted_paths:
                auto_quarantined, _ = self._apply_file_action(
                    file_paths=corrupted_paths,
                    action_name="quarantine",
                    executor=self._quarantine_file,
                    confirm=False,
                    success_message=False,
                )

        self.refresh_views()

        summary = build_scan_summary(self.current_results)
        status_message = (
            f"Scan complete: {summary.corrupted_files} corrupted of {summary.total_files} files"
        )
        if auto_quarantined:
            status_message += f" | Auto-quarantined: {auto_quarantined}"
        self._set_status(status_message)

        if summary.corrupted_files > 0:
            messagebox.showwarning(
                "Corruption Detected",
                f"Found {summary.corrupted_files} corrupted file(s).",
            )

    def _handle_scan_failed(self, event: ScanFailedEvent) -> None:
        if event.token != self._scan_token:
            return

        self._cancelled_tokens.discard(event.token)
        self._set_scan_state(False)
        self._set_status("Scan failed.")
        messagebox.showerror("Scan Error", f"Scan failed:\n{event.error_message}")

    def stop_scan(self) -> None:
        if not self.scan_running:
            return

        self._cancelled_tokens.add(self._scan_token)
        self.stop_button.config(state=tk.DISABLED)
        self._set_status("Stop requested. Waiting for current scan to finish...")

        detector = None
        with self._active_scan_detector_lock:
            detector = self._active_scan_detector

        if detector is None:
            return

        for method_name in ("cancel_scan", "request_stop", "stop_scan", "stop", "cancel"):
            method = getattr(detector, method_name, None)
            if callable(method):
                try:
                    method()
                    break
                except Exception:
                    LOGGER.exception("Failed to request scan stop via detector method %s", method_name)

    def clear_results(self, silent: bool = False) -> None:
        self.current_results = []
        self.corrupted_tree.delete(*self.corrupted_tree.get_children())
        self.all_files_tree.delete(*self.all_files_tree.get_children())
        self._refresh_text_views()
        if not silent:
            self._set_status("Results cleared.")

    def _active_tree(self) -> ttk.Treeview | None:
        current_tab = self.notebook.index(self.notebook.select())
        if current_tab == 1:
            return self.corrupted_tree
        if current_tab == 2:
            return self.all_files_tree
        return None

    def get_selected_files(self) -> list[str]:
        tree = self._active_tree()
        if tree is None:
            return []

        file_paths: list[str] = []
        for item_id in tree.selection():
            values = tree.item(item_id, "values")
            if values:
                file_paths.append(str(values[0]))

        seen: set[str] = set()
        unique_paths: list[str] = []
        for path in file_paths:
            if path not in seen:
                seen.add(path)
                unique_paths.append(path)
        return unique_paths

    def _result_by_path(self, file_path: str) -> FileAnalysisResultLike | None:
        for result in self.current_results:
            if result_path(result) == file_path:
                return result
        return None

    def _selected_result(self) -> FileAnalysisResultLike | None:
        selected_files = self.get_selected_files()
        if not selected_files:
            return None
        return self._result_by_path(selected_files[0])

    def _on_tree_selection_changed(self, _event: tk.Event[Any]) -> None:
        result = self._selected_result()
        if result is None:
            set_readonly_text(self.format_text, "Select a file to view format details.")
            return
        set_readonly_text(self.format_text, build_format_details(result))

    def show_context_menu(self, event: tk.Event[Any]) -> None:
        tree = event.widget
        if not isinstance(tree, ttk.Treeview):
            return

        item_id = tree.identify_row(event.y)
        if item_id:
            tree.selection_set(item_id)
            self.context_menu.tk_popup(event.x_root, event.y_root)

    def show_format_details(self) -> None:
        result = self._selected_result()
        if result is None:
            messagebox.showinfo("Format Details", "Please select a file first.")
            return

        set_readonly_text(self.format_text, build_format_details(result))
        self.notebook.select(self.format_frame)

    def open_file_location(self) -> None:
        selected_files = self.get_selected_files()
        if not selected_files:
            return

        target = Path(selected_files[0])
        if not target.exists():
            messagebox.showwarning("Missing File", f"File no longer exists:\n{target}")
            return

        try:
            if sys.platform == "win32":
                subprocess.Popen(["explorer", f"/select,{target}"])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-R", str(target)])
            else:
                subprocess.Popen(["xdg-open", str(target.parent)])
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to open file location:\n{exc}")

    def copy_file_path(self) -> None:
        selected_files = self.get_selected_files()
        if not selected_files:
            return

        payload = "\n".join(selected_files)
        self.root.clipboard_clear()
        self.root.clipboard_append(payload)
        self._set_status(f"Copied {len(selected_files)} path(s) to clipboard.")

    def _drop_results(self, removed_paths: set[str]) -> None:
        self.current_results = [
            result for result in self.current_results if result_path(result) not in removed_paths
        ]

    def _quarantine_file(self, file_path: str) -> bool:
        return bool(self.detector.quarantine_file(file_path))

    def _delete_file(self, file_path: str) -> bool:
        path = Path(file_path)
        if not path.exists():
            return False
        path.unlink()
        return True

    def _apply_file_action(
        self,
        file_paths: Sequence[str],
        action_name: str,
        executor: Callable[[str], bool],
        *,
        confirm: bool,
        success_message: bool,
    ) -> tuple[int, int]:
        unique_paths = tuple(dict.fromkeys(file_paths))
        if not unique_paths:
            return 0, 0

        if confirm:
            action_label = action_name.capitalize()
            destructive_note = "\n\nThis action cannot be undone." if action_name == "delete" else ""
            approved = messagebox.askyesno(
                f"Confirm {action_label}",
                f"{action_label} {len(unique_paths)} selected file(s)?{destructive_note}",
            )
            if not approved:
                return 0, 0

        succeeded: list[str] = []
        failures: list[str] = []

        for file_path in unique_paths:
            try:
                if executor(file_path):
                    succeeded.append(file_path)
                else:
                    failures.append(f"{file_path}: operation returned false")
            except Exception as exc:
                failures.append(f"{file_path}: {exc}")

        if succeeded:
            self._drop_results(set(succeeded))
            self.refresh_views()

        status_message = f"{action_name.capitalize()} complete: {len(succeeded)} succeeded, {len(failures)} failed."
        self._set_status(status_message)

        if success_message:
            if failures:
                failure_preview = "\n".join(failures[:5])
                extra = "\n..." if len(failures) > 5 else ""
                messagebox.showwarning(
                    "Partial Success",
                    f"{status_message}\n\nFailures:\n{failure_preview}{extra}",
                )
            else:
                messagebox.showinfo("Success", status_message)

        return len(succeeded), len(failures)

    def quarantine_selected(self) -> None:
        selected_files = self.get_selected_files()
        if not selected_files:
            messagebox.showwarning("No Selection", "Please select files to quarantine.")
            return

        self._apply_file_action(
            file_paths=selected_files,
            action_name="quarantine",
            executor=self._quarantine_file,
            confirm=True,
            success_message=True,
        )

    def delete_selected(self) -> None:
        selected_files = self.get_selected_files()
        if not selected_files:
            messagebox.showwarning("No Selection", "Please select files to delete.")
            return

        self._apply_file_action(
            file_paths=selected_files,
            action_name="delete",
            executor=self._delete_file,
            confirm=True,
            success_message=True,
        )

    def quarantine_all_corrupted(self) -> None:
        corrupted_files = [result_path(result) for result in self.current_results if result_is_corrupted(result)]
        if not corrupted_files:
            messagebox.showinfo("No Corrupted Files", "No corrupted files to quarantine.")
            return

        self._apply_file_action(
            file_paths=corrupted_files,
            action_name="quarantine",
            executor=self._quarantine_file,
            confirm=True,
            success_message=True,
        )

    def delete_all_corrupted(self) -> None:
        corrupted_files = [result_path(result) for result in self.current_results if result_is_corrupted(result)]
        if not corrupted_files:
            messagebox.showinfo("No Corrupted Files", "No corrupted files to delete.")
            return

        self._apply_file_action(
            file_paths=corrupted_files,
            action_name="delete",
            executor=self._delete_file,
            confirm=True,
            success_message=True,
        )

    def _quarantine_directory(self) -> Path:
        for attribute_name in ("quarantine_dir", "quarantine_path"):
            value = getattr(self.detector, attribute_name, None)
            if value:
                return Path(value)
        return Path("quarantine")

    def view_quarantine(self) -> None:
        """List quarantined files from the quarantine log, with Restore.

        The original viewer listed whatever happened to sit in the quarantine
        directory and offered no way to act on it, so a quarantined file could
        only be recovered by hand-editing the database.
        """
        quarantine_dir = self._quarantine_directory()
        try:
            entries = list(self.detector.list_quarantine())
        except Exception as exc:
            messagebox.showerror("Quarantine", f"Could not read the quarantine log:\n{exc}")
            return

        stray_files = []
        if quarantine_dir.exists():
            known = {Path(entry.quarantine_path).name for entry in entries}
            stray_files = sorted(
                (path for path in quarantine_dir.iterdir() if path.name not in known),
                key=lambda path: path.name.casefold(),
            )

        if not entries and not stray_files:
            messagebox.showinfo("Quarantine", "Quarantine is empty.")
            return

        viewer = tk.Toplevel(self.root)
        viewer.title("Quarantine Viewer")
        viewer.geometry("860x500")
        viewer.transient(self.root)

        frame = ttk.Frame(viewer, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            frame,
            text="Select one or more files to restore. Files are put back at their "
                 "original location (without overwriting anything).",
        ).pack(anchor=tk.W, pady=(0, 6))

        listbox = tk.Listbox(frame, selectmode=tk.EXTENDED)
        listbox.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=listbox.yview)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y)
        listbox.configure(yscrollcommand=scrollbar.set)

        # index -> callable that performs the restore for that row
        actions: dict[int, Path] = {}
        for entry in entries:
            when = entry.quarantined_at.strftime("%Y-%m-%d %H:%M") if entry.quarantined_at else "?"
            listbox.insert(
                tk.END,
                f"{Path(entry.quarantine_path).name}  <-  {entry.original_path}  "
                f"[{when}]  {entry.reason}",
            )
            actions[listbox.size() - 1] = Path(entry.quarantine_path)
        for path in stray_files:
            listbox.insert(tk.END, f"{path.name}  (not in the quarantine log - cannot be restored)")
            actions[listbox.size() - 1] = None  # type: ignore[assignment]

        button_row = ttk.Frame(viewer, padding=(10, 0, 10, 10))
        button_row.pack(fill=tk.X)

        def restore_selected() -> None:
            selection = listbox.curselection()
            if not selection:
                messagebox.showwarning("No Selection", "Please select a file to restore.")
                return
            restored, skipped, failures = [], [], []
            for index in selection:
                quarantine_path = actions.get(index)
                if quarantine_path is None:
                    skipped.append(listbox.get(index).split("  ")[0])
                    continue
                try:
                    restored.append(self.detector.restore_file(quarantine_path))
                except Exception as exc:
                    failures.append(f"{quarantine_path.name}: {exc}")

            lines = []
            if restored:
                lines.append("Restored:\n" + "\n".join(f"  {path}" for path in restored))
            if skipped:
                lines.append("Not in the quarantine log (left in place):\n"
                             + "\n".join(f"  {name}" for name in skipped))
            if failures:
                lines.append("Failed:\n" + "\n".join(f"  {failure}" for failure in failures))

            (messagebox.showwarning if failures else messagebox.showinfo)(
                "Restore", "\n\n".join(lines) or "Nothing to restore."
            )
            viewer.destroy()
            if restored:
                self.refresh_views()

        ttk.Button(button_row, text="Restore Selected", command=restore_selected).pack(side=tk.RIGHT)
        ttk.Button(button_row, text="Close", command=viewer.destroy).pack(
            side=tk.RIGHT, padx=(0, 6)
        )


    def show_library_status(self) -> None:
        try:
            library_status = dict(self.detector.get_library_status())
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to load library status:\n{exc}")
            return

        lines = [
            "Format Validation Library Status",
            "================================",
            "",
        ]

        for library_name in sorted(library_status):
            status_text = "Available" if library_status[library_name] else "Not Available"
            lines.append(f"{library_name}: {status_text}")

        if not any(library_status.values()):
            lines.extend(
                (
                    "",
                    "No format validation libraries are available.",
                    "Install them with: pip install -r requirements.txt",
                )
            )

        messagebox.showinfo("Library Status", "\n".join(lines))

    def clear_database(self) -> None:
        approved = messagebox.askyesno(
            "Clear Database",
            "Are you sure you want to clear all analysis data?",
        )
        if not approved:
            return

        database_path = Path(getattr(self.detector, "database_path", ""))
        try:
            if database_path:
                database_path.unlink(missing_ok=True)
            init_method = getattr(self.detector, "_init_database", None)
            if callable(init_method):
                init_method()
            messagebox.showinfo("Success", "Database cleared successfully.")
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to clear database:\n{exc}")

    def export_report(self) -> None:
        if not self.current_results:
            messagebox.showinfo("Export Report", "There are no results to export.")
            return

        filename = filedialog.asksaveasfilename(
            title="Export Report",
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"),
                ("Text files", "*.txt"),
                ("All files", "*.*"),
            ],
        )

        if not filename:
            return

        path = Path(filename)
        try:
            if path.suffix.lower() == ".txt":
                path.write_text(build_text_report(self.current_results), encoding="utf-8")
            else:
                payload = build_export_payload(self.current_results)
                path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            messagebox.showinfo("Success", f"Report exported to:\n{path}")
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to export report:\n{exc}")

    def show_about(self) -> None:
        """Show about dialog"""
        about_text = """Corruption Isolation Engine (CIE)
Version 2.0

This Project Is Made By Kanishk Soni

A desktop tool for scanning directories, detecting corrupted files,
quarantining suspicious items, and exporting structured reports."""
        
        messagebox.showinfo("About CIE", about_text)

    def on_close(self) -> None:
        if self.scan_running:
            approved = messagebox.askyesno(
                "Quit",
                "A scan is still running. Quit anyway?",
            )
            if not approved:
                return
        self.root.destroy()


def main() -> int:
    logging.basicConfig(level=logging.INFO)

    if CORE_ANALYZER_IMPORT_ERROR is not None or CorruptionDetector is None:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Startup Error",
            f"Failed to import core_analyzer:\n{CORE_ANALYZER_IMPORT_ERROR}",
        )
        root.destroy()
        return 1

    root = tk.Tk()
    CIEMainWindow(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())