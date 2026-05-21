#!/usr/bin/env python3

################################

# terminal commands
# python duplicate_user_scan.py [file path] --per-owner-files
# python duplicate_user_scan.py [file path] [user handle] --per-owner-files

cd /network/iss/levy/analyze/vol1e/sara
python duplicate_user_scan.py /network/iss/levy/analyze/vol1e --user Victor.Altmayer --per-owner-files

################################

import argparse
import csv
import hashlib
import os
import pwd
import shutil
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    import blake3
except ImportError:
    blake3 = None


DEFAULT_OUTPUT_DIRNAME = "user_reports"
DEFAULT_QUARANTINE_DIRNAME = "quarantined_duplicates"

EXCLUDED_NAMES = {
    ".git", ".venv", "venv", "env", "__pycache__", ".cache",
    "node_modules", "site-packages", ".nim_quarantine",
    "quarantined_duplicates", "reports", "user_reports"
}


def progress_bar(current: int, total: int, width: int = 30) -> str:
    if total <= 0:
        return "[" + "?" * width + "]"
    ratio = min(max(current / total, 0), 1)
    filled = int(width * ratio)
    bar = "█" * filled + "-" * (width - filled)
    return f"[{bar}] {ratio * 100:5.1f}%"


def activity_bar(count: int, width: int = 20) -> str:
    filled = (count // 100) % (width + 1)
    return "[" + "█" * filled + "-" * (width - filled) + "]"


def shorten_path(path: Path, max_len: int = 90) -> str:
    text = str(path)
    if len(text) <= max_len:
        return text
    return "..." + text[-(max_len - 3):]


def safe_name(text: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in text)


def bytes_to_human(num_bytes: float) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(num_bytes)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.2f} {unit}"
        size /= 1024


def resolve_hash_algorithm(algorithm: str) -> str:
    if algorithm == "auto":
        if blake3 is not None:
            return "blake3"
        print("BLAKE3 not installed. Falling back to SHA256.", flush=True)
        return "sha256"

    if algorithm == "blake3" and blake3 is None:
        print("WARNING: BLAKE3 requested but not installed. Falling back to SHA256.", flush=True)
        return "sha256"

    return algorithm


def compute_hash(path: Path, algorithm: str) -> str:
    if algorithm == "blake3":
        h = blake3.blake3()
    elif algorithm == "sha256":
        h = hashlib.sha256()
    else:
        raise ValueError("Unsupported hash algorithm.")

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


def get_file_metadata(path: Path) -> dict:
    stat = path.stat()

    try:
        owner = pwd.getpwuid(stat.st_uid).pw_name
    except Exception:
        owner = str(stat.st_uid)

    return {
        "owner_username": owner,
        "last_opened": datetime.fromtimestamp(stat.st_atime).isoformat(timespec="seconds"),
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
        "created_or_metadata_changed": datetime.fromtimestamp(stat.st_ctime).isoformat(timespec="seconds"),
    }


def should_skip(path: Path, root: Path, skip_symlinks: bool) -> bool:
    if skip_symlinks and path.is_symlink():
        return True

    try:
        rel_parts = [p.lower() for p in path.relative_to(root).parts]
    except Exception:
        rel_parts = [p.lower() for p in path.parts]

    return any(part in EXCLUDED_NAMES for part in rel_parts)


def collect_files(root: Path, max_mb: float, skip_symlinks: bool, requested_users):
    max_bytes = int(max_mb * 1024 * 1024)

    files = []

    skipped_empty = 0
    skipped_large = 0
    skipped_symlink_or_excluded = 0
    skipped_permission = 0
    skipped_unreadable = 0
    skipped_user_filter = 0

    dirs_scanned = 0
    files_seen = 0
    last_print = time.time()
    spinner = ["|", "/", "-", "\\"]
    spin_idx = 0

    print()
    print("Collecting files...")
    print(f"Maximum file size included: {max_mb:,.0f} MB")

    if requested_users:
        print("User filter enabled:")
        print(", ".join(sorted(requested_users)))

    print("Discovery progress is activity-based because total file count is unknown at this stage.")
    print()

    for dirpath, dirnames, filenames in os.walk(root):
        dirs_scanned += 1
        files_seen += len(filenames)

        current = Path(dirpath)

        dirnames[:] = [
            d for d in dirnames
            if d.lower() not in EXCLUDED_NAMES
        ]

        for filename in filenames:
            path = current / filename

            try:
                if should_skip(path, root, skip_symlinks):
                    skipped_symlink_or_excluded += 1
                    continue

                if not path.is_file():
                    continue

                stat = path.stat()
                size = stat.st_size

                if size <= 0:
                    skipped_empty += 1
                    continue

                if size > max_bytes:
                    skipped_large += 1
                    continue

                try:
                    owner = pwd.getpwuid(stat.st_uid).pw_name
                except Exception:
                    owner = str(stat.st_uid)

                if requested_users and owner.lower() not in requested_users:
                    skipped_user_filter += 1
                    continue

                files.append(path)

            except PermissionError:
                skipped_permission += 1
                continue

            except Exception:
                skipped_unreadable += 1
                continue

        if time.time() - last_print >= 1:
            symbol = spinner[spin_idx % len(spinner)]
            spin_idx += 1

            print(
                f"\r{symbol} Discovering {activity_bar(dirs_scanned)} | "
                f"directory: {shorten_path(current, 70)} | "
                f"dirs: {dirs_scanned:,} | "
                f"seen: {files_seen:,} | "
                f"kept: {len(files):,} | "
                f"user-filtered: {skipped_user_filter:,} | "
                f"perm: {skipped
