#!/usr/bin/env python3

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


DEFAULT_REPORT_DIRNAME = "reports"

EXCLUDED_NAMES = {
    ".git", ".venv", "venv", "env", "__pycache__", ".cache",
    "node_modules", "site-packages", ".nim_quarantine",
    "quarantined_duplicates"
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


def shorten_path(path: Path, max_len: int = 100) -> str:
    text = str(path)
    if len(text) <= max_len:
        return text
    return "..." + text[-(max_len - 3):]


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


def should_skip(path: Path, root: Path, skip_symlinks: bool) -> bool:
    if skip_symlinks and path.is_symlink():
        return True

    try:
        rel_parts = [p.lower() for p in path.relative_to(root).parts]
    except Exception:
        rel_parts = [p.lower() for p in path.parts]

    return any(part in EXCLUDED_NAMES for part in rel_parts)


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


def collect_files(root: Path, max_mb: float, skip_symlinks: bool):
    max_bytes = int(max_mb * 1024 * 1024)

    files = []

    skipped_empty = 0
    skipped_large = 0
    skipped_symlink_or_excluded = 0
    skipped_permission = 0
    skipped_unreadable = 0

    dirs_scanned = 0
    files_seen = 0
    last_print = time.time()
    spinner = ["|", "/", "-", "\\"]
    spin_idx = 0

    print()
    print("Collecting files...")
    print(f"Maximum file size included: {max_mb:,.0f} MB")
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

                size = path.stat().st_size

                if size <= 0:
                    skipped_empty += 1
                    continue

                if size > max_bytes:
                    skipped_large += 1
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
                f"large: {skipped_large:,} | "
                f"perm: {skipped_permission:,} | "
                f"unreadable: {skipped_unreadable:,}",
                end="",
                flush=True
            )
            last_print = time.time()

    print()
    print()
    print("File collection complete.")
    print(f"Directories scanned: {dirs_scanned:,}")
    print(f"Files seen: {files_seen:,}")
    print(f"Files kept for duplicate analysis: {len(files):,}")
    print(f"Skipped empty files: {skipped_empty:,}")
    print(f"Skipped large files: {skipped_large:,}")
    print(f"Skipped excluded/symlink files: {skipped_symlink_or_excluded:,}")
    print(f"Skipped permission denied: {skipped_permission:,}")
    print(f"Skipped unreadable/other files: {skipped_unreadable:,}")

    return files, {
        "dirs_scanned": dirs_scanned,
        "files_seen": files_seen,
        "skipped_empty": skipped_empty,
        "skipped_large": skipped_large,
        "skipped_symlink_or_excluded": skipped_symlink_or_excluded,
        "skipped_permission": skipped_permission,
        "skipped_unreadable": skipped_unreadable,
    }


def choose_keep_file(paths):
    return sorted(paths, key=lambda p: (-p.stat().st_mtime, len(str(p))))[0]


def safe_quarantine_path(root: Path, original: Path, group_id: int) -> Path:
    quarantine_root = root / "quarantined_duplicates"
    relative = original.relative_to(root)
    target = quarantine_root / f"group_{group_id:05d}" / relative

    counter = 1
    final_target = target

    while final_target.exists():
        final_target = target.with_name(
            f"{target.stem}__duplicate_{counter}{target.suffix}"
        )
        counter += 1

    return final_target


def write_csv(rows, output_csv: Path):
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "duplicate_group_id",
        "recommended_action",
        "quarantine_recommended",
        "keep_file",
        "candidate_file",
        "quarantine_target",
        "owner_username",
        "last_opened",
        "modified",
        "created_or_metadata_changed",
        "hash_algorithm",
        "content_hash",
        "size_bytes",
        "size_mb",
        "reason",
    ]

    with output_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def scan_duplicates(root: Path, algorithm: str, max_mb: float, skip_symlinks: bool):
    resolved_algorithm = resolve_hash_algorithm(algorithm)

    print(f"Scanning root: {root}")
    print("Mode: read-only scan first")
    print("No files will be moved unless you confirm quarantine later.")
    print(f"Hash algorithm: {resolved_algorithm.upper()}")

    files, collection_stats = collect_files(
        root=root,
        max_mb=max_mb,
        skip_symlinks=skip_symlinks
    )

    print()
    print("Grouping files by exact file size...")

    by_size = defaultdict(list)
    for path in files:
        try:
            by_size[path.stat().st_size].append(path)
        except Exception:
            continue

    candidate_groups = [
        (size, same_size_files)
        for size, same_size_files in by_size.items()
        if len(same_size_files) >= 2
    ]

    total_candidate_files = sum(len(paths) for _, paths in candidate_groups)

    print(f"Total size groups: {len(by_size):,}")
    print(f"Candidate size groups with >=2 files: {len(candidate_groups):,}")
    print(f"Candidate files requiring hashing: {total_candidate_files:,}")

    by_hash = defaultdict(list)

    hash_errors = 0
    permission_hash_errors = 0
    hashed_files = 0

    live_duplicate_groups = 0
    live_duplicate_files = 0

    last_print = time.time()

    print()
    print("Hashing candidate files...")

    for group_idx, (size, same_size_files) in enumerate(candidate_groups, start=1):
        for path in same_size_files:
            try:
                digest = compute_hash(path, resolved_algorithm)

                key = (size, digest)
                before = len(by_hash[key])

                by_hash[key].append(path)

                after = len(by_hash[key])
                hashed_files += 1

                if before == 1 and after == 2:
                    live_duplicate_groups += 1
                    live_duplicate_files += 2
                elif after > 2:
                    live_duplicate_files += 1

            except PermissionError:
                permission_hash_errors += 1

            except Exception as e:
                hash_errors += 1
                print()
                print(f"Skipped unreadable/hash-failed file: {path} ({e})", flush=True)

            if time.time() - last_print >= 1:
                bar = progress_bar(hashed_files, total_candidate_files)

                print(
                    f"\rHashing {bar} | "
                    f"current: {shorten_path(path, 70)} | "
                    f"size-groups: {group_idx:,}/{len(candidate_groups):,} | "
                    f"files: {hashed_files:,}/{total_candidate_files:,} | "
                    f"duplicate groups: {live_duplicate_groups:,} | "
                    f"duplicate files: {live_duplicate_files:,} | "
                    f"permission errors: {permission_hash_errors:,} | "
                    f"hash errors: {hash_errors:,}",
                    end="",
                    flush=True
                )
                last_print = time.time()

    print()
    print()
    print("Hashing complete.")
    print(f"Files hashed: {hashed_files:,}")
    print(f"Live duplicate groups detected: {live_duplicate_groups:,}")
    print(f"Live duplicate files detected: {live_duplicate_files:,}")
    print(f"Permission errors during hashing: {permission_hash_errors:,}")
    print(f"Hash/read errors during hashing: {hash_errors:,}")

    rows = []
    group_id = 1

    print()
    print("Building duplicate report...")

    for (size, digest), paths in by_hash.items():
        if len(paths) < 2:
            continue

        keep_file = choose_keep_file(paths)

        for path in sorted(paths, key=lambda p: str(p).lower()):
            try:
                stat = path.stat()
                metadata = get_file_metadata(path)
            except Exception:
                continue

            quarantine = path != keep_file
            quarantine_target = safe_quarantine_path(root, path, group_id) if quarantine else ""

            rows.append({
                "duplicate_group_id": group_id,
                "recommended_action": "QUARANTINE" if quarantine else "KEEP",
                "quarantine_recommended": "YES" if quarantine else "NO_KEEP_THIS_FILE",
                "keep_file": str(keep_file),
                "candidate_file": str(path),
                "quarantine_target": str(quarantine_target),
                "owner_username": metadata["owner_username"],
                "last_opened": metadata["last_opened"],
                "modified": metadata["modified"],
                "created_or_metadata_changed": metadata["created_or_metadata_changed"],
                "hash_algorithm": resolved_algorithm.upper(),
                "content_hash": digest,
                "size_bytes": stat.st_size,
                "size_mb": round(stat.st_size / (1024 ** 2), 3),
                "reason": f"same {resolved_algorithm.upper()} content hash",
            })

        group_id += 1

    diagnostics = {
        **collection_stats,
        "candidate_size_groups": len(candidate_groups),
        "candidate_files_hashed": hashed_files,
        "hash_errors": hash_errors,
        "permission_hash_errors": permission_hash_errors,
        "total_candidate_files": total_candidate_files,
        "hash_algorithm": resolved_algorithm,
        "live_duplicate_groups": live_duplicate_groups,
        "live_duplicate_files": live_duplicate_files,
    }

    return files, rows, diagnostics


def quarantine_files(rows, manifest_csv: Path):
    move_rows = [row for row in rows if row["recommended_action"] == "QUARANTINE"]

    if not move_rows:
        print("No quarantine candidates found.")
        return

    print()
    print("Quarantine information:")
    print("Files will be MOVED, not deleted.")
    print("A manifest CSV will be written so the operation can be reviewed or manually reversed.")
    print("Reversibility depends on permissions and whether files are not modified/moved again later.")
    print()

    answer = input(f"Move {len(move_rows)} files to quarantined_duplicates? Type y or n: ").strip().lower()

    if answer != "y":
        print("Quarantine cancelled. No files were moved.")
        return

    manifest = []

    for row in move_rows:
        src = Path(row["candidate_file"])
        dst = Path(row["quarantine_target"])

        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dst))

            manifest.append({
                **row,
                "quarantine_status": "MOVED",
                "moved_at": datetime.now().isoformat(timespec="seconds"),
            })

            print(f"MOVED: {src} -> {dst}")

        except Exception as e:
            manifest.append({
                **row,
                "quarantine_status": f"FAILED: {e}",
                "moved_at": datetime.now().isoformat(timespec="seconds"),
            })

            print(f"FAILED: {src} ({e})")

    write_csv(manifest, manifest_csv)
    print(f"Quarantine manifest written to: {manifest_csv}")


def main():
    parser = argparse.ArgumentParser(
        description="Flexible read-only duplicate scanner with optional quarantine."
    )

    parser.add_argument("path", help="Root path to scan")

    parser.add_argument(
        "--out",
        default=None,
        help="CSV report output path. Default: timestamped report in ./reports"
    )

    parser.add_argument(
        "--hash",
        choices=["auto", "blake3", "sha256"],
        default="auto",
        help="Hash algorithm. Default: auto, preferring BLAKE3 if installed, otherwise SHA256."
    )

    parser.add_argument(
        "--max-mb",
        type=float,
        default=20000,
        help="Maximum file size in MB to include. Default: 20000 MB."
    )

    parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="Follow symlinks instead of skipping them."
    )

    parser.add_argument(
        "--quarantine",
        action="store_true",
        help="Ask whether to move recommended duplicates."
    )

    parser.add_argument(
        "--manifest",
        default=None,
        help="CSV manifest for quarantined files. Default: timestamped manifest in ./reports."
    )

    args = parser.parse_args()

    root = Path(args.path).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        print(f"Invalid path: {root}", file=sys.stderr)
        sys.exit(1)

    default_report_dir = Path.cwd() / DEFAULT_REPORT_DIRNAME
    default_report_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.out is None:
        output_csv = default_report_dir / f"duplicate_report_{timestamp}.csv"
    else:
        output_csv = Path(args.out).expanduser().resolve()

    if args.manifest is None:
        manifest_csv = default_report_dir / f"quarantine_manifest_{timestamp}.csv"
    else:
        manifest_csv = Path(args.manifest).expanduser().resolve()

    files, rows, diagnostics = scan_duplicates(
        root=root,
        algorithm=args.hash,
        max_mb=args.max_mb,
        skip_symlinks=not args.follow_symlinks,
    )

    write_csv(rows, output_csv)

    groups = len(set(row["duplicate_group_id"] for row in rows))
    quarantine_count = sum(row["recommended_action"] == "QUARANTINE" for row in rows)

    print()
    print("Scan complete.")
    print(f"Hash algorithm used: {diagnostics['hash_algorithm'].upper()}")
    print(f"Directories scanned: {diagnostics['dirs_scanned']:,}")
    print(f"Files seen: {diagnostics['files_seen']:,}")
    print(f"Files kept for analysis: {len(files):,}")
    print(f"Skipped empty files: {diagnostics['skipped_empty']:,}")
    print(f"Skipped large files: {diagnostics['skipped_large']:,}")
    print(f"Skipped excluded/symlink files: {diagnostics['skipped_symlink_or_excluded']:,}")
    print(f"Skipped permission denied: {diagnostics['skipped_permission']:,}")
    print(f"Skipped unreadable/other files: {diagnostics['skipped_unreadable']:,}")
    print(f"Candidate size groups: {diagnostics['candidate_size_groups']:,}")
    print(f"Candidate files hashed: {diagnostics['candidate_files_hashed']:,}")
    print(f"Permission errors during hashing: {diagnostics['permission_hash_errors']:,}")
    print(f"Hash/read errors during hashing: {diagnostics['hash_errors']:,}")
    print(f"Duplicate groups found: {groups:,}")
    print(f"Duplicate files found: {diagnostics['live_duplicate_files']:,}")
    print(f"Rows written: {len(rows):,}")
    print(f"Files recommended for quarantine: {quarantine_count:,}")
    print(f"CSV report: {output_csv}")

    if args.quarantine:
        quarantine_files(rows, manifest_csv)
    else:
        print()
        print("No files were moved.")
        print("To enable interactive quarantine, rerun with: --quarantine")


if __name__ == "__main__":
    main()
