#!/usr/bin/env python3


# terminal commands
# python duplicate_user_scan.py [file path] --per-owner-files
# python duplicate_user_scan.py [file path] [user handle] --per-owner-files

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


def get_owner_username(path: Path) -> str:
    stat = path.stat()
    try:
        return pwd.getpwuid(stat.st_uid).pw_name
    except Exception:
        return str(stat.st_uid)


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
    print(f"Skipped by user filter: {skipped_user_filter:,}")
    print(f"Skipped empty files: {skipped_empty:,}")
    print(f"Skipped large files: {skipped_large:,}")
    print(f"Skipped excluded/symlink files: {skipped_symlink_or_excluded:,}")
    print(f"Skipped permission denied: {skipped_permission:,}")
    print(f"Skipped unreadable/other files: {skipped_unreadable:,}")

    return files, {
        "dirs_scanned": dirs_scanned,
        "files_seen": files_seen,
        "files_kept": len(files),
        "skipped_user_filter": skipped_user_filter,
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

    if not rows:
        output_csv.write_text("", encoding="utf-8")
        return

    fieldnames = list(rows[0].keys())

    with output_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def scan_duplicates(root: Path, algorithm: str, max_mb: float, skip_symlinks: bool, requested_users):
    resolved_algorithm = resolve_hash_algorithm(algorithm)

    print(f"Scanning root: {root}")
    print("Mode: read-only scan first")
    print("No files will be moved unless you confirm quarantine later.")
    print(f"Hash algorithm: {resolved_algorithm.upper()}")

    files, collection_stats = collect_files(
        root=root,
        max_mb=max_mb,
        skip_symlinks=skip_symlinks,
        requested_users=requested_users,
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

    duplicate_rows = []
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

            duplicate_rows.append({
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

    return duplicate_rows, diagnostics


def summarize_by_owner(rows):
    owner_stats = defaultdict(lambda: {
        "duplicate_groups": set(),
        "duplicate_rows_all": 0,
        "keep_rows": 0,
        "quarantine_candidates": 0,
        "duplicate_capacity_bytes_all": 0,
        "quarantine_capacity_bytes": 0,
    })

    total_duplicate_capacity = 0
    total_quarantine_capacity = 0

    for row in rows:
        owner = row.get("owner_username") or "UNKNOWN"
        action = row.get("recommended_action", "")
        group_id = row.get("duplicate_group_id", "")
        size = int(float(row.get("size_bytes", 0) or 0))

        owner_stats[owner]["duplicate_groups"].add(group_id)
        owner_stats[owner]["duplicate_rows_all"] += 1
        owner_stats[owner]["duplicate_capacity_bytes_all"] += size
        total_duplicate_capacity += size

        if action == "QUARANTINE":
            owner_stats[owner]["quarantine_candidates"] += 1
            owner_stats[owner]["quarantine_capacity_bytes"] += size
            total_quarantine_capacity += size
        elif action == "KEEP":
            owner_stats[owner]["keep_rows"] += 1

    summary_rows = []

    for owner, stats in owner_stats.items():
        duplicate_capacity = stats["duplicate_capacity_bytes_all"]
        quarantine_capacity = stats["quarantine_capacity_bytes"]

        summary_rows.append({
            "owner_username": owner,
            "duplicate_groups": len(stats["duplicate_groups"]),
            "duplicate_rows_all": stats["duplicate_rows_all"],
            "keep_rows": stats["keep_rows"],
            "quarantine_candidates": stats["quarantine_candidates"],
            "duplicate_capacity_bytes_all": duplicate_capacity,
            "duplicate_capacity_human_all": bytes_to_human(duplicate_capacity),
            "duplicate_capacity_percent_all": round(
                duplicate_capacity / total_duplicate_capacity * 100, 2
            ) if total_duplicate_capacity else 0,
            "quarantine_capacity_bytes": quarantine_capacity,
            "quarantine_capacity_human": bytes_to_human(quarantine_capacity),
            "quarantine_capacity_percent": round(
                quarantine_capacity / total_quarantine_capacity * 100, 2
            ) if total_quarantine_capacity else 0,
        })

    summary_rows.sort(key=lambda r: r["duplicate_capacity_bytes_all"], reverse=True)

    totals = {
        "total_duplicate_capacity": total_duplicate_capacity,
        "total_quarantine_capacity": total_quarantine_capacity,
        "total_duplicate_rows": len(rows),
        "total_quarantine_rows": sum(1 for r in rows if r.get("recommended_action") == "QUARANTINE"),
    }

    return summary_rows, totals


def write_text_report(summary_rows, totals, output_txt: Path, top_n: int):
    output_txt.parent.mkdir(parents=True, exist_ok=True)

    lines = []
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines.append("=" * 100)
    lines.append("Duplicate file analysis by owner")
    lines.append(f"Date of report: {date}")
    lines.append("=" * 100)
    lines.append("")
    lines.append(f"Total duplicate rows: {totals['total_duplicate_rows']:,}")
    lines.append(f"Total duplicate capacity: {bytes_to_human(totals['total_duplicate_capacity'])}")
    lines.append(f"Total quarantine candidates: {totals['total_quarantine_rows']:,}")
    lines.append(f"Potential reclaimable capacity: {bytes_to_human(totals['total_quarantine_capacity'])}")
    lines.append("")
    lines.append("=" * 100)
    lines.append(f"Capacity of duplicate files by owner, top {top_n}")
    lines.append("=" * 100)
    lines.append("")
    lines.append(f"{'Capacity':>14} {'%':>8} {'Groups':>8} {'Rows':>10} {'Quarantine':>12}  Owner")
    lines.append("-" * 100)

    for row in summary_rows[:top_n]:
        lines.append(
            f"{row['duplicate_capacity_human_all']:>14} "
            f"{row['duplicate_capacity_percent_all']:>7.1f}% "
            f"{row['duplicate_groups']:>8,} "
            f"{row['duplicate_rows_all']:>10,} "
            f"{row['quarantine_candidates']:>12,}  "
            f"{row['owner_username']}"
        )

    output_txt.write_text("\n".join(lines), encoding="utf-8")


def write_per_owner_files(rows, output_dir: Path):
    per_owner_dir = output_dir / "per_owner"
    per_owner_dir.mkdir(parents=True, exist_ok=True)

    grouped = defaultdict(list)

    for row in rows:
        owner = row.get("owner_username") or "UNKNOWN"
        grouped[owner].append(row)

    for owner, owner_rows in grouped.items():
        out_file = per_owner_dir / f"duplicates_{safe_name(owner)}.csv"
        write_csv(owner_rows, out_file)


def quarantine_files(rows, manifest_csv: Path):
    move_rows = [row for row in rows if row["recommended_action"] == "QUARANTINE"]

    if not move_rows:
        print("No quarantine candidates found.")
        return

    print()
    print("Quarantine information:")
    print("Files will be MOVED, not deleted.")
    print("A manifest CSV will be written so the operation can be reviewed or manually reversed.")
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
        description="Full duplicate scan with owner-level reporting."
    )

    parser.add_argument(
        "path",
        help="Target directory to scan."
    )

    parser.add_argument(
        "--user",
        nargs="+",
        default=None,
        help="Restrict scan to one or more owner usernames, e.g. --user Victor.Altmayer"
    )

    parser.add_argument(
        "--out-dir",
        default=None,
        help="Output directory. Default: ./user_reports"
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
        "--per-owner-files",
        action="store_true",
        help="Write one CSV file per owner."
    )

    parser.add_argument(
        "--quarantine",
        action="store_true",
        help="Ask whether to move recommended duplicates."
    )

    parser.add_argument(
        "--top-n",
        type=int,
        default=20,
        help="Number of owners shown in text summary. Default: 20."
    )

    args = parser.parse_args()

    root = Path(args.path).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        print(f"Invalid scan path: {root}", file=sys.stderr)
        sys.exit(1)

    if args.out_dir is None:
        output_dir = Path.cwd() / DEFAULT_OUTPUT_DIRNAME
    else:
        output_dir = Path(args.out_dir).expanduser().resolve()

    output_dir.mkdir(parents=True, exist_ok=True)

    requested_users = None
    user_suffix = "all_users"

    if args.user:
        requested_users = {u.lower() for u in args.user}
        user_suffix = "_".join(safe_name(u) for u in args.user)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    duplicate_report_csv = output_dir / f"duplicate_report_{user_suffix}_{timestamp}.csv"
    owner_summary_csv = output_dir / f"duplicate_capacity_by_owner_{user_suffix}_{timestamp}.csv"
    owner_summary_txt = output_dir / f"duplicate_capacity_by_owner_{user_suffix}_{timestamp}.txt"
    manifest_csv = output_dir / f"quarantine_manifest_{user_suffix}_{timestamp}.csv"

    duplicate_rows, diagnostics = scan_duplicates(
        root=root,
        algorithm=args.hash,
        max_mb=args.max_mb,
        skip_symlinks=not args.follow_symlinks,
        requested_users=requested_users,
    )

    write_csv(duplicate_rows, duplicate_report_csv)

    summary_rows, totals = summarize_by_owner(duplicate_rows)
    write_csv(summary_rows, owner_summary_csv)
    write_text_report(summary_rows, totals, owner_summary_txt, args.top_n)

    if args.per_owner_files:
        write_per_owner_files(duplicate_rows, output_dir)

    groups = len(set(row["duplicate_group_id"] for row in duplicate_rows))
    quarantine_count = sum(row["recommended_action"] == "QUARANTINE" for row in duplicate_rows)

    print()
    print("Scan complete.")
    print(f"Hash algorithm used: {diagnostics['hash_algorithm'].upper()}")
    print(f"Directories scanned: {diagnostics['dirs_scanned']:,}")
    print(f"Files seen: {diagnostics['files_seen']:,}")
    print(f"Files kept for analysis: {diagnostics['files_kept']:,}")
    print(f"Skipped by user filter: {diagnostics['skipped_user_filter']:,}")
    print(f"Skipped permission denied: {diagnostics['skipped_permission']:,}")
    print(f"Candidate size groups: {diagnostics['candidate_size_groups']:,}")
    print(f"Candidate files hashed: {diagnostics['candidate_files_hashed']:,}")
    print(f"Duplicate groups found: {groups:,}")
    print(f"Duplicate files found: {diagnostics['live_duplicate_files']:,}")
    print(f"Files recommended for quarantine: {quarantine_count:,}")
    print()
    print(f"Full duplicate report: {duplicate_report_csv}")
    print(f"Owner summary CSV: {owner_summary_csv}")
    print(f"Owner summary TXT: {owner_summary_txt}")

    if args.per_owner_files:
        print(f"Per-owner reports: {output_dir / 'per_owner'}")

    if args.quarantine:
        quarantine_files(duplicate_rows, manifest_csv)
    else:
        print()
        print("No files were moved.")
        print("To enable interactive quarantine, rerun with: --quarantine")


if __name__ == "__main__":
    main()
