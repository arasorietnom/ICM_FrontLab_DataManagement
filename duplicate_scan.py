#!/usr/bin/env python3

import argparse
import csv
import hashlib
import os
import shutil
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    import blake3
except ImportError:
    blake3 = None


EXCLUDED_NAMES = {
    ".git", ".venv", "venv", "env", "__pycache__", ".cache",
    "node_modules", "site-packages", ".nim_quarantine",
    "quarantined_duplicates"
}


def compute_hash(path: Path, algorithm: str) -> str:
    if algorithm == "blake3":
        if blake3 is None:
            raise RuntimeError("BLAKE3 not installed. Use --hash sha256 or install blake3.")
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


def collect_files(root: Path, max_mb: float, skip_symlinks: bool):
    max_bytes = int(max_mb * 1024 * 1024)
    files = []

    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)

        dirnames[:] = [
            d for d in dirnames
            if d.lower() not in EXCLUDED_NAMES
        ]

        for filename in filenames:
            path = current / filename

            try:
                if should_skip(path, root, skip_symlinks):
                    continue

                if not path.is_file():
                    continue

                size = path.stat().st_size

                if size <= 0:
                    continue

                if size > max_bytes:
                    continue

                files.append(path)

            except Exception:
                continue

    return files


def choose_keep_file(paths):
    """
    Default retention rule:
    1. keep newest file
    2. if tied, keep shortest path
    """
    return sorted(paths, key=lambda p: (-p.stat().st_mtime, len(str(p))))[0]


def safe_quarantine_path(root: Path, original: Path, group_id: int) -> Path:
    quarantine_root = root / "quarantined_duplicates"
    relative = original.relative_to(root)
    target = quarantine_root / f"group_{group_id:05d}" / relative

    counter = 1
    final_target = target

    while final_target.exists():
        final_target = target.with_name(f"{target.stem}__duplicate_{counter}{target.suffix}")
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
        "hash_algorithm",
        "content_hash",
        "size_bytes",
        "size_mb",
        "modified",
        "reason",
    ]

    with output_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def scan_duplicates(root: Path, algorithm: str, max_mb: float, skip_symlinks: bool):
    print(f"Scanning root: {root}")
    print("Mode: read-only scan first")
    print("No files will be moved unless you confirm quarantine later.")

    files = collect_files(root, max_mb=max_mb, skip_symlinks=skip_symlinks)

    by_size = defaultdict(list)
    for path in files:
        try:
            by_size[path.stat().st_size].append(path)
        except Exception:
            continue

    by_hash = defaultdict(list)

    for size, same_size_files in by_size.items():
        if len(same_size_files) < 2:
            continue

        for path in same_size_files:
            try:
                digest = compute_hash(path, algorithm)
                by_hash[(size, digest)].append(path)
            except Exception as e:
                print(f"Skipped unreadable file: {path} ({e})")

    rows = []
    group_id = 1

    for (size, digest), paths in by_hash.items():
        if len(paths) < 2:
            continue

        keep_file = choose_keep_file(paths)

        for path in sorted(paths, key=lambda p: str(p).lower()):
            stat = path.stat()
            quarantine = path != keep_file
            quarantine_target = safe_quarantine_path(root, path, group_id) if quarantine else ""

            rows.append({
                "duplicate_group_id": group_id,
                "recommended_action": "QUARANTINE" if quarantine else "KEEP",
                "quarantine_recommended": "YES" if quarantine else "NO_KEEP_THIS_FILE",
                "keep_file": str(keep_file),
                "candidate_file": str(path),
                "quarantine_target": str(quarantine_target),
                "hash_algorithm": algorithm.upper(),
                "content_hash": digest,
                "size_bytes": size,
                "size_mb": round(size / (1024 ** 2), 3),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
                "reason": f"same {algorithm.upper()} content hash",
            })

        group_id += 1

    return files, rows


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
    parser.add_argument("--out", default="duplicate_report.csv", help="CSV report output path")
    parser.add_argument("--hash", choices=["blake3", "sha256"], default="blake3")
    parser.add_argument("--max-mb", type=float, default=2000)
    parser.add_argument("--follow-symlinks", action="store_true")
    parser.add_argument("--quarantine", action="store_true", help="Ask whether to move recommended duplicates")
    parser.add_argument("--manifest", default="quarantine_manifest.csv")

    args = parser.parse_args()

    root = Path(args.path).expanduser().resolve()
    output_csv = Path(args.out).expanduser().resolve()
    manifest_csv = Path(args.manifest).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        print(f"Invalid path: {root}", file=sys.stderr)
        sys.exit(1)

    files, rows = scan_duplicates(
        root=root,
        algorithm=args.hash,
        max_mb=args.max_mb,
        skip_symlinks=not args.follow_symlinks,
    )

    write_csv(rows, output_csv)

    groups = len(set(row["duplicate_group_id"] for row in rows))
    quarantine_count = sum(row["recommended_action"] == "QUARANTINE" for row in rows)

    print()
    print(f"Files scanned: {len(files)}")
    print(f"Duplicate groups found: {groups}")
    print(f"Rows written: {len(rows)}")
    print(f"Files recommended for quarantine: {quarantine_count}")
    print(f"CSV report: {output_csv}")

    if args.quarantine:
        quarantine_files(rows, manifest_csv)
    else:
        print()
        print("No files were moved.")
        print("To enable interactive quarantine, rerun with: --quarantine")


if __name__ == "__main__":
    main()
