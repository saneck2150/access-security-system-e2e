#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

CPP_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}

DEFAULT_EXCLUDE_DIRS = {
    ".git",
    "build",
    "devel",
    "install",
    "third_party",
}

def should_skip_dir(dir_name: str, excluded: set[str]) -> bool:
    return dir_name in excluded

def collect_files(root: Path, exts: set[str], excluded_dirs: set[str]) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # prune excluded dirs in-place so os.walk won't descend into them
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d, excluded_dirs)]

        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix in exts:
                files.append(p)
    return files

def run_clang_format(files: list[Path], clang_format: str, dry_run: bool) -> int:
    if not files:
        print("No matching files found.")
        return 0

    CHUNK_SIZE = 200
    base_args = [clang_format]
    if dry_run:
        base_args += ["--dry-run", "--Werror"]
    else:
        base_args += ["-i"]

    rc = 0
    for i in range(0, len(files), CHUNK_SIZE):
        chunk = files[i:i + CHUNK_SIZE]
        cmd = base_args + [str(p) for p in chunk]
        try:
            subprocess.run(cmd, check=False)
        except OSError as e:
            print(f"Failed to run clang-format: {e}", file=sys.stderr)
            return 2
    return rc

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Recursively run clang-format on C/C++ sources/headers, skipping build dirs."
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=".",
        help="Root directory to scan (default: .)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Directory name to exclude (can be repeated). Default: .git, build, devel, install",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Don't modify files; fail if formatting would change anything (clang-format --dry-run --Werror).",
    )
    parser.add_argument(
        "--clang-format",
        default="clang-format",
        help="clang-format executable (default: clang-format).",
    )
    args = parser.parse_args()

    clang_path = shutil.which(args.clang_format)
    if not clang_path:
        print(f"Error: '{args.clang_format}' not found in PATH.", file=sys.stderr)
        return 2

    excluded_dirs = set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude)

    root = Path(args.root).resolve()
    if not root.exists():
        print(f"Error: root path does not exist: {root}", file=sys.stderr)
        return 2

    files = collect_files(root, CPP_EXTS, excluded_dirs)
    print(f"Found {len(files)} files under {root} (excluded dirs: {sorted(excluded_dirs)})")

    return run_clang_format(files, clang_path, args.dry_run)

if __name__ == "__main__":
    raise SystemExit(main())
