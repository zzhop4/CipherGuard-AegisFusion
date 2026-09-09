#!/usr/bin/env python3
"""Export the reviewed CipherGuard-AegisFusion public showcase tree.

The exporter is intentionally fail-closed:

- only explicit file paths from ``release/PUBLIC_ALLOWLIST.txt`` are copied;
- directories, globs, absolute paths and ``..`` traversal are rejected;
- every allowlisted source must exist as a regular file;
- the destination must be outside the staging repository and empty/nonexistent;
- no source ``.git`` history, model/data artifacts, or unlisted legacy files are copied.

The output additionally receives generated SHA256/provenance manifests. These
manifests describe the exported tree; they are not copied from the staging repo.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path, PurePosixPath
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ALLOWLIST = REPO_ROOT / "release" / "PUBLIC_ALLOWLIST.txt"

BLOCKED_SUFFIXES = {
    ".npy",
    ".npz",
    ".pth",
    ".pt",
    ".cbm",
    ".onnx",
    ".pkl",
    ".joblib",
    ".pcap",
    ".pcapng",
    ".pyc",
    ".zip",
}

FORBIDDEN_EXACT = {
    ".git",
    ".env",
    "backend/attack_lab.py",
}

FORBIDDEN_PREFIXES = (
    ".git/",
    "research/domain_generalization/legacy/",
    "data/",
    "dataset/",
    "datasets/",
    "models/",
    "runtime/",
    "logs/",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_relative_file_path(raw: str) -> str:
    if "*" in raw or "?" in raw or "[" in raw:
        raise ValueError(f"glob patterns are forbidden in public allowlist: {raw!r}")

    posix = PurePosixPath(raw)
    if posix.is_absolute() or not posix.parts:
        raise ValueError(f"allowlist path must be repository-relative: {raw!r}")
    if any(part in {"", ".", ".."} for part in posix.parts):
        raise ValueError(f"unsafe allowlist path: {raw!r}")

    normalized = posix.as_posix()
    if normalized in FORBIDDEN_EXACT:
        raise ValueError(f"explicitly forbidden public path: {normalized}")
    if any(normalized.startswith(prefix) for prefix in FORBIDDEN_PREFIXES):
        raise ValueError(f"forbidden public path prefix: {normalized}")
    if posix.suffix.lower() in BLOCKED_SUFFIXES:
        raise ValueError(f"blocked artifact extension in public allowlist: {normalized}")
    return normalized


def load_allowlist(path: Path) -> list[str]:
    entries: list[str] = []
    seen: set[str] = set()

    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            normalized = _validate_relative_file_path(stripped)
        except ValueError as exc:
            raise ValueError(f"{path}:{line_number}: {exc}") from exc
        if normalized in seen:
            raise ValueError(f"{path}:{line_number}: duplicate allowlist entry: {normalized}")
        seen.add(normalized)
        entries.append(normalized)

    if not entries:
        raise ValueError(f"public allowlist is empty: {path}")
    return entries


def _ensure_source_file(root: Path, relative: str) -> Path:
    source = (root / relative).resolve()
    try:
        source.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"allowlisted source escapes repository root: {relative}") from exc
    if not source.is_file():
        raise FileNotFoundError(f"allowlisted source is missing or not a file: {relative}")
    return source


def _prepare_output(root: Path, output: Path) -> Path:
    output = output.expanduser().resolve()
    if output == root or root in output.parents:
        raise ValueError("public export destination must be outside the staging repository")
    if output.exists():
        if not output.is_dir():
            raise ValueError(f"export destination exists and is not a directory: {output}")
        if any(output.iterdir()):
            raise ValueError(f"export destination must be empty: {output}")
    else:
        output.mkdir(parents=True)
    return output


def _git_value(root: Path, args: Iterable[str]) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = completed.stdout.strip()
    return value or None


def export_tree(root: Path, output: Path, allowlist_path: Path) -> dict[str, object]:
    root = root.expanduser().resolve()
    allowlist_path = allowlist_path.expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"repository root does not exist: {root}")
    if not allowlist_path.is_file():
        raise FileNotFoundError(f"public allowlist not found: {allowlist_path}")

    entries = load_allowlist(allowlist_path)
    output = _prepare_output(root, output)

    checksums: list[tuple[str, str]] = []
    total_bytes = 0
    for relative in entries:
        source = _ensure_source_file(root, relative)
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        checksums.append((relative, sha256_file(destination)))
        total_bytes += destination.stat().st_size

    if (output / ".git").exists():
        raise RuntimeError("export unexpectedly contains .git metadata")

    checksum_path = output / "RELEASE_FILE_SHA256.txt"
    checksum_path.write_text(
        "".join(f"{digest}  {relative}\n" for relative, digest in checksums),
        encoding="utf-8",
    )

    provenance = {
        "format": "cipherguard-public-export-v1",
        "source_commit": _git_value(root, ["rev-parse", "HEAD"]),
        "source_branch": _git_value(root, ["rev-parse", "--abbrev-ref", "HEAD"]),
        "allowlist": "release/PUBLIC_ALLOWLIST.txt",
        "allowlisted_file_count": len(entries),
        "allowlisted_bytes": total_bytes,
        "generated_files": ["RELEASE_FILE_SHA256.txt", "RELEASE_EXPORT.json"],
        "notes": [
            "No source .git history is copied.",
            "Legacy domain-generalization experiments are not in the default allowlist.",
            "Model/data/PCAP artifacts are not in the default allowlist.",
        ],
    }
    (output / "RELEASE_EXPORT.json").write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    return {
        "output": str(output),
        "allowlisted_file_count": len(entries),
        "allowlisted_bytes": total_bytes,
        "source_commit": provenance["source_commit"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summary = export_tree(args.root, args.output, args.allowlist)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
