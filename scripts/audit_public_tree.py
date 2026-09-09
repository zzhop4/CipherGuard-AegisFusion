#!/usr/bin/env python3
"""Audit reviewed public-source paths for accidental publication hazards.

This lightweight scanner is intentionally conservative and dependency-free. It
is designed to be rerun both in the private staging branch and after copying
the reviewed tree into a brand-new public repository.

It checks source/config/test/research paths for:
- competition-machine absolute paths;
- Windows user-drive absolute paths;
- private-key headers;
- AWS access-key shaped tokens;
- bearer-token literals;
- quoted password/secret/api-key/token assignments with non-placeholder values.

It is not a substitute for GitHub secret scanning or a dedicated scanner such
as gitleaks/trufflehog. Final public release should still run one of those on
the NEW repository history.
"""
from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path
from typing import Iterable


TEXT_SUFFIXES = {
    "",
    ".py",
    ".sh",
    ".md",
    ".txt",
    ".json",
    ".jsonl",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".example",
}

REVIEW_ROOTS = (
    "backend",
    "training",
    "services",
    "research",
    "evaluation",
    "scripts",
    "tests",
)

ROOT_FILES = (
    ".env.example",
    ".gitignore",
    "requirements.txt",
    "pyproject.toml",
    "SECURITY.md",
)

SELF_EXCLUDED = {
    "scripts/audit_public_tree.py",
    "scripts/verify_system.sh",
}

PLACEHOLDER_MARKERS = (
    "example",
    "placeholder",
    "change-me",
    "changeme",
    "replace-me",
    "replace_me",
    "your-",
    "your_",
    "dummy",
    "test-only",
    "not-a-real",
    "xxxxx",
    "<",
    "${",
)

PATTERNS = (
    (
        "competition_absolute_path",
        re.compile(r"/mnt/data/(?:newcipher|venvs|conda_envs)(?:/|\\b)"),
    ),
    (
        "windows_user_absolute_path",
        re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\s]+\\"),
    ),
    (
        "private_key_header",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "aws_access_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "bearer_token_literal",
        re.compile(r"(?i)Authorization\s*:\s*Bearer\s+[A-Za-z0-9._~-]{16,}"),
    ),
)

ASSIGNMENT = re.compile(
    r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|bearer[_-]?token)"
    r"\s*[:=]\s*(['\"])([^'\"\n]{4,})\1"
)


def git_tracked(root: Path) -> list[str] | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "ls-files"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def candidate_paths(root: Path) -> Iterable[Path]:
    tracked = git_tracked(root)
    if tracked is not None:
        for relative in tracked:
            if relative in SELF_EXCLUDED:
                continue
            if relative in ROOT_FILES or any(
                relative == prefix or relative.startswith(prefix + "/")
                for prefix in REVIEW_ROOTS
            ):
                path = root / relative
                if path.is_file():
                    yield path
        return

    for relative in ROOT_FILES:
        path = root / relative
        if path.is_file():
            yield path
    for prefix in REVIEW_ROOTS:
        directory = root / prefix
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            if relative not in SELF_EXCLUDED:
                yield path


def is_text_candidate(path: Path) -> bool:
    if path.name == ".env.example":
        return True
    return path.suffix.lower() in TEXT_SUFFIXES


def looks_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def audit_file(root: Path, path: Path) -> list[str]:
    relative = path.relative_to(root).as_posix()
    if not is_text_candidate(path):
        return []
    try:
        data = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    if len(data) > 2_000_000:
        return []

    findings: list[str] = []
    for label, pattern in PATTERNS:
        for match in pattern.finditer(data):
            line = data.count("\n", 0, match.start()) + 1
            findings.append(f"{relative}:{line}: {label}")

    for match in ASSIGNMENT.finditer(data):
        value = match.group(2)
        if looks_placeholder(value):
            continue
        line = data.count("\n", 0, match.start()) + 1
        findings.append(f"{relative}:{line}: credential_like_assignment")

    return findings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        default=str(Path(__file__).resolve().parents[1]),
        help="repository root",
    )
    args = parser.parse_args()
    root = Path(args.root).resolve()

    findings: list[str] = []
    scanned = 0
    for path in candidate_paths(root):
        if is_text_candidate(path):
            scanned += 1
            findings.extend(audit_file(root, path))

    if findings:
        print("PUBLIC_TREE_AUDIT_FAIL")
        for item in findings:
            print("[FAIL]", item)
        raise SystemExit(1)

    print(f"[OK] public-tree text files scanned: {scanned}")
    print("[OK] no known machine paths or credential-shaped literals found")
    print("PUBLIC_TREE_AUDIT_OK")


if __name__ == "__main__":
    main()
