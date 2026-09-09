#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORTER_PATH = ROOT / "scripts" / "export_public_tree.py"
SPEC = importlib.util.spec_from_file_location("export_public_tree", EXPORTER_PATH)
assert SPEC is not None and SPEC.loader is not None
EXPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPORTER)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    allowlist = ROOT / "release" / "PUBLIC_ALLOWLIST.txt"
    entries = EXPORTER.load_allowlist(allowlist)

    assert "research/domain_generalization/legacy/README_STRICT_REPRODUCTION.md" not in entries
    assert "backend/attack_lab.py" not in entries
    assert "scripts/export_public_tree.py" in entries
    assert "tests/test_public_export.py" in entries
    assert "requirements-ci-lock-linux-py311.txt" in entries
    assert len(entries) == len(set(entries))

    with tempfile.TemporaryDirectory(prefix="cipherguard-public-export-") as temp:
        output = Path(temp) / "public"
        summary = EXPORTER.export_tree(ROOT, output, allowlist)

        assert summary["allowlisted_file_count"] == len(entries)
        assert not (output / ".git").exists()
        assert not (output / "research" / "domain_generalization" / "legacy").exists()
        assert not (output / "backend" / "attack_lab.py").exists()

        for relative in entries:
            assert (output / relative).is_file(), relative

        blocked_suffixes = EXPORTER.BLOCKED_SUFFIXES
        for path in output.rglob("*"):
            if path.is_file():
                assert path.suffix.lower() not in blocked_suffixes, path

        checksum_lines = (
            output / "RELEASE_FILE_SHA256.txt"
        ).read_text(encoding="utf-8").splitlines()
        assert len(checksum_lines) == len(entries)

        observed = {}
        for line in checksum_lines:
            digest, relative = line.split("  ", 1)
            observed[relative] = digest
        assert set(observed) == set(entries)
        for relative, expected in observed.items():
            assert sha256_file(output / relative) == expected

        provenance = json.loads(
            (output / "RELEASE_EXPORT.json").read_text(encoding="utf-8")
        )
        assert provenance["format"] == "cipherguard-public-export-v1"
        assert provenance["allowlisted_file_count"] == len(entries)

    with tempfile.TemporaryDirectory(prefix="cipherguard-public-allowlist-") as temp:
        bad = Path(temp) / "bad.txt"
        bad.write_text("../secret.txt\n", encoding="utf-8")
        try:
            EXPORTER.load_allowlist(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("path traversal entry was accepted")

    print("PUBLIC_EXPORT_TEST_OK")
    print(f"ALLOWLISTED_FILES={len(entries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
