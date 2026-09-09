#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "scripts" / "verify_model_release.py"
SPEC = importlib.util.spec_from_file_location("verify_model_release", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    template_path = ROOT / "release" / "MODEL_RELEASE_TEMPLATE.json"
    template = json.loads(template_path.read_text(encoding="utf-8"))

    template_summary = VERIFIER.validate_manifest(template, template_ok=True)
    assert template_summary["artifact_count"] == 7
    assert template_summary["placeholder_fields"] > 0
    assert template_summary["release_ready"] is False

    try:
        VERIFIER.validate_manifest(template, template_ok=False)
    except VERIFIER.ReleaseValidationError:
        pass
    else:
        raise AssertionError("untouched model-release template passed strict validation")

    with tempfile.TemporaryDirectory(prefix="cipherguard-model-release-") as temp:
        assets = Path(temp) / "assets"
        assets.mkdir()
        manifest = copy.deepcopy(template)
        manifest["status"] = "RELEASE_READY"
        manifest["source_commit"] = "a" * 40
        manifest["model_version"] = "test-model-release-v1"
        manifest["provenance"]["license_review"] = "PASS"
        manifest["provenance"]["third_party_review"] = "PASS"

        for index, artifact in enumerate(manifest["artifacts"], 1):
            relative = artifact["path"]
            target = assets / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            payload = f"mock-artifact-{index}:{artifact['role']}\n".encode("utf-8")
            target.write_bytes(payload)
            artifact["sha256"] = digest_bytes(payload)

        summary = VERIFIER.validate_manifest(
            manifest,
            assets_root=assets,
            template_ok=False,
        )
        assert summary["artifact_count"] == 7
        assert summary["verified_assets"] == 7
        assert summary["placeholder_fields"] == 0
        assert summary["release_ready"] is True

        first = manifest["artifacts"][0]
        (assets / first["path"]).write_bytes(b"tampered\n")
        try:
            VERIFIER.validate_manifest(
                manifest,
                assets_root=assets,
                template_ok=False,
            )
        except VERIFIER.ReleaseValidationError as exc:
            assert "SHA256 mismatch" in str(exc)
        else:
            raise AssertionError("tampered model artifact passed SHA256 verification")

    print("MODEL_RELEASE_MANIFEST_TEST_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
