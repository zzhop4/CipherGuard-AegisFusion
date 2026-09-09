#!/usr/bin/env python3
"""Validate a separately distributed CipherGuard-AegisFusion model bundle.

This verifier never uploads or publishes model weights. It validates release
metadata and, when an asset root is supplied, verifies every declared SHA256.
The checked model bundle remains outside ordinary Git history.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA = "cipherguard-model-release-v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
PLACEHOLDER_PREFIX = "REPLACE_WITH_"

EXPECTED_FEATURE_CONTRACT = {
    "raw_flow_features": 78,
    "probability_evidence_features": 16,
    "past_only_temporal_features": 135,
    "augmented_temporal_features": 229,
    "temporal_windows": [8, 32, 128],
}
EXPECTED_THRESHOLDS = {
    "family_gate": 0.36,
    "standalone_binary_evaluation": 0.71,
    "selective_temporal_expert": 0.85,
    "infiltration_alert_attack_probability": 0.55,
}
EXPECTED_ROLES = {
    "feature_manifest",
    "hierarchical_summary",
    "binary_attack_gate",
    "attack_family_classifier",
    "attack_family_label_encoder",
    "temporal_summary",
    "selective_temporal_infiltration_expert",
}
BLOCKED_PUBLIC_GIT_SUFFIXES = {".cbm", ".pth", ".pt", ".onnx", ".pkl", ".joblib"}


class ReleaseValidationError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative_path(raw: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise ReleaseValidationError("artifact path must be a non-empty string")
    if "*" in raw or "?" in raw or "[" in raw:
        raise ReleaseValidationError(f"artifact globs are forbidden: {raw!r}")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ReleaseValidationError(f"unsafe artifact path: {raw!r}")
    return path.as_posix()


def _is_placeholder(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(PLACEHOLDER_PREFIX)


def validate_manifest(
    manifest: dict[str, Any],
    *,
    assets_root: Path | None = None,
    template_ok: bool = False,
) -> dict[str, Any]:
    if manifest.get("schema") != SCHEMA:
        raise ReleaseValidationError(f"unexpected schema: {manifest.get('schema')!r}")

    feature_contract = manifest.get("feature_contract")
    if feature_contract != EXPECTED_FEATURE_CONTRACT:
        raise ReleaseValidationError("feature contract differs from frozen public contract")

    thresholds = manifest.get("threshold_contract")
    if thresholds != EXPECTED_THRESHOLDS:
        raise ReleaseValidationError("threshold contract differs from frozen public contract")

    source_commit = manifest.get("source_commit")
    placeholder_fields = 0
    if _is_placeholder(source_commit):
        placeholder_fields += 1
        if not template_ok:
            raise ReleaseValidationError("source_commit is still a template placeholder")
    elif not isinstance(source_commit, str) or not COMMIT_RE.fullmatch(source_commit):
        raise ReleaseValidationError("source_commit must be exactly 40 lowercase hex characters")

    model_version = manifest.get("model_version")
    if _is_placeholder(model_version):
        placeholder_fields += 1
        if not template_ok:
            raise ReleaseValidationError("model_version is still a template placeholder")
    elif not isinstance(model_version, str) or not model_version.strip():
        raise ReleaseValidationError("model_version must be a non-empty string")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ReleaseValidationError("artifacts must be a non-empty list")

    roles: set[str] = set()
    paths: set[str] = set()
    verified_assets = 0

    root = assets_root.expanduser().resolve() if assets_root is not None else None
    if root is not None and not root.is_dir():
        raise ReleaseValidationError(f"assets root does not exist: {root}")

    for item in artifacts:
        if not isinstance(item, dict):
            raise ReleaseValidationError("every artifact entry must be an object")
        role = item.get("role")
        if not isinstance(role, str) or not role:
            raise ReleaseValidationError("artifact role must be a non-empty string")
        if role in roles:
            raise ReleaseValidationError(f"duplicate artifact role: {role}")
        roles.add(role)

        relative = _safe_relative_path(item.get("path"))
        if relative in paths:
            raise ReleaseValidationError(f"duplicate artifact path: {relative}")
        paths.add(relative)

        digest = item.get("sha256")
        if _is_placeholder(digest):
            placeholder_fields += 1
            if not template_ok:
                raise ReleaseValidationError(f"SHA256 placeholder remains for {relative}")
        elif not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ReleaseValidationError(f"invalid SHA256 for {relative}")

        if root is not None:
            if _is_placeholder(digest):
                raise ReleaseValidationError(
                    f"cannot verify assets while SHA256 placeholder remains: {relative}"
                )
            artifact_path = (root / relative).resolve()
            try:
                artifact_path.relative_to(root)
            except ValueError as exc:
                raise ReleaseValidationError(
                    f"artifact escapes assets root: {relative}"
                ) from exc
            if not artifact_path.is_file():
                raise ReleaseValidationError(f"declared artifact missing: {relative}")
            observed = sha256_file(artifact_path)
            if observed != digest:
                raise ReleaseValidationError(
                    f"SHA256 mismatch for {relative}: expected {digest}, observed {observed}"
                )
            verified_assets += 1

    if roles != EXPECTED_ROLES:
        raise ReleaseValidationError(
            f"artifact role set mismatch; missing={sorted(EXPECTED_ROLES - roles)} "
            f"extra={sorted(roles - EXPECTED_ROLES)}"
        )

    provenance = manifest.get("provenance")
    if not isinstance(provenance, dict):
        raise ReleaseValidationError("provenance must be an object")
    if provenance.get("dataset_redistribution") != "DATASETS_NOT_BUNDLED":
        raise ReleaseValidationError("dataset redistribution policy must remain DATASETS_NOT_BUNDLED")

    for key in ("license_review", "third_party_review"):
        value = provenance.get(key)
        if value == "REQUIRED_BEFORE_PUBLICATION":
            placeholder_fields += 1
            if not template_ok:
                raise ReleaseValidationError(f"{key} has not been completed")
        elif value != "PASS":
            raise ReleaseValidationError(f"{key} must be PASS before release")

    policy = manifest.get("release_policy")
    if not isinstance(policy, dict):
        raise ReleaseValidationError("release_policy must be an object")
    if policy.get("ordinary_git_history") != "DO_NOT_COMMIT_MODEL_BINARIES":
        raise ReleaseValidationError("model binaries must remain outside ordinary Git history")
    if policy.get("require_sha256") is not True:
        raise ReleaseValidationError("release policy must require SHA256")
    if policy.get("require_source_commit") is not True:
        raise ReleaseValidationError("release policy must require source commit")
    if policy.get("require_known_limitations") is not True:
        raise ReleaseValidationError("release policy must require known limitations")

    limitations = manifest.get("known_limitations")
    if not isinstance(limitations, list) or not limitations:
        raise ReleaseValidationError("known_limitations must be a non-empty list")
    joined = " ".join(str(item) for item in limitations).lower()
    if "zero-shot" not in joined or "no-go" not in joined:
        raise ReleaseValidationError("zero-shot NO-GO limitation is missing")

    binary_paths = [
        path for path in paths if PurePosixPath(path).suffix.lower() in BLOCKED_PUBLIC_GIT_SUFFIXES
    ]
    if not binary_paths:
        raise ReleaseValidationError("model release manifest declares no model binary artifacts")

    if root is not None and verified_assets != len(artifacts):
        raise ReleaseValidationError("not every declared artifact was verified")

    release_ready = (
        placeholder_fields == 0
        and root is not None
        and verified_assets == len(artifacts)
    )

    return {
        "schema": SCHEMA,
        "artifact_count": len(artifacts),
        "verified_assets": verified_assets,
        "placeholder_fields": placeholder_fields,
        "release_ready": release_ready,
        "model_binary_count": len(binary_paths),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--assets-root", type=Path)
    parser.add_argument(
        "--template-ok",
        action="store_true",
        help="validate template structure while allowing explicit placeholders",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.template_ok and args.assets_root is None:
        raise ReleaseValidationError(
            "strict release verification requires --assets-root so every SHA256 is checked"
        )
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    summary = validate_manifest(
        manifest,
        assets_root=args.assets_root,
        template_ok=args.template_ok,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if not args.template_ok and not summary["release_ready"]:
        raise ReleaseValidationError("model release manifest is not release-ready")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseValidationError as exc:
        print(f"MODEL_RELEASE_VALIDATION_FAILED: {exc}")
        raise SystemExit(1)
