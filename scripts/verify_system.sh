#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${CIPHERGUARD_PYTHON:-python3}"
FAILURES=0
WARNINGS=0

ok(){ printf '[OK] %s\n' "$*"; }
warn(){ printf '[WARN] %s\n' "$*"; WARNINGS=$((WARNINGS+1)); }
fail(){ printf '[FAIL] %s\n' "$*"; FAILURES=$((FAILURES+1)); }

printf '============================================================\n'
printf ' CipherGuard-AegisFusion repository verification\n'
printf '============================================================\n'

required=(
  "README.md"
  "SECURITY.md"
  ".env.example"
  "requirements.txt"
  "requirements-ci-lock-linux-py311.txt"
  "pyproject.toml"
  "release/PUBLIC_ALLOWLIST.txt"
  "release/MODEL_RELEASE_TEMPLATE.json"
  "backend/aegisfusion_bridge.py"
  "backend/packet_evidence.py"
  "backend/engine.py"
  "backend/realtime_monitor.py"
  "training/train_hierarchical_catboost.py"
  "training/temporal_feature_pipeline.py"
  "training/train_temporal_infiltration_expert.py"
  "services/model_runtime/aegisfusion_service/app.py"
  "research/chainlens/chainlens_qoa_v2.py"
  "research/chainlens/CHAINLENS_QOA_V2_PROTOCOL.json"
  "research/chainlens/README.md"
  "research/serviceshape/service_relative.py"
  "research/serviceshape/SERVICESHAPE_METHOD_CONTRACT.json"
  "research/serviceshape/README.md"
  "evaluation/EXTERNAL_EVALUATION_CONTRACT.json"
  "evaluation/claim_guard.py"
  "evaluation/README.md"
  "scripts/start_aegisfusion.sh"
  "scripts/audit_public_tree.py"
  "scripts/export_public_tree.py"
  "scripts/verify_model_release.py"
  "tests/test_offline_metadata_pipeline.py"
  "tests/test_chainlens_qoa.py"
  "tests/test_serviceshape_representation.py"
  "tests/test_external_evaluation_contract.py"
  "tests/test_public_export.py"
  "tests/test_model_release_manifest.py"
  "tests/test_public_claim_surface.py"
  "tests/smoke_test_model_service.py"
  "docs/ARCHITECTURE.md"
  "docs/REPRODUCTION.md"
  "docs/SOURCE_MAP.md"
  "docs/KNOWN_LIMITATIONS.md"
  "docs/DEPENDENCY_SNAPSHOT.md"
  "docs/MODEL_WEIGHTS.md"
  "docs/PUBLISH_CHECKLIST.md"
  "docs/PUBLIC_RELEASE_MANIFEST.md"
)

for relative in "${required[@]}"; do
  if [ -f "$ROOT/$relative" ]; then
    ok "present: $relative"
  else
    fail "missing: $relative"
  fi
done

if command -v "$PY" >/dev/null 2>&1; then
  VERSION="$($PY -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
  ok "python: $PY ($VERSION)"
else
  fail "python executable not found: $PY"
fi

if command -v "$PY" >/dev/null 2>&1; then
  syntax_files=(
    "$ROOT/backend/aegisfusion_bridge.py"
    "$ROOT/backend/packet_evidence.py"
    "$ROOT/backend/engine.py"
    "$ROOT/backend/realtime_monitor.py"
    "$ROOT/training/train_hierarchical_catboost.py"
    "$ROOT/training/temporal_feature_pipeline.py"
    "$ROOT/training/train_temporal_infiltration_expert.py"
    "$ROOT/services/model_runtime/aegisfusion_service/app.py"
    "$ROOT/research/chainlens/chainlens_qoa_v2.py"
    "$ROOT/research/serviceshape/service_relative.py"
    "$ROOT/evaluation/claim_guard.py"
    "$ROOT/scripts/audit_public_tree.py"
    "$ROOT/scripts/export_public_tree.py"
    "$ROOT/scripts/verify_model_release.py"
    "$ROOT/tests/test_offline_metadata_pipeline.py"
    "$ROOT/tests/test_chainlens_qoa.py"
    "$ROOT/tests/test_serviceshape_representation.py"
    "$ROOT/tests/test_external_evaluation_contract.py"
    "$ROOT/tests/test_public_export.py"
    "$ROOT/tests/test_model_release_manifest.py"
    "$ROOT/tests/test_public_claim_surface.py"
    "$ROOT/tests/smoke_test_model_service.py"
  )
  if "$PY" -m py_compile "${syntax_files[@]}"; then
    ok "Python syntax compile"
  else
    fail "Python syntax compile"
  fi

  if "$PY" "$ROOT/tests/test_offline_metadata_pipeline.py"; then
    ok "offline metadata-only and cross-flow regression test"
  else
    fail "offline metadata-only and cross-flow regression test"
  fi

  if "$PY" "$ROOT/tests/test_chainlens_qoa.py"; then
    ok "ChainLens-QoA V2 deterministic regression test"
  else
    fail "ChainLens-QoA V2 deterministic regression test"
  fi

  if "$PY" "$ROOT/tests/test_serviceshape_representation.py"; then
    ok "ServiceShape past-only representation regression test"
  else
    fail "ServiceShape past-only representation regression test"
  fi

  if "$PY" "$ROOT/tests/test_external_evaluation_contract.py"; then
    ok "external evaluation claim/freeze contract regression test"
  else
    fail "external evaluation claim/freeze contract regression test"
  fi

  if "$PY" "$ROOT/tests/test_public_export.py"; then
    ok "fail-closed public export allowlist regression test"
  else
    fail "fail-closed public export allowlist regression test"
  fi

  if "$PY" "$ROOT/tests/test_model_release_manifest.py"; then
    ok "model release manifest and SHA256 tamper regression test"
  else
    fail "model release manifest and SHA256 tamper regression test"
  fi

  if "$PY" "$ROOT/tests/test_public_claim_surface.py"; then
    ok "public README claim-surface regression test"
  else
    fail "public README claim-surface regression test"
  fi

  if "$PY" "$ROOT/scripts/verify_model_release.py" \
      --manifest "$ROOT/release/MODEL_RELEASE_TEMPLATE.json" \
      --template-ok >/dev/null; then
    ok "model release template structure"
  else
    fail "model release template structure"
  fi

  if "$PY" "$ROOT/scripts/audit_public_tree.py" --root "$ROOT"; then
    ok "reviewed public-tree path/credential audit"
  else
    fail "reviewed public-tree path/credential audit"
  fi

  if "$PY" -c 'import tomllib' >/dev/null 2>&1; then
    if "$PY" - "$ROOT" <<'PY'
import sys
from pathlib import Path
import tomllib

root = Path(sys.argv[1])
reqs = {
    line.strip()
    for line in (root / "requirements.txt").read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.lstrip().startswith("#")
}
with (root / "pyproject.toml").open("rb") as handle:
    project = tomllib.load(handle)["project"]
pyproject_reqs = set(project.get("dependencies", []))
if reqs != pyproject_reqs:
    print("requirements.txt / pyproject.toml mismatch", file=sys.stderr)
    print("requirements-only:", sorted(reqs - pyproject_reqs), file=sys.stderr)
    print("pyproject-only:", sorted(pyproject_reqs - reqs), file=sys.stderr)
    raise SystemExit(1)
print("DIRECT_DEPENDENCY_CONTRACT_OK")
PY
    then
      ok "requirements.txt and pyproject.toml direct dependency contract"
    else
      fail "requirements.txt and pyproject.toml direct dependency contract"
    fi
  else
    warn "tomllib unavailable; direct dependency metadata comparison skipped"
  fi
fi

tracked_bad=0
if command -v git >/dev/null 2>&1 && [ -d "$ROOT/.git" ]; then
  while IFS= read -r path; do
    case "$path" in
      *.npy|*.npz|*.pth|*.pt|*.cbm|*.onnx|*.pkl|*.joblib|*.pcap|*.pcapng|*.pyc|*.zip)
        printf '[FAIL] tracked binary/data artifact: %s\n' "$path"
        tracked_bad=1
        ;;
    esac
  done < <(git -C "$ROOT" ls-files)
  if [ "$tracked_bad" -eq 0 ]; then
    ok "no blocked binary/data extensions tracked in current tree"
  else
    FAILURES=$((FAILURES+1))
  fi
else
  warn "git metadata unavailable; tracked-file audit skipped"
fi

DATA_MANIFEST="${AEGISFUSION_DATA_DIR:-$ROOT/data/processed/tabular_v1}/manifest.json"
BASE_MODEL="${AEGISFUSION_BASE_MODEL_DIR:-$ROOT/models/hierarchical_full_v1}/binary/catboost_binary.cbm"
FAMILY_MODEL="${AEGISFUSION_BASE_MODEL_DIR:-$ROOT/models/hierarchical_full_v1}/attack_family/catboost_attack_family.cbm"
TEMP_MODEL="${AEGISFUSION_TEMPORAL_MODEL_DIR:-$ROOT/models/temporal_infiltration_full_v1}/catboost_temporal_infiltration_expert.cbm"

for asset in "$DATA_MANIFEST" "$BASE_MODEL" "$FAMILY_MODEL" "$TEMP_MODEL"; do
  if [ -f "$asset" ]; then
    ok "runtime asset: $asset"
  else
    warn "runtime asset absent (expected for source-only clone): $asset"
  fi
done

HEALTH_URL="${AEGISFUSION_URL:-http://127.0.0.1:18083}/api/v1/aegisfusion/health"
if command -v curl >/dev/null 2>&1 && curl -fsS --max-time 2 "$HEALTH_URL" >/dev/null 2>&1; then
  ok "model service reachable: $HEALTH_URL"
  if "$PY" "$ROOT/tests/smoke_test_model_service.py"; then
    ok "black-box model-service smoke test"
  else
    fail "black-box model-service smoke test"
  fi
else
  warn "model service not running; online smoke test skipped"
fi

printf '\n============================================================\n'
printf 'failures=%d warnings=%d\n' "$FAILURES" "$WARNINGS"
if [ "$FAILURES" -eq 0 ]; then
  printf 'REPOSITORY STATUS: PASS\n'
  exit 0
fi
printf 'REPOSITORY STATUS: FAIL\n'
exit 1
