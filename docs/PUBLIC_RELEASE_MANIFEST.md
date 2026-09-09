# Public Release Manifest

This document defines the clean Public source release for **CipherGuard-AegisFusion**.

Public repository:

```text
zzhop4/CipherGuard-AegisFusion
```

Private staging/provenance repository:

```text
zzhop4/cipher
```

The Public repository must not inherit the old staging Git history or its model/data artifacts.

## 1. Canonical public allowlist

The machine-readable source of truth is:

```text
release/PUBLIC_ALLOWLIST.txt
```

Only explicitly reviewed files belong in the default Public tree. New public files must be added deliberately to that list and pass CI.

## 2. Public source categories

### Root/runtime metadata

```text
README.md
SECURITY.md
.gitignore
.env.example
requirements.txt
requirements-ci-lock-linux-py311.txt
pyproject.toml
```

### Production source

```text
backend/
  aegisfusion_bridge.py
  packet_evidence.py
  engine.py
  realtime_monitor.py

services/model_runtime/aegisfusion_service/
  app.py
  README.md

training/
  README.md
  train_hierarchical_catboost.py
  temporal_feature_pipeline.py
  train_temporal_infiltration_expert.py

scripts/
  start_aegisfusion.sh
  verify_system.sh
  audit_public_tree.py
  export_public_tree.py
  verify_model_release.py
```

### Attribution / reviewed research

```text
research/chainlens/
  chainlens_qoa_v2.py
  CHAINLENS_QOA_V2_PROTOCOL.json
  README.md

research/serviceshape/
  service_relative.py
  SERVICESSHAPE_METHOD_CONTRACT.json
  README.md
```

Provenance remains explicit:

- ChainLens V2 = restored frozen attribution core/protocol;
- ServiceShape = **method-contract reconstruction**, not a byte-for-byte trainer mirror.

### External evaluation evidence

```text
evaluation/
  EXTERNAL_EVALUATION_CONTRACT.json
  claim_guard.py
  README.md
```

These preserve result roles, freeze conditions, threshold provenance and NO-GO boundaries. They are not presented as the missing original evaluators.

### Tests / CI

```text
.github/workflows/verify.yml

tests/
  test_offline_metadata_pipeline.py
  test_chainlens_qoa.py
  test_serviceshape_representation.py
  test_external_evaluation_contract.py
  test_public_export.py
  test_model_release_manifest.py
  test_public_claim_surface.py
  smoke_test_model_service.py
```

### Documentation / release controls

```text
docs/
  ARCHITECTURE.md
  REPRODUCTION.md
  SOURCE_MAP.md
  KNOWN_LIMITATIONS.md
  DEPENDENCY_SNAPSHOT.md
  MODEL_WEIGHTS.md
  PUBLISH_CHECKLIST.md
  PUBLIC_RELEASE_MANIFEST.md

release/
  PUBLIC_ALLOWLIST.txt
  MODEL_RELEASE_TEMPLATE.json
```

## 3. Explicitly excluded from ordinary Public Git history

Do not commit:

```text
.git history from private staging
.env
*.npy
*.npz
*.pth
*.pt
*.cbm
*.onnx
*.pkl
*.joblib
*.pcap
*.pcapng
*.pyc
*.zip
__pycache__/
.venv/
venv/
runtime/
logs/
cache/
```

Also exclude raw/processed datasets without explicit redistribution permission, competition submission archives, local service state, private server configuration, and `backend/attack_lab.py` from the default Public production tree.

## 4. Model-weight release policy

**Current project-owner decision: source code is public; trained model weights are not public.**

The source repository must remain fully inspectable and Level-A verifiable without `.cbm/.pkl` assets. Missing private weights are an expected degraded runtime state.

If weights are published later, keep them outside ordinary source history and use the model-release controls:

```bash
python scripts/verify_model_release.py \
  --manifest path/to/MODEL_RELEASE_MANIFEST.json \
  --assets-root path/to/model-release-assets
```

Strict release verification requires source commit, model version, fixed feature/threshold contracts, seven declared runtime roles, real SHA256 values, actual file verification, license/third-party review, and the zero-shot NO-GO limitation.

## 5. Public source verification

Source-only verification:

```bash
bash scripts/verify_system.sh
```

The CI release gate should continue to cover:

1. source-only deterministic checks;
2. clean dependency installation with `pip check`;
3. actual allowlist export into a temporary clean directory;
4. public-tree audit and source verification inside that exported directory;
5. README claim-surface regression.

## 6. Dependency provenance

`requirements.txt` / `pyproject.toml` contain the direct portable runtime pins validated on a clean GitHub runner. `requirements-ci-lock-linux-py311.txt` records the complete Linux/Python-3.11 snapshot.

These are **portable CI pins**, not a claim about exact historical competition-server package versions.

## 7. Public claim freeze

The Public release must preserve:

- `90.38%` = CSE-CIC-IDS2018 main-domain independent-Test Macro-F1;
- `32.65%` = CICIDS2017 external-stress F1;
- `51.06%` = NF-ToN-IoT-v3 sealed one-shot external F1;
- `99.23%` = ChainLens V2 edge reduction, not detection accuracy;
- `7/7` = controlled campaign engineering closure, not arbitrary-real-network guarantee;
- ServiceShape = Representation GO / Standalone Detector NO-GO;
- strong zero-shot generalization = NO-GO.

`evaluation/claim_guard.py` locks the machine contract; `tests/test_public_claim_surface.py` locks the README surface.

## 8. Public/private history boundary

The clean Public `main` should contain only reviewed source-release history. Migration probes, staging-only branches/files, old model/data artifacts, and private provenance must remain outside Public `main`.

The final release process therefore reconstructs the Public `main` tree from approved blobs and the allowlist instead of exposing the historical `zzhop4/cipher` repository.
