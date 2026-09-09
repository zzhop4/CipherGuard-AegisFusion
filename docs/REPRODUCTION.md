# Reproduction Guide

CipherGuard-AegisFusion separates **source verification**, **runtime inference**, and **full model retraining**. The public repository intentionally does not bundle competition datasets, PCAP captures, or trained model weights.

## 1. Reproduction levels

### Level A — Source-only verification

**Available in the public repository now.** No dataset or trained model weight is required.

```bash
python tests/test_offline_metadata_pipeline.py
python tests/test_chainlens_qoa.py
python tests/test_serviceshape_representation.py
python tests/test_external_evaluation_contract.py
python tests/test_public_claim_surface.py

bash scripts/verify_system.sh
```

This verifies code/protocol invariants rather than reproducing the headline ML scores.

### Level B — Runtime inference reproduction

Requires valid local model assets matching the documented model layout. The current public-release policy is **source public / trained weights not public**. Users may provide weights they trained themselves from legally obtained datasets.

### Level C — Full training / experiment reproduction

Requires the relevant official datasets, prepared 78D data contract, frozen split/evaluation semantics, and sufficient compute. External multi-million-flow tests additionally require the original evaluators or a separately audited faithful reconstruction.

The repository does **not** claim one-command Level C reproduction.

## 2. Verified portable environment

The current portable dependency contract was clean-installed and verified on GitHub-hosted Ubuntu 24.04 with CPython 3.11.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip check
cp .env.example .env
```

Direct dependencies are pinned in `requirements.txt` and `pyproject.toml`. `requirements-ci-lock-linux-py311.txt` records the complete Linux/Python-3.11 package snapshot used by CI. See `docs/DEPENDENCY_SNAPSHOT.md`.

This portable dependency snapshot is **not** a claim that the historical competition server used exactly the same package versions.

## 3. Source-only verification

`scripts/verify_system.sh` checks:

- required production/research/release files;
- Python syntax compilation;
- machine-specific path or credential-shaped publication hazards;
- blocked tracked assets such as `.cbm`, `.pth`, `.npy`, `.pcap`, `.zip`;
- synthetic-PCAP bidirectional Flow assembly and CIC-style metadata extraction;
- payload-marker non-disclosure;
- frozen realtime scan / SSH burst / SYN-flood thresholds;
- sequence, tunnel-score and Infiltration-promotion logic;
- ChainLens-QoA V2 sparsification/QoA behavior;
- ServiceShape past-only method contract;
- external evaluation result/freeze claim contract;
- public README claim-surface constraints;
- public allowlist exporter and model-release manifest guards.

If a model service is already running with valid local weights, the verifier also runs the online 78D/229D black-box smoke test.

## 4. Main data contract

Training expects a prepared directory equivalent to:

```text
data/processed/tabular_v1/
├── manifest.json
├── train/
├── val/
└── test/
```

`manifest.json` must contain the ordered `feature_columns` list. The production model uses 78 leakage-controlled Flow features. Identity-like fields such as raw IP addresses, Flow ID, and raw timestamp must not enter the numerical model vector.

Allowed metadata used for split bookkeeping or past-only temporal context may include:

- `target_binary`
- `target_family`
- `meta__row_hash`
- `meta__source_file`
- `meta__timestamp`

Past-only context construction is distinct from feeding identity shortcuts directly into the classifier.

## 5. Train the hierarchical detector

```bash
python training/train_hierarchical_catboost.py \
  --data-dir data/processed/tabular_v1 \
  --output-dir models/hierarchical_full_v1
```

The training path contains:

1. binary Attack Gate;
2. conditional attack-family classifier;
3. Validation-only threshold selection;
4. independent Test reporting.

**Validation chooses. Test reports. External datasets do not retune production thresholds.**

## 6. Train the selective temporal expert

```bash
python training/train_temporal_infiltration_expert.py \
  --data-dir data/processed/tabular_v1 \
  --base-model-dir models/hierarchical_full_v1 \
  --output-dir models/temporal_infiltration_full_v1
```

Frozen temporal windows:

```text
8, 32, 128
```

The expert targets the difficult Benign/Infiltration boundary. Its augmented representation is:

```text
78 raw Flow features
+ 16 probability evidence features
+ 135 past-only temporal-context features
= 229 dimensions
```

## 7. Runtime model layout

A locally prepared runtime bundle should provide the equivalent of:

```text
models/
├── hierarchical_full_v1/
│   ├── summary.json
│   ├── binary/
│   │   └── catboost_binary.cbm
│   └── attack_family/
│       ├── catboost_attack_family.cbm
│       └── label_encoder.json
└── temporal_infiltration_full_v1/
    ├── summary.json
    └── catboost_temporal_infiltration_expert.cbm
```

Trained binaries are excluded from ordinary Git history. See `docs/MODEL_WEIGHTS.md`.

## 8. Start the model service

After `.env` points to valid local data/model locations:

```bash
bash scripts/start_aegisfusion.sh
```

Default health endpoint:

```text
http://127.0.0.1:18083/api/v1/aegisfusion/health
```

Then:

```bash
python tests/smoke_test_model_service.py
```

The smoke test verifies the live 78D feature contract, 229D augmented dimensionality, base/temporal execution path, and causal context history `0 -> 1 -> 2`.

## 9. Realtime capture

`backend/realtime_monitor.py` supports passive monitoring and classic-PCAP replay.

- Linux: native `AF_PACKET` path is available.
- Other platforms: optional Scapy/Npcap may be used when installed/configured.
- Live capture may require elevated packet-capture permissions.
- Offline replay does not require live-capture privileges.

The public production tree does not include the controlled attack generator.

## 10. ServiceShape reproduction boundary

`research/serviceshape/service_relative.py` is a **method-contract reconstruction**, not a byte-for-byte mirror of the historical trainer.

It reproduces evidenced invariants:

```text
r(x,b) = log(1+x) - log(1+b)

z_robust =
  (x - median(H_service))
  / (IQR(H_service) + epsilon)
```

plus strict encode-then-update past-only semantics. Reproducing historical ServiceShape AUROC/AUPRC values requires the original data/evaluation pipeline or a separately audited reconstruction.

## 11. External evaluation reproduction boundary

Known final evaluator entries include:

- `eval_cicids2017_final_v2.py`
- `eval_ton_core_zero_shot_1.py`

Their complete source bodies were not recovered from the sanitized source bundle. Therefore:

- `evaluation/EXTERNAL_EVALUATION_CONTRACT.json` preserves the frozen experimental role, metrics, threshold provenance and NO-GO decisions;
- `evaluation/claim_guard.py` verifies publication consistency;
- neither is presented as the original evaluator implementation.

ToN's sealed contract remains:

```text
42/42 common features
threshold = 0.2666317962
threshold source = CSE source validation
model/evaluator/threshold/protocol frozen before target score
one-shot execution
no target-domain retuning
```

## 12. Public release status

This repository is the clean **Public source release**. Current policy:

- source code and verification controls: public;
- trained model weights: not public;
- datasets / raw PCAPs: not bundled;
- old `zzhop4/cipher` history: remains private staging/provenance and is not inherited here.

The Public tree is governed by `release/PUBLIC_ALLOWLIST.txt`, `scripts/audit_public_tree.py`, claim-surface regression tests, and GitHub Actions. Future model publication, if any, must use the separate model-release verifier and SHA256 manifest rather than ordinary Git history.
