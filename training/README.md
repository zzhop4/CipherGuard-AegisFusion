# Training Code

This directory contains the formal model-training path used by CipherGuard-AegisFusion rather than the older exploratory domain-generalization scripts that previously lived at repository root.

## `train_hierarchical_catboost.py`

Frozen 78D hierarchical CatBoost training pipeline.

It trains two models:

1. `P(Attack | x)` — binary Attack Gate
2. `P(Family | Attack, x)` — conditional attack-family classifier

Threshold search is performed on Validation data, and Test is used for reporting. The script supports CPU/GPU CatBoost and uses square-root class balancing by default.

```bash
python training/train_hierarchical_catboost.py \
  --data-dir data/processed/tabular_v1 \
  --output-dir models/hierarchical_full_v1
```

## `temporal_feature_pipeline.py`

Portable extraction of the inference-relevant feature construction used by the frozen selective temporal Infiltration expert.

It contains:

- 16D probability-evidence construction
- past-only windows `8 / 32 / 128`
- historical mean / standard deviation / standardized deviation
- deterministic time ordering
- augmented-dimension validation

With the competition feature contract this produces:

```text
78 raw
+ 16 probability evidence
+ 135 temporal context
= 229 dimensions
```

## `train_temporal_infiltration_expert.py`

GitHub-portable training entry derived from the recovered competition-freeze trainer. It removes machine-specific `/mnt/data/...` assumptions while preserving the modeling contract:

1. load the frozen hierarchical base models;
2. construct probability evidence and past-only context;
3. select the Benign/Infiltration boundary plus hard negatives;
4. fit the selective CatBoost expert;
5. search the expert threshold on Validation;
6. report the untouched Test split.

```bash
python training/train_temporal_infiltration_expert.py \
  --data-dir data/processed/tabular_v1 \
  --base-model-dir models/hierarchical_full_v1 \
  --output-dir models/temporal_infiltration_full_v1
```

The original competition trainer remains preserved in the private source archive for provenance; the GitHub version is intentionally path-portable and does not bundle generated model/data artifacts.
