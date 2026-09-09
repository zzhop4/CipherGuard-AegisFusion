# AegisFusion Model Service

FastAPI runtime for the production-style CipherGuard-AegisFusion model path.

## Model chain

```text
78D Flow metadata
   ↓
Binary CatBoost: P(Attack | x)
   ↓
Conditional Family CatBoost: P(Family | Attack, x)
   ↓
16D probability evidence
   +
past-only temporal context (8 / 32 / 128)
   ↓
229D selective Infiltration expert
```

The temporal expert is only allowed to rewrite the **Benign/Infiltration** boundary. It does not replace predictions for every family.

## Required local assets

```text
repo/
├── data/processed/tabular_v1/
│   └── manifest.json
└── models/
    ├── hierarchical_full_v1/
    │   ├── summary.json
    │   ├── binary/catboost_binary.cbm
    │   └── attack_family/
    │       ├── catboost_attack_family.cbm
    │       └── label_encoder.json
    └── temporal_infiltration_full_v1/
        ├── summary.json
        └── catboost_temporal_infiltration_expert.cbm
```

Paths can be overridden with `.env` variables:

- `AEGISFUSION_DATA_DIR`
- `AEGISFUSION_BASE_MODEL_DIR`
- `AEGISFUSION_TEMPORAL_MODEL_DIR`
- `AEGISFUSION_PROJECT`
- `CIPHERGUARD_APP`

## Start

From repository root:

```bash
cp .env.example .env
bash scripts/start_aegisfusion.sh
```

The default service port is `18083`.

## Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | concise health alias |
| GET | `/api/v1/aegisfusion/health` | model readiness / context state |
| GET | `/api/v1/aegisfusion/features` | 78D feature contract and temporal windows |
| GET | `/api/v1/aegisfusion/models` | active model roles and thresholds |
| GET | `/api/v1/aegisfusion/metrics` | competition metrics with scope warning |
| POST | `/api/v1/aegisfusion/predict/flow` | one Flow prediction |
| POST | `/api/v1/aegisfusion/predict/batch` | ordered batch prediction |
| POST | `/api/v1/aegisfusion/context/reset` | reset one/all causal contexts |
| POST | `/api/v1/aegisfusion/reload` | reload frozen model assets |

## Request example

```json
{
  "features": {
    "Flow Duration": 12000.0
  },
  "context_id": "demo-flow-chain",
  "use_temporal": true
}
```

The example above is intentionally incomplete. The service enforces the exact ordered feature contract from `manifest.json` and returns a `422 feature_contract_mismatch` when fields are missing or unexpected.

## Causal context

`context_id` identifies one ordered history. For a sequence of three requests using the same context, the response field `context_history_before_prediction` should be:

```text
0 → 1 → 2
```

Only previous observations are used to build mean/std/z temporal features. The current Flow is appended **after** its context features are computed.

## Compatibility

The competition environment exposed a Python-3.9/CatBoost-1.2.x compatibility issue. This public version avoids:

- Python 3.10-only `str | None` annotations;
- reliance on CatBoost `feature_count_`, which is not exposed consistently across versions.

Model dimensionality is checked from `feature_names_` when available and otherwise from the frozen feature contract.
