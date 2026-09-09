# Dependency Snapshot

This file records the **portable CI environment that was actually installed and imported successfully** during the GitHub cleanup. It is not a reconstruction of the exact historical competition server.

## Verified environment

- Verification date: 2026-09-09
- Source commit used for the discovery run: `f6479444081baf80173665acffe138f45ad564ed`
- GitHub runner OS: Ubuntu 24.04.4 LTS
- Runner image: `ubuntu-24.04`, image version `20260831.293.1`
- CPython: `3.11.16`
- pip: `26.2.1`
- `pip check`: PASS
- AegisFusion FastAPI service import without model/data assets: PASS

The model service is expected to report a missing `manifest.json` / model asset during an asset-free import. The relevant portability check is that module import completes and the runtime remains in a degraded/not-ready state rather than crashing the process.

## Direct runtime dependency contract

The following direct package versions were resolved by the successful clean runner and are pinned in `requirements.txt` and `pyproject.toml`:

| Package | Verified version |
|---|---:|
| numpy | 2.4.6 |
| pandas | 3.0.5 |
| pyarrow | 25.0.1 |
| catboost | 1.2.10 |
| scikit-learn | 1.9.0 |
| matplotlib | 3.11.1 |
| fastapi | 0.141.1 |
| uvicorn | 0.52.4 |
| pydantic | 2.13.5 |

## CI lock

`requirements-ci-lock-linux-py311.txt` records the complete package set installed by that successful run, including transitive packages.

Its scope is intentionally narrow:

```text
Linux / Ubuntu 24.04
CPython 3.11
GitHub-hosted clean-runner reproducibility
```

Do not treat the CI lock as a universal Windows/macOS lock. In particular, `uvicorn[standard]` resolves platform-sensitive extras such as `uvloop` on Linux.

## What this snapshot proves

It proves that, on the verified clean environment:

1. the declared runtime dependencies can be installed from scratch;
2. dependency metadata is internally consistent (`pip check` passes);
3. NumPy, pandas, PyArrow, CatBoost, scikit-learn, Matplotlib, FastAPI, Uvicorn and Pydantic import successfully;
4. the portable AegisFusion model service imports without requiring competition-server absolute paths or bundled model assets.

## What this snapshot does not prove

It does **not** prove that these are the exact historical versions used on the competition server. It also does not, by itself, prove numerical identity of a full training run because the public repository intentionally excludes the original datasets and model binaries.

For scientific claims, keep the distinctions explicit:

- **competition method / result freeze**: supported by recovered source, protocols and evidence files;
- **portable dependency snapshot**: supported by current clean GitHub CI;
- **full numerical retraining reproduction**: requires licensed datasets, the declared split/manifest contract and a separately verified clean-machine run.
