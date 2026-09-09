# Model Weights

The public source release of **CipherGuard-AegisFusion** does **not** include trained model weights at this time.

## What is published

The repository includes the source required to inspect and reproduce the model pipeline, including:

- the 78D hierarchical CatBoost training entrypoint;
- the 16D probability-evidence and past-only temporal feature pipeline;
- the 229D Selective Temporal Infiltration Expert training entrypoint;
- the model-service runtime and its feature contracts;
- source-only regression tests and clean-environment dependency verification.

## What is not published

The following trained runtime assets are intentionally withheld from the current public release:

```text
models/hierarchical_full_v1/binary/catboost_binary.cbm
models/hierarchical_full_v1/attack_family/catboost_attack_family.cbm
models/hierarchical_full_v1/attack_family/label_encoder.pkl
models/temporal_infiltration_full_v1/catboost_temporal_infiltration_expert.cbm
```

Associated generated summaries/manifests may also be absent when they are tied to the private model bundle.

Raw/processed competition datasets and PCAP captures are likewise not bundled.

## Reproducing the weights

Users who have legitimately obtained the required datasets can train their own weights with the public training entrypoints documented in `docs/REPRODUCTION.md`.

A source-only clone is expected to pass repository verification without any `.cbm`, `.pkl`, dataset, or PCAP asset present. The model service therefore supports an asset-missing/degraded state instead of treating missing private weights as a source-code failure.

## Future model release

The project owner may publish audited weights separately in a future GitHub Release. If that happens, the weights will remain outside ordinary source Git history and must pass the repository's strict release controls:

- exact source commit and model version;
- frozen feature/threshold contract;
- required runtime asset roles;
- SHA256 for every artifact;
- actual file verification against the manifest;
- license and third-party review;
- known-limitations / zero-shot NO-GO boundary retained.

See `release/MODEL_RELEASE_TEMPLATE.json` and `scripts/verify_model_release.py`.

Until such a release exists, **the absence of public model weights is intentional, not a missing-file bug.**
