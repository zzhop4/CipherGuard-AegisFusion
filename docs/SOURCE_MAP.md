# Source Map

This document maps the competition freeze to the GitHub-friendly public tree. It intentionally distinguishes **restored frozen source**, **portabilized source**, and **method/evidence-contract reconstruction**.

## Competition freeze → GitHub

| Competition component | Original entry | GitHub location | Status |
|---|---|---|---|
| 78D hierarchical detector | `train_hierarchical_catboost.py` | `training/train_hierarchical_catboost.py` | Restored from frozen source |
| Selective temporal expert | `train_temporal_infiltration_expert.py` | `training/train_temporal_infiltration_expert.py` | Portable trainer from frozen method/source |
| Temporal feature contract | functions inside frozen temporal trainer | `training/temporal_feature_pipeline.py` | Extracted reusable module |
| Model service | `aegisfusion_service/app.py` | `services/model_runtime/aegisfusion_service/app.py` | Portabilized; machine paths removed |
| Model launcher | `start_aegisfusion.sh` | `scripts/start_aegisfusion.sh` | Portabilized |
| PCAP / 78D bridge | `backend/aegisfusion_bridge.py` | `backend/aegisfusion_bridge.py` | Portabilized final bridge; live service feature contract retained |
| Packet metadata evidence | `backend/packet_evidence.py` | `backend/packet_evidence.py` | Final metadata-only logic restored; legacy payload-marker logic excluded |
| Detection integration | `backend/engine.py` | `backend/engine.py` | Final sequence/tunnel/promotion logic restored |
| Realtime flow state | `backend/realtime_monitor.py` | `backend/realtime_monitor.py` | Passive public core restored; attack generation excluded |
| Source-only verification | repository verification scripts | `scripts/verify_system.sh`, `.github/workflows/verify.yml` | Available |
| Controlled campaign lab | `backend/attack_lab.py` | not public | Withheld from public production tree |
| ChainLens-QoA | `chainlens_qoa_v2.py`, `CHAINLENS_QOA_V2_PROTOCOL.json` | `research/chainlens/` | Frozen V2 attribution core/protocol restored |
| ServiceShape | `audit_service_relative_causal_v1.py`, `train_serviceshape_xd_relative_v1.py`, `eval_serviceshape_xd_unsw.py`, V2 scripts | `research/serviceshape/` | **Method-contract reconstruction**; complete original source body not recovered |
| CICIDS2017 external evaluator | `eval_cicids2017_final_v2.py`, `CICIDS2017_FINAL_*` | `evaluation/` | **Evidence/claim-contract reconstruction**; final result/decision preserved, evaluator body not recovered |
| ToN sealed evaluator | `eval_ton_core_zero_shot_1.py`, `TON_ONE_SHOT_PREFLIGHT_V1.json`, `TON_FINAL_DECISION_V1.json` | `evaluation/` | **Evidence/claim-contract reconstruction**; one-shot/freeze/result preserved, evaluator body not recovered |
| Earlier domain-generalization work | CNN/DANN/weak-GRL scripts | private staging only | Preserved as research provenance, not included in default Public tree |

## Provenance labels

### Restored / mirrored frozen source

Use only when the final code body or sufficiently complete final source was recovered and can be mapped back to the competition freeze.

### Portabilized

The final logic is available, but server-specific absolute paths, local environments or deployment assumptions were replaced with repository-relative configuration.

### Method / evidence-contract reconstruction

The final formulas, causal constraints, protocol, metrics or GO/NO-GO decision are evidenced, but the original complete source body is not currently recoverable from the sanitized bundle.

A reconstruction **must never be described as a byte-for-byte competition-source mirror**.

ServiceShape and the public external-evaluation contract currently belong to this category.

## Production path represented in GitHub

```text
PCAP / PCAPNG / Realtime Traffic
  -> backend/realtime_monitor.py
       -> passive capture or PCAP replay
       -> bidirectional five-tuple Flow state
       -> exact cross-flow SYN aggregation
       -> asynchronous Flow inspection
  -> backend/aegisfusion_bridge.py
       -> dominant-flow selection
       -> CIC-style statistics
       -> live /features contract alignment
  -> services/model_runtime/aegisfusion_service/app.py
       -> 78D hierarchical CatBoost
       -> 16D probability evidence
       -> past-only 8 / 32 / 128 context
       -> selective temporal Infiltration expert
  -> backend/packet_evidence.py
       -> metadata-only packet/sequence rules
  -> backend/engine.py
       -> final model-family + rule evidence fusion
       -> conservative Infiltration promotion gate
  -> research/chainlens/chainlens_qoa_v2.py
       -> sparse evidence graph / QoA attribution profile
```

ServiceShape deliberately remains outside production inference:

```text
Research Flow metadata
  -> research/serviceshape/service_relative.py
       -> past-only per-service history
       -> relative-log representation
       -> median / IQR robust deviation
       -> representation evidence only
```

## Source-only regression coverage

`tests/test_offline_metadata_pipeline.py` locks:

- synthetic PCAP parsing and bidirectional Flow assembly;
- CIC-style metadata extraction;
- payload-marker non-disclosure;
- final scan / SSH burst / SYN-flood thresholds;
- sequence/tunnel calculations;
- Infiltration promotion rule.

`tests/test_chainlens_qoa.py` locks nearest-predecessor V2 sparsification, explicit relation preservation, weak-edge policy, future-edge rejection and deterministic QoA tiers.

`tests/test_serviceshape_representation.py` locks only the evidenced ServiceShape method contract: `r(x,b)`, median/IQR robust deviation, current-Flow exclusion from its own baseline, service-history isolation and explicit unavailable state with no prior history.

`tests/test_external_evaluation_contract.py` is a reporting-integrity guard, not the original multi-million-flow evaluator. It locks:

- 90.38% as main-domain independent-Test headline;
- CICIDS2017 as external stress / NO-GO;
- ToN as sealed one-shot / NO-GO;
- ToN threshold `0.2666317962` from CSE source validation;
- no target-domain retuning;
- pre-score evaluator/model/threshold/protocol freeze semantics.

## Realtime freeze

The public realtime core retains the final defensive thresholds:

- scan: 5 seconds, `>=8` unique SYN flows and `>=6` destination/port pairs;
- SSH burst: 20 seconds, `>=7` unique SYN flows from one source to one authentication target;
- SYN flood: 2 seconds, `>=30` unique SYN flows from one source to one target;
- post-bruteforce correlation: compatible later behavior on the same pair within 10 minutes.

Unique Flow IDs are counted instead of raw SYN frames so duplicate loopback/libpcap observations cannot inflate the rate.

## ChainLens-QoA boundary

ChainLens-QoA is attribution, not attack classification. V2 preserves every valid explicit prior-alert reference, links only the nearest prior alert on the same source/destination pair within 600 seconds, and keeps same-source/different-target context within 120 seconds as weak visual context.

The `48,471 -> 372` edge result on 374 nodes is an evidence-graph sparsification result, not a detection metric. QoA A/B/C/D describes attribution evidence quality, not attack probability.

## ServiceShape boundary

Frozen final materials support:

```text
r(x,b) = log(1+x) - log(1+b)

z_robust =
  (x - median(H_service))
  / (IQR(H_service) + epsilon)
```

and the final evidence split:

- V1 Source Temporal: AUROC `0.8596`, AUPRC `0.4310`;
- V1 UNSW target-context ranking: AUROC `0.6933`, AUPRC `0.0835`;
- V2 Source Temporal: AUROC `0.8518`, AUPRC `0.4717`;
- V2 UNSW: AUROC `0.5831`, AUPRC `0.1462`, below the frozen `0.72` gate.

Accepted conclusion: **Representation GO / Standalone Detector NO-GO**.

## External evaluation boundary

### CICIDS2017

This is a production-faithful external stress test without target-domain retuning:

- valid flows: `2,830,743`
- Precision: `42.58%`
- Recall: `26.48%`
- F1: `32.65%`
- Benign FPR: `8.76%`
- AUROC: `66.06%`
- AUPRC: `42.32%`

### NF-ToN-IoT-v3

This is the sealed one-shot external stress track:

- rows: `27,520,260`
- attack rows: `10,728,046`
- common feature compatibility: `42/42`
- threshold: `0.2666317962`
- threshold source: CSE source validation
- evaluator/model/threshold/protocol frozen before target scoring
- one shot, no target-domain retuning
- F1: `51.06%`
- AUROC: `56.40%`

Accepted conclusion: **method integrity PASS / strong zero-shot generalization NO-GO**.

The original evaluator filenames are preserved for provenance, but `evaluation/claim_guard.py` is intentionally only a publication-integrity guard. It is not presented as a replacement or mirror of the missing evaluator source bodies.

## Production baseline and model assets

The production baseline remains the V14.3-compatible stack unless a later component has complete evidence showing it is superior and interface-compatible.

Core production model assets are intentionally excluded from ordinary Git history:

- `catboost_binary.cbm`
- `catboost_attack_family.cbm`
- `catboost_temporal_infiltration_expert.cbm`

Current release policy is **source public / trained weights not public**. If the project owner later publishes weights, they must be distributed separately with source-commit/version metadata and SHA256 verification.

## Public/private repository separation

`zzhop4/CipherGuard-AegisFusion` is the clean Public source repository. `zzhop4/cipher` remains the private staging/provenance repository and retains earlier experimental history that is intentionally not copied into the Public history.

## What is not being hidden

Failed or weaker research branches remain part of the scientific record in private provenance and published limitations. They may be labeled `RESEARCH`, `NO-GO` or `HOLD`, but must not be presented as production improvements.
