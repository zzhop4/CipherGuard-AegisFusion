# System Architecture

CipherGuard-AegisFusion separates flow-level machine learning, temporal rescue, packet/sequence metadata evidence, realtime cross-flow state, service-relative representation research, and attack-chain attribution instead of treating them as one opaque score.

## End-to-end production path

```text
PCAP / Realtime Network Input
        ↓
Passive capture / PCAP replay
        ↓
Bidirectional five-tuple Flow construction
        ↓
78D leakage-controlled Flow features
        ↓
AegisFusion hierarchical detector
  1) Attack Gate: P(Attack | x)
  2) Attack Family: P(Family | Attack, x)
        ↓
16D probability evidence
        +
Past-only temporal context
  selected metadata × windows 8 / 32 / 128
  mean / std / robust standardized deviation
        ↓
229D Selective Temporal Infiltration Expert
        ↓
Metadata-only packet / sequence evidence
        +
Realtime cross-flow correlation
        ↓
Evidence fusion
        ↓
Sparse attack graph / ChainLens-QoA
```

ServiceShape is deliberately not inserted into this production inference path. It remains a research representation line whose final decision is **Representation GO / Standalone Detector NO-GO**.

## Public production modules

The current source-only public core is split into explicit modules:

- `backend/realtime_monitor.py`: passive capture, replay, bidirectional flow state, asynchronous inspection and cross-flow correlation;
- `backend/aegisfusion_bridge.py`: PCAP-to-CIC-style feature extraction and model-service contract alignment;
- `services/model_runtime/aegisfusion_service/app.py`: hierarchical + causal temporal inference service;
- `backend/packet_evidence.py`: V14.3 metadata-only packet/sequence rules;
- `backend/engine.py`: final evidence-fusion and family-promotion policy;
- `tests/test_offline_metadata_pipeline.py`: source-only regression test for metadata and freeze logic.

The controlled attack generator is not part of this public production path.

## Public attribution module

`research/chainlens/chainlens_qoa_v2.py` receives already-produced alerts and organizes them into sparse evidence components. It does not create a new attack probability and cannot recover an attack behavior that the upstream detector never emitted.

The V2 causal backbone preserves:

- every valid explicit prior-alert reference;
- only the nearest prior alert on the same `src_ip/dst_ip` pair within 600 seconds as a component edge;
- only the nearest same-source/different-target prior alert within 120 seconds as weak visual context;
- strict time direction: future alerts cannot become evidence for earlier alerts.

QoA A/B/C/D is a deterministic attribution-quality profile, not classifier confidence.

## ServiceShape research representation

The final competition materials freeze the following service-relative quantities:

```text
r(x,b) = log(1+x) - log(1+b)

z_robust =
  (x - median(H_service))
  / (IQR(H_service) + epsilon)
```

`research/serviceshape/service_relative.py` implements a source-only **method-contract reconstruction** of those formulas and their past-only semantics:

```text
past service history
        ↓
encode current flow
        ↓
return relative representation
        ↓
only then append current flow to history
```

This prevents current-flow self leakage. Service keys are used only to select the appropriate history and are not emitted as numeric identity features.

The complete original `train/eval_serviceshape_xd*.py` source body was not recovered from the sanitized evidence bundle, so the portable module is intentionally not described as a frozen-source mirror.

The final research evidence is also kept separate from production performance:

- V1 Source Temporal: AUROC `0.8596`, AUPRC `0.4310`;
- V1 UNSW target-context ranking: AUROC `0.6933`, AUPRC `0.0835`;
- V2 Source Temporal: AUROC `0.8518`, AUPRC `0.4717`;
- V2 UNSW: AUROC `0.5831`, AUPRC `0.1462`, below the frozen `0.72` AUROC gate.

Therefore ServiceShape demonstrates representation signal but is not promoted to the production detector.

## Hierarchical detector

The base model is deliberately split into two tasks.

```text
a_t = P(Attack | x_t)
q_t = P(Family=k | Attack, x_t)
P(Y=Benign | x_t) = 1 - a_t
P(Y=k | x_t) ≈ a_t × q_t,k
```

The separation reduces the pressure caused by the severe Benign/Attack imbalance before family classification.

The competition freeze used separate thresholds for different tasks. These values must not be interpreted as one global threshold:

- family gate: `0.36`
- standalone binary evaluation: `0.71`
- selective temporal expert: `0.85`

## 16D probability evidence

The temporal expert does not consume only Top-1 output. It receives model uncertainty and competition between Infiltration, Benign, and other attack families.

The feature group contains:

- attack probability
- benign probability
- Infiltration conditional probability
- Infiltration joint probability
- strongest-other joint probability
- Infiltration advantage
- family Top-1
- family Top-2
- probability margin
- entropy
- six attack-family conditional probabilities

## Past-only temporal context

The frozen temporal training code uses windows `8,32,128`. Context is built from earlier flows only; future observations are not allowed to influence the prediction at time `t`.

The selected context candidates include duration, packet counts, byte counts, rates, packet-length statistics, active/idle statistics, and initial TCP window fields. For each selected feature and each window, the implementation derives mean, standard deviation and standardized deviation.

This is the key reason the temporal expert reaches 229 augmented dimensions:

```text
78 raw Flow features
+ 16 probability evidence features
+ 135 temporal context features
= 229 dimensions
```

## PCAP → model bridge

`backend/aegisfusion_bridge.py` does not hard-code a second independent 78-column contract. It asks the running model service for `/api/v1/aegisfusion/features`, normalizes extracted CIC-style names to that contract, then reports:

- total feature count;
- recognized feature count;
- recognized feature ratio;
- dominant-flow packet count;
- number of flows found in the PCAP;
- direction packet/byte statistics.

This makes feature-contract drift visible instead of silently accepting a partially mismatched vector.

## Stateful packet / sequence evidence

The rule engine remains separate from AegisFusion family probabilities. It uses metadata and cross-packet state to identify behaviors without reading application payload semantics.

The final V14.3 logic includes, among other rules:

- periodic encrypted C2 from de-duplicated small-packet IAT/size rhythm;
- opaque command automation from repeated small requests and much larger responses;
- long bidirectional encrypted-tunnel metadata patterns;
- outbound bulk asymmetry for data-exfiltration candidates;
- SYN scan patterns.

`backend/engine.py` adds two final frozen calculations on top of packet evidence.

### Request / response sequence metrics

Near-identical loopback copies are de-duplicated when the same `(direction, payload_length)` appears again within `6 ms`. The engine then derives direction-switch ratio, up/down payload medians, IAT variation and up-direction IAT variation.

An opaque abnormal-command candidate requires a sufficiently long alternating sequence, strong small-request / large-response asymmetry and the final causal/model-or-metadata support conditions. The command content itself is never decrypted.

### Tunnel support score

The final tunnel support score combines:

- `+0.20` for at least 20 packets;
- `+0.20` for at least 8 seconds duration;
- `+0.20` for a reasonable bidirectional byte ratio;
- `+0.15` for persistent heartbeat/proxy-like timing;
- `+0.25` when AegisFusion reports Botnet or Infiltration.

It is capped at `1.0`; the metadata tunnel candidate is emitted when the packet rule matches or the combined score reaches `0.80`.

## Infiltration promotion gate

The final family-alert policy is intentionally asymmetric. Non-Benign model families other than Infiltration are reported normally. `Infiltration` is more conservative because the temporal expert can produce a strong conditional signal on shifted or synthetic traffic even when the binary gate is weak.

An Infiltration family result becomes an alert only when:

```text
attack_probability >= 0.55
OR
metadata behavior ∈ {
  abnormal_command_sequence,
  encrypted_tunnel,
  data_exfiltration
}
```

A `tls_periodic_c2` rule by itself is **not** an Infiltration corroborator. The raw model result is still returned even if the family signal is not promoted to an alert.

## Realtime cross-flow state

`backend/realtime_monitor.py` preserves the passive final-monitor defaults:

```text
min_flow_packets       = 12
flow_timeout_seconds   = 2.0
reinspect_packets      = 30
inactive_flow_seconds  = 90.0
bpf_filter             = tcp or udp
use_temporal           = true
```

The public monitor supports Linux `AF_PACKET` capture, optional Scapy/Npcap capture, and classic-PCAP replay.

The final defensive cross-flow rules use unique Flow IDs rather than raw SYN packet counts:

- scan: within 5 seconds, `>=8` unique SYN flows and `>=6` distinct target/port combinations;
- SSH burst: within 20 seconds, `>=7` unique SYN flows from one source to one authentication target;
- SYN flood: within 2 seconds, `>=30` unique SYN flows from one source to one target.

This unique-flow counting is important on loopback/libpcap captures where one SYN can be observed more than once.

A brute-force alert is also retained for 10 minutes. If the same source/target pair subsequently produces infiltration, abnormal command, encrypted tunnel or exfiltration evidence, the monitor derives a `bruteforce_post_action` correlation alert.

## Trust and evaluation controls

LeakGuard is the evaluation-control layer rather than another classifier:

- past-only prediction
- identity shortcut exclusion
- Validation selects model/threshold
- Test only reports
- external datasets do not retune production thresholds
- model / evaluator / threshold / protocol versions are frozen before sealed evaluation

## Source-only verification

`.github/workflows/verify.yml` runs `scripts/verify_system.sh` without downloading competition data or model weights. The source-only checks cover:

- required production and reviewed research files and Python syntax;
- machine-specific absolute paths;
- accidentally tracked model/data/PCAP artifacts;
- synthetic-PCAP five-tuple and CIC-style extraction;
- payload-marker non-disclosure;
- final cross-flow thresholds;
- sequence, tunnel-score and Infiltration-promotion freeze logic;
- ChainLens nearest-predecessor sparsification, weak-edge policy and QoA profile;
- ServiceShape scalar formulas, past-only update order and service-history isolation.

If a model service is already available, the same verification script additionally runs the 78D/229D black-box smoke test.

## Research versus production

The repository keeps these roles explicit:

- **Production baseline:** V14.3-compatible 78D hierarchical model + selective temporal expert + metadata evidence engine + passive realtime monitor.
- **Research representation:** ServiceShape portable method-contract core; final standalone-detector decision remains NO-GO.
- **Attribution:** ChainLens-QoA V2 sparse evidence graph and deterministic QoA profile.
- **Negative/open research:** open-world/novelty and weaker cross-domain variants remain evidence, not production claims.

Research branches that failed validation remain evidence, but they must not silently replace the production baseline.
