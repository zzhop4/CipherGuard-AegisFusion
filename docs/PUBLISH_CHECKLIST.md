# Public Release Checklist

This checklist governs the clean Public repository `zzhop4/CipherGuard-AegisFusion`. The old `zzhop4/cipher` repository remains private staging/provenance and must not be made public wholesale.

## A. Public source release — completed controls

- [x] `.env.example` is public; real `.env` is excluded
- [x] competition-machine absolute paths removed from reviewed production code
- [x] Production / Research / Attribution / NO-GO roles separated
- [x] 78D hierarchical + 229D temporal training/runtime source published
- [x] Model Service + PCAP bridge published
- [x] metadata-only packet evidence + evidence-fusion engine published
- [x] passive realtime / replay / cross-flow core published
- [x] `attack_lab.py` excluded from the default Public tree
- [x] ChainLens-QoA V2 core/protocol + deterministic test published
- [x] ServiceShape labeled method-contract reconstruction
- [x] external evaluation labeled evidence/claim-contract reconstruction
- [x] source-only verification implemented
- [x] clean dependency snapshot verified
- [x] fail-closed public allowlist/exporter implemented
- [x] model-release SHA256 guard implemented
- [x] README claim-surface regression implemented
- [x] current release policy explicitly states **source public / trained weights not public**

## B. Never commit to ordinary Public Git history

- [ ] real `.env`, token, API key, database password, SSH private key
- [ ] private school/server credentials or non-public internal addresses
- [ ] datasets without redistribution permission
- [ ] large PCAP / PCAPNG files
- [ ] `.npy/.npz/.pth/.pt/.cbm/.onnx/.pkl/.joblib`
- [ ] Python virtual environments / `__pycache__` / `.pyc`
- [ ] logs, runtime state, caches, debug output
- [ ] original competition ZIP/export bundles
- [ ] unnecessary personal information or internal judging/school materials

CI and `scripts/audit_public_tree.py` provide automated guardrails, but publication still requires human review for third-party licensing and non-code materials.

## C. Dependency/reproducibility gate

- [x] source-only verification commands documented
- [x] model-asset absence treated as an expected degraded state, not a source failure
- [x] nine direct runtime dependencies pinned in `requirements.txt` and `pyproject.toml`
- [x] Linux/Python-3.11 full CI dependency snapshot recorded
- [x] `pip check` passed on clean GitHub runner
- [x] formal trainer CLI/module loading verified in clean dependency job
- [x] Model Service imports without private model assets
- [ ] real model-service smoke test with project-owned weights — intentionally deferred because weights are not public

The dependency snapshot is a **portable CI environment**, not a reconstruction of exact historical competition-server packages.

## D. Machine-governed public tree

The default public source set is defined by:

```text
release/PUBLIC_ALLOWLIST.txt
```

The exporter must continue to:

- [x] accept only explicit repository-relative file paths
- [x] reject glob patterns and `..` traversal
- [x] reject `.git`, `.env`, and `backend/attack_lab.py`
- [x] reject legacy/data/models/runtime/logs prefixes
- [x] reject model/data/PCAP binary extensions
- [x] generate per-file SHA256 and export provenance

Any future public file must be added deliberately to the allowlist and revalidated by CI.

## E. Model-weight policy

**Current decision: trained weights are not published.**

The source repository may document their expected roles/paths, but it must not add trained binaries to ordinary Git history.

If the project owner later chooses to publish weights, use a separate GitHub Release or other audited artifact channel and require:

- [ ] exact source commit + model version
- [ ] all seven declared runtime asset roles
- [ ] SHA256 for every artifact
- [ ] actual asset-root verification
- [ ] feature/threshold contract match
- [ ] license review PASS
- [ ] third-party review PASS
- [ ] known-limitations / zero-shot NO-GO retained

Until those conditions are satisfied, `release/MODEL_RELEASE_TEMPLATE.json` remains a template, not proof of a released model.

## F. Claim integrity

Automated README regression locks:

- [x] CSE-CIC-IDS2018 7-class Macro-F1 `90.38%` as main-domain independent Test
- [x] CICIDS2017 F1 `32.65%` as external stress / NO-GO
- [x] NF-ToN-IoT-v3 F1 `51.06%` as sealed one-shot / zero-shot NO-GO
- [x] ToN threshold `0.2666317962` as CSE source-validation threshold
- [x] ChainLens `99.23%` as edge reduction, not detection accuracy
- [x] ServiceShape as Representation GO / Standalone Detector NO-GO
- [x] Controlled Campaign `7/7` as controlled engineering closure only

Resume/PPT/demo claims should remain consistent with these boundaries.

## G. Ownership / licensing

Project publication decisions are made by the project owner/team leader. No extra teammate-authorization gate is required for this repository release.

Still review independently:

- [ ] source-code license choice, or explicit no-license/all-rights-reserved status
- [ ] third-party code-license compatibility
- [ ] dataset redistribution terms
- [ ] screenshots/images/fonts/logos used in future showcase material
- [ ] unnecessary personal/internal information

## H. Public repository finalization

Before treating a Public `main` commit as the release baseline:

- [ ] no old private staging history reachable from `main`
- [ ] no `_probe*` / migration-only files in tree or retained `main` history
- [ ] only reviewed allowlisted source files in release tree
- [ ] `bash scripts/verify_system.sh` PASS
- [ ] clean-dependency job PASS
- [ ] public-tree/export job PASS
- [ ] README relative links valid
- [ ] Actions run on the actual Public repository, not only private staging

The finalization process should leave a compact Public history and keep private provenance in `zzhop4/cipher`.
