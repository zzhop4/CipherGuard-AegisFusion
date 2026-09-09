# External evaluation evidence

This directory preserves the **claim/evidence contract** for the final external tests. It does not pretend that the sanitized showcase currently contains the complete original evaluator source.

Known final evaluator entries were:

- `eval_cicids2017_final_v2.py`
- `eval_ton_core_zero_shot_1.py`

Their complete source bodies have not yet been recovered from the sanitized evidence bundle. Therefore `claim_guard.py` is a publication-consistency guard, **not a reimplementation presented as the original evaluator**.

## Why this directory exists

The most important external-evaluation rule is semantic separation:

```text
90.38% Macro-F1
    = CSE-CIC-IDS2018 main-domain independent Test

32.65% F1
    = CICIDS2017 strict external stress

51.06% F1
    = NF-ToN-IoT-v3 sealed one-shot external stress
```

Those numbers answer different questions and must never be merged into one model score.

## CICIDS2017

Final documented result:

| Metric | Value |
|---|---:|
| Valid flows | 2,830,743 |
| Precision | 42.58% |
| Recall | 26.48% |
| F1 | 32.65% |
| Benign FPR | 8.76% |
| AUROC | 66.06% |
| AUPRC | 42.32% |

This track is a production-faithful external domain-shift stress test with no target-domain retuning. The temporal final prediction remained the protocol-selected result even though it traded recall/F1 for a lower FPR; it was not replaced after seeing the external score.

## NF-ToN-IoT-v3 sealed one-shot

Final documented constraints:

- 27,520,260 rows;
- 10,728,046 attack rows;
- `42/42` common NetFlow feature compatibility passed;
- threshold `0.2666317962` came from CSE source validation;
- evaluator, model, threshold and protocol were frozen before scoring;
- the target set was executed once;
- no target-domain retuning after result inspection.

Final result:

| Metric | Value |
|---|---:|
| Precision | 54.61% |
| Recall | 47.94% |
| F1 | 51.06% |
| FPR | 25.46% |
| AUROC | 56.40% |
| AUPRC | 58.70% |

The accepted conclusion is:

> **Method integrity PASS; strong zero-shot generalization NO-GO.**

The value of this experiment is that the negative/limited result was accepted without tuning the target domain after the fact.

## Claim guard

Run:

```bash
python evaluation/claim_guard.py
```

The guard verifies that:

- the 90.38% headline remains labeled main-domain independent Test;
- CICIDS2017 and ToN remain external stress tracks;
- both external tracks retain `NO_GO` for strong generalization;
- ToN remains one-shot and source-validation-thresholded;
- the frozen ToN threshold is not silently changed;
- forbidden claims such as “cross-dataset F1 exceeds 90%” remain explicitly blocked.

This is intentionally a **reporting integrity test**, not a substitute for rerunning the original multi-million-flow evaluators.
