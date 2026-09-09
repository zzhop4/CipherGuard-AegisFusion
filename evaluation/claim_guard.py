#!/usr/bin/env python3
"""Validate the public external-evaluation claim contract.

This is a publication/consistency guard, NOT a replacement for the original
competition evaluators.  The complete bodies of ``eval_cicids2017_final_v2.py``
and ``eval_ton_core_zero_shot_1.py`` were not recovered from the sanitized
source bundle.

The guard prevents the most damaging reporting mistakes:

- using the 90.38% main-domain Macro-F1 as a cross-dataset result;
- presenting CICIDS2017 / ToN stress scores as the headline model score;
- removing the external NO-GO conclusion;
- losing ToN's sealed one-shot threshold provenance.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping


DEFAULT_CONTRACT = Path(__file__).with_name("EXTERNAL_EVALUATION_CONTRACT.json")


class ContractError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def load_contract(path: str | Path = DEFAULT_CONTRACT) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ContractError("contract root must be an object")
    return value


def validate_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    primary = contract.get("primary_performance") or {}
    external = contract.get("external_stress_tests") or {}
    policy = contract.get("claim_policy") or {}

    _require(
        primary.get("role") == "independent main-domain test",
        "primary result must remain main-domain independent Test",
    )
    main_macro = float(primary.get("multiclass_macro_f1") or 0.0)
    _require(0.90 <= main_macro < 0.91, "unexpected primary Macro-F1")

    cic = external.get("CICIDS2017") or {}
    ton = external.get("NF-ToN-IoT-v3") or {}
    _require(bool(cic), "missing CICIDS2017 stress track")
    _require(bool(ton), "missing NF-ToN-IoT-v3 stress track")

    _require(cic.get("target_domain_retuning") is False, "CICIDS2017 retuning must be false")
    _require(ton.get("target_domain_retuning") is False, "ToN retuning must be false")
    _require(cic.get("strong_generalization_claim") == "NO_GO", "CICIDS2017 must remain NO_GO")
    _require(ton.get("strong_generalization_claim") == "NO_GO", "ToN must remain NO_GO")

    cic_f1 = float(cic.get("f1") or 0.0)
    ton_f1 = float(ton.get("f1") or 0.0)
    _require(0.32 < cic_f1 < 0.34, "unexpected CICIDS2017 F1")
    _require(0.50 < ton_f1 < 0.52, "unexpected ToN F1")
    _require(main_macro > cic_f1 and main_macro > ton_f1, "external scores must not replace primary score")

    _require(ton.get("common_feature_compatibility") == "42/42", "ToN feature compatibility changed")
    _require(abs(float(ton.get("threshold")) - 0.2666317962) < 1e-12, "ToN threshold changed")
    _require(ton.get("threshold_source") == "CSE source validation", "ToN threshold provenance changed")
    _require(ton.get("one_shot") is True, "ToN must remain one-shot")
    for field in (
        "evaluator_frozen_before_score",
        "model_frozen_before_score",
        "threshold_frozen_before_score",
        "protocol_frozen_before_score",
    ):
        _require(ton.get(field) is True, f"ToN freeze condition lost: {field}")

    forbidden = set(policy.get("forbidden_claims") or [])
    _require("cross-dataset F1 exceeds 90%" in forbidden, "missing cross-dataset claim guard")
    _require("strong zero-shot generalization" in forbidden, "missing zero-shot claim guard")

    return {
        "valid": True,
        "primary_macro_f1": main_macro,
        "cicids2017_f1": cic_f1,
        "ton_f1": ton_f1,
        "external_strong_generalization": "NO_GO",
        "ton_one_shot": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", default=str(DEFAULT_CONTRACT))
    args = parser.parse_args()
    result = validate_contract(load_contract(args.contract))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print("EXTERNAL_EVALUATION_CLAIM_GUARD_OK")


if __name__ == "__main__":
    main()
