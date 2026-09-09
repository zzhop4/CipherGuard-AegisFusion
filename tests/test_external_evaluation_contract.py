#!/usr/bin/env python3
"""Source-only checks for the frozen external-evaluation claim contract."""
from __future__ import annotations

import copy
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation.claim_guard import ContractError, load_contract, validate_contract


def must_fail(value: dict, message_fragment: str) -> None:
    try:
        validate_contract(value)
    except ContractError as exc:
        assert message_fragment in str(exc), (message_fragment, str(exc))
    else:
        raise AssertionError("expected ContractError")


def main() -> None:
    contract = load_contract()
    result = validate_contract(contract)
    assert result["valid"] is True
    assert result["external_strong_generalization"] == "NO_GO"
    assert result["primary_macro_f1"] > result["cicids2017_f1"]
    assert result["primary_macro_f1"] > result["ton_f1"]

    changed = copy.deepcopy(contract)
    changed["external_stress_tests"]["NF-ToN-IoT-v3"]["threshold"] = 0.5
    must_fail(changed, "ToN threshold changed")

    changed = copy.deepcopy(contract)
    changed["external_stress_tests"]["NF-ToN-IoT-v3"]["strong_generalization_claim"] = "GO"
    must_fail(changed, "ToN must remain NO_GO")

    changed = copy.deepcopy(contract)
    changed["external_stress_tests"]["CICIDS2017"]["target_domain_retuning"] = True
    must_fail(changed, "CICIDS2017 retuning must be false")

    changed = copy.deepcopy(contract)
    changed["claim_policy"]["forbidden_claims"].remove("cross-dataset F1 exceeds 90%")
    must_fail(changed, "missing cross-dataset claim guard")

    print("[OK] primary and external result roles remain separated")
    print("[OK] ToN sealed one-shot threshold/freeze contract locked")
    print("[OK] strong zero-shot generalization remains NO-GO")
    print("EXTERNAL_EVALUATION_CONTRACT_OK")


if __name__ == "__main__":
    main()
