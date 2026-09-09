#!/usr/bin/env python3
"""Deterministic source-only checks for the portable ServiceShape contract."""
from __future__ import annotations

import math
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from research.serviceshape.service_relative import (
    PastOnlyServiceShape,
    iqr,
    log_relative,
    median,
    robust_z,
)


def close(left: float, right: float, tolerance: float = 1e-9) -> None:
    assert math.isclose(left, right, rel_tol=tolerance, abs_tol=tolerance), (
        left,
        right,
    )


def test_scalar_contract() -> None:
    close(log_relative(99.0, 9.0), math.log(100.0) - math.log(10.0))
    close(median([1.0, 2.0, 3.0, 4.0]), 2.5)
    close(iqr([1.0, 2.0, 3.0, 4.0]), 1.5)
    close(
        robust_z(4.0, [1.0, 2.0, 3.0], eps=1e-6),
        (4.0 - 2.0) / (1.0 + 1e-6),
    )


def test_past_only_update_order() -> None:
    encoder = PastOnlyServiceShape(eps=1e-6)

    first = encoder.encode_then_update("https", {"bytes": 100.0})
    assert first["past_only"] is True
    assert first["feature_count"] == 0
    assert first["unavailable_features"] == ["bytes"]
    assert encoder.history_count("https", "bytes") == 1

    second = encoder.encode_then_update("https", {"bytes": 300.0})
    item = second["features"]["bytes"]
    assert item["history_count"] == 1
    close(float(item["baseline_median"]), 100.0)
    close(float(item["log_relative"]), log_relative(300.0, 100.0))

    assert encoder.history_count("https", "bytes") == 2

    third_preview = encoder.encode("https", {"bytes": 500.0})
    third_item = third_preview["features"]["bytes"]
    assert third_preview["history_updated"] is False
    assert third_item["history_count"] == 2
    close(float(third_item["baseline_median"]), 200.0)
    assert encoder.history_count("https", "bytes") == 2


def test_service_isolation() -> None:
    encoder = PastOnlyServiceShape()
    encoder.update("service-a", {"bytes": 10.0})
    encoder.update("service-a", {"bytes": 20.0})
    encoder.update("service-b", {"bytes": 1000.0})

    a = encoder.encode("service-a", {"bytes": 30.0})
    b = encoder.encode("service-b", {"bytes": 1200.0})

    assert a["features"]["bytes"]["history_count"] == 2
    close(float(a["features"]["bytes"]["baseline_median"]), 15.0)
    assert b["features"]["bytes"]["history_count"] == 1
    close(float(b["features"]["bytes"]["baseline_median"]), 1000.0)


def test_feature_isolation_and_bounded_history() -> None:
    encoder = PastOnlyServiceShape(max_history=2)
    encoder.update("svc", {"bytes": 1.0, "packets": 2.0})
    encoder.update("svc", {"bytes": 3.0})
    encoder.update("svc", {"bytes": 5.0})

    assert encoder.history_count("svc", "bytes") == 2
    assert encoder.history_count("svc", "packets") == 1

    result = encoder.encode("svc", {"bytes": 7.0, "packets": 4.0})
    close(float(result["features"]["bytes"]["baseline_median"]), 4.0)
    close(float(result["features"]["packets"]["baseline_median"]), 2.0)


def main() -> None:
    test_scalar_contract()
    test_past_only_update_order()
    test_service_isolation()
    test_feature_isolation_and_bounded_history()
    print("[OK] ServiceShape scalar formulas")
    print("[OK] ServiceShape current-flow self-leakage blocked")
    print("[OK] ServiceShape service/feature histories isolated")
    print("SERVICESHAPE_REPRESENTATION_OK")


if __name__ == "__main__":
    main()
