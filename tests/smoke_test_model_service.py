#!/usr/bin/env python3
"""Black-box smoke test for the portable AegisFusion FastAPI service.

No competition dataset is required.  The test obtains the 78 feature names from
the service and sends finite synthetic values solely to verify the runtime
contract, model execution path and causal context accumulation.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


BASE_URL = os.getenv("AEGISFUSION_URL", "http://127.0.0.1:18083").rstrip("/")


def request_json(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        BASE_URL + path,
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"HTTP {exc.code} {method} {path}: {body}"
        ) from exc


def make_synthetic_flow(feature_names: list[str], scale: float) -> dict[str, float]:
    values: dict[str, float] = {}
    for index, name in enumerate(feature_names, start=1):
        values[name] = float((index % 17) + 1) * scale
    return values


def main() -> None:
    print("========== HEALTH ==========")
    health = request_json("GET", "/api/v1/aegisfusion/health")
    print(json.dumps(health, ensure_ascii=False, indent=2))
    if not health.get("model_ready"):
        raise RuntimeError(f"Model not ready: {health.get('model_error')}")

    print("\n========== FEATURE CONTRACT ==========")
    feature_info = request_json("GET", "/api/v1/aegisfusion/features")
    feature_names = list(feature_info["feature_names"])
    print("feature_count =", len(feature_names))
    print("augmented_feature_count =", feature_info["augmented_feature_count"])
    print("context_columns =", feature_info["context_columns"])
    print("windows =", feature_info["windows"])

    if len(feature_names) != 78:
        raise RuntimeError(f"Expected 78 raw features, got {len(feature_names)}")
    if int(feature_info["augmented_feature_count"]) != 229:
        raise RuntimeError(
            "Expected 229 augmented features, got "
            f"{feature_info['augmented_feature_count']}"
        )
    if list(feature_info["windows"]) != [8, 32, 128]:
        raise RuntimeError(f"Unexpected windows: {feature_info['windows']}")

    context_id = "github-smoke-causal-context"
    encoded = urllib.parse.quote(context_id, safe="")
    request_json(
        "POST",
        f"/api/v1/aegisfusion/context/reset?context_id={encoded}",
    )

    print("\n========== CAUSAL CONTEXT ==========")
    depths: list[int] = []
    for index, scale in enumerate((1.0, 1.05, 0.95), start=1):
        result = request_json(
            "POST",
            "/api/v1/aegisfusion/predict/flow",
            {
                "features": make_synthetic_flow(feature_names, scale),
                "context_id": context_id,
                "use_temporal": True,
            },
        )
        depth = int(result["context_history_before_prediction"])
        depths.append(depth)
        print(
            f"flow={index} family={result['family']} "
            f"base={result['base_family']} history_before={depth} "
            f"temporal_applied={result['temporal_applied']}"
        )

    if depths != [0, 1, 2]:
        raise RuntimeError(f"Causal context did not accumulate: {depths}")

    print("\n========== BASE ONLY ==========")
    base_only = request_json(
        "POST",
        "/api/v1/aegisfusion/predict/flow",
        {
            "features": make_synthetic_flow(feature_names, 1.0),
            "context_id": "github-smoke-base-only",
            "use_temporal": False,
        },
    )
    if base_only["temporal_infiltration_probability"] is not None:
        raise RuntimeError("Base-only request unexpectedly used temporal model")
    if base_only["temporal_applied"]:
        raise RuntimeError("Base-only request unexpectedly marked temporal_applied")

    print(
        "family =",
        base_only["family"],
        "model_path =",
        base_only["model_path"],
    )

    final_health = request_json("GET", "/api/v1/aegisfusion/health")
    print("\n========== FINAL ==========")
    print("request_count =", final_health["request_count"])
    print("contexts =", final_health["contexts"])
    print("[OK] 78D -> 229D inference and causal context work.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"\n[ERROR] {type(exc).__name__}: {exc}", file=sys.stderr)
        raise
