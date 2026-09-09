#!/usr/bin/env python3
"""Regression guard for the public-facing README claim surface.

The machine evaluation contract protects experiment metadata. This test protects
the short claims a portfolio reader is most likely to see in README.md.
"""
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"

REQUIRED_FRAGMENTS = [
    "| CSE-CIC-IDS2018 独立 Test | 7 类 Macro-F1 | **90.38%** |",
    "| CICIDS2017 | 无目标域调参 external stress | **32.65%** | **66.06%** | strong generalization NO-GO |",
    "| NF-ToN-IoT-v3 | sealed one-shot | **51.06%** | **56.40%** | method integrity PASS / zero-shot NO-GO |",
    "| ChainLens V2 | Evidence-graph edge reduction | **99.23%** |",
    "| Controlled Campaign | 异常场景 | **7 / 7** |",
    "> **Representation GO；Standalone Detector NO-GO。**",
    "threshold `0.2666317962` 来自 **CSE source validation**",
    "当前公开的是**证据/claim contract**，不是伪造的 evaluator mirror。",
]

FORBIDDEN_FRAGMENTS = [
    "cross-dataset F1 exceeds 90%",
    "cross-dataset F1 = 90.38%",
    "cross-dataset F1: 90.38%",
    "strong zero-shot generalization = GO",
    "strong zero-shot generalization = PASS",
    "strong zero-shot generalization solved",
    "99.23% detection accuracy",
    "99.23% 检测准确率",
    "7/7 proves real-world generalization",
    "Standalone Detector GO",
]


def main() -> int:
    text = README.read_text(encoding="utf-8")

    missing = [fragment for fragment in REQUIRED_FRAGMENTS if fragment not in text]
    if missing:
        print("Missing required public claim fragments:")
        for fragment in missing:
            print(f"  - {fragment}")
        raise SystemExit(1)

    lowered = text.lower()
    forbidden_hits = [
        fragment
        for fragment in FORBIDDEN_FRAGMENTS
        if fragment.lower() in lowered
    ]
    if forbidden_hits:
        print("Forbidden public claim fragments detected:")
        for fragment in forbidden_hits:
            print(f"  - {fragment}")
        raise SystemExit(1)

    primary_index = text.index("**90.38%**")
    primary_context = text[max(0, primary_index - 120) : primary_index + 120]
    if "CSE-CIC-IDS2018 独立 Test" not in primary_context:
        raise AssertionError("90.38% lost its main-domain independent-Test qualifier")

    for marker in ("减少约 **99.23%**", "**99.23%** |"):
        index = text.index(marker)
        context = text[max(0, index - 180) : index + 180].lower()
        if "edge reduction" not in context and "图稀疏化" not in context:
            raise AssertionError("99.23% lost its attribution/edge-reduction context")

    print("PUBLIC_CLAIM_SURFACE_OK")
    print("PRIMARY=main-domain-90.38")
    print("CICIDS2017=external-stress-32.65")
    print("TON=sealed-one-shot-51.06")
    print("CHAINLENS=edge-reduction-99.23")
    print("SERVICESHAPE=representation-go-detector-no-go")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
