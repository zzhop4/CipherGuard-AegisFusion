#!/usr/bin/env python3
"""AegisFusion production-style model service.

Portable GitHub version of the competition model service.  It serves the
frozen hierarchical CatBoost detector plus the selective causal temporal
Infiltration expert without depending on the original `/mnt/data/...` layout.

The service never receives application payload bytes.  Its request contract is
an ordered set of the 78 leakage-controlled flow features defined by
``manifest.json``.
"""
from __future__ import annotations

import json
import math
import os
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Optional

import numpy as np
from catboost import CatBoostClassifier
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


# app.py -> aegisfusion_service -> model_runtime -> services -> repository root
REPO_ROOT = Path(__file__).resolve().parents[3]
PROJECT = Path(
    os.getenv(
        "AEGISFUSION_PROJECT",
        str(REPO_ROOT / "runtime" / "aegisfusion_project"),
    )
).resolve()
APP_ROOT = Path(
    os.getenv(
        "CIPHERGUARD_APP",
        str(REPO_ROOT / "runtime" / "cipherguard_app"),
    )
).resolve()
DATA_DIR = Path(
    os.getenv(
        "AEGISFUSION_DATA_DIR",
        str(REPO_ROOT / "data" / "processed" / "tabular_v1"),
    )
).resolve()
BASE_MODEL_DIR = Path(
    os.getenv(
        "AEGISFUSION_BASE_MODEL_DIR",
        str(REPO_ROOT / "models" / "hierarchical_full_v1"),
    )
).resolve()
TEMPORAL_MODEL_DIR = Path(
    os.getenv(
        "AEGISFUSION_TEMPORAL_MODEL_DIR",
        str(REPO_ROOT / "models" / "temporal_infiltration_full_v1"),
    )
).resolve()


app = FastAPI(
    title="AegisFusion_NIDS Model Service",
    version="1.1.0-portable",
    description=(
        "Hierarchical CatBoost plus causal temporal Infiltration expert. "
        "The service accepts flow metadata features only; it does not decrypt "
        "or inspect TLS/SSH application payload content."
    ),
)

_allowed_origins = [
    item.strip()
    for item in os.getenv("AEGISFUSION_CORS_ORIGINS", "*").split(",")
    if item.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins or ["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class FlowPredictionRequest(BaseModel):
    features: dict[str, float] = Field(
        ...,
        description="Exactly the 78 leakage-controlled CIC flow features.",
    )
    context_id: str = Field(default="global", min_length=1, max_length=128)
    use_temporal: bool = True


class BatchPredictionRequest(BaseModel):
    flows: list[FlowPredictionRequest]
    reset_context_before: bool = False


class Runtime:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.ready = False
        self.error: Optional[str] = None
        self.loaded_at = 0.0
        self.request_count = 0

        self.feature_columns: list[str] = []
        self.context_columns: list[str] = []
        self.context_indexes: list[int] = []
        self.windows: list[int] = []
        self.attack_class_names: list[str] = []
        self.full_class_names: list[str] = []
        self.full_mapping: dict[str, int] = {}

        # Values are overwritten from the frozen summaries during load().
        self.family_threshold = 0.36
        self.expert_threshold = 0.85
        self.max_history = 128

        self.binary_model: Optional[CatBoostClassifier] = None
        self.family_model: Optional[CatBoostClassifier] = None
        self.temporal_model: Optional[CatBoostClassifier] = None

        self.histories: dict[str, deque[np.ndarray]] = defaultdict(deque)
        self.load()

    @staticmethod
    def read_json(path: Path) -> dict[str, Any]:
        if not path.exists():
            raise FileNotFoundError(path)
        return json.loads(path.read_text(encoding="utf-8"))

    def load(self) -> None:
        """Load the feature contract and all three frozen CatBoost models."""
        started = time.time()
        try:
            manifest = self.read_json(DATA_DIR / "manifest.json")
            base_summary = self.read_json(BASE_MODEL_DIR / "summary.json")
            encoder = self.read_json(
                BASE_MODEL_DIR / "attack_family" / "label_encoder.json"
            )
            temporal_summary = self.read_json(
                TEMPORAL_MODEL_DIR / "summary.json"
            )

            feature_columns = list(manifest["feature_columns"])
            attack_class_names = list(encoder["class_names"])
            full_class_names = ["Benign", *attack_class_names]
            full_mapping = {
                name: index for index, name in enumerate(full_class_names)
            }
            context_columns = list(temporal_summary["context_columns"])
            context_indexes = [
                feature_columns.index(name) for name in context_columns
            ]
            windows = [
                int(value) for value in temporal_summary.get("windows", [8, 32, 128])
            ]
            if not windows or any(value <= 0 for value in windows):
                raise RuntimeError(f"Invalid temporal windows: {windows}")

            family_threshold = float(
                temporal_summary.get(
                    "base_family_threshold",
                    base_summary["hierarchical_family"]["threshold"],
                )
            )
            expert_threshold = float(temporal_summary["expert_threshold"])

            binary = CatBoostClassifier()
            binary.load_model(
                str(BASE_MODEL_DIR / "binary" / "catboost_binary.cbm")
            )
            family = CatBoostClassifier()
            family.load_model(
                str(
                    BASE_MODEL_DIR
                    / "attack_family"
                    / "catboost_attack_family.cbm"
                )
            )
            temporal = CatBoostClassifier()
            temporal.load_model(
                str(
                    TEMPORAL_MODEL_DIR
                    / "catboost_temporal_infiltration_expert.cbm"
                )
            )

            expected = (
                len(feature_columns)
                + 10
                + len(attack_class_names)
                + len(context_columns) * len(windows) * 3
            )

            # CatBoost 1.2.x exposes feature_names_ but not feature_count_.
            temporal_feature_names = getattr(
                temporal,
                "feature_names_",
                None,
            )
            model_feature_count = (
                len(temporal_feature_names)
                if temporal_feature_names
                else expected
            )
            if model_feature_count != expected:
                raise RuntimeError(
                    "Temporal feature mismatch: "
                    f"model={model_feature_count}, expected={expected}"
                )

            with self.lock:
                self.feature_columns = feature_columns
                self.attack_class_names = attack_class_names
                self.full_class_names = full_class_names
                self.full_mapping = full_mapping
                self.context_columns = context_columns
                self.context_indexes = context_indexes
                self.windows = windows
                self.max_history = max(windows)
                self.family_threshold = family_threshold
                self.expert_threshold = expert_threshold
                self.binary_model = binary
                self.family_model = family
                self.temporal_model = temporal
                self.histories.clear()
                self.loaded_at = time.time()
                self.error = None
                self.ready = True

            print(
                "[AegisFusion] loaded in "
                f"{time.time() - started:.3f}s "
                f"raw={len(feature_columns)} augmented={expected}",
                flush=True,
            )
        except Exception as exc:  # service stays alive and exposes health error
            with self.lock:
                self.ready = False
                self.error = f"{type(exc).__name__}: {exc}"
                self.binary_model = None
                self.family_model = None
                self.temporal_model = None
            print(f"[AegisFusion] load failed: {self.error}", flush=True)

    def validate(self, features: dict[str, float]) -> np.ndarray:
        expected = set(self.feature_columns)
        received = set(features)
        missing = sorted(expected - received)
        extra = sorted(received - expected)
        if missing or extra:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "feature_contract_mismatch",
                    "expected_count": len(self.feature_columns),
                    "received_count": len(features),
                    "missing": missing,
                    "extra": extra,
                },
            )

        values: list[float] = []
        non_finite: list[str] = []
        invalid: list[str] = []
        for name in self.feature_columns:
            try:
                value = float(features[name])
            except (TypeError, ValueError):
                invalid.append(name)
                value = 0.0
            if not math.isfinite(value):
                non_finite.append(name)
            values.append(value)

        if invalid or non_finite:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "invalid_feature_value",
                    "invalid": invalid,
                    "non_finite": non_finite,
                },
            )

        return np.asarray(values, dtype=np.float32)

    def base_predict(self, raw: np.ndarray) -> dict[str, Any]:
        assert self.binary_model is not None
        assert self.family_model is not None

        x = raw.reshape(1, -1)
        attack_probability = float(
            self.binary_model.predict_proba(x)[0, 1]
        )
        conditional = np.asarray(
            self.family_model.predict_proba(x)[0],
            dtype=np.float32,
        )
        conditional_id = int(np.argmax(conditional))
        base_id = (
            conditional_id + 1
            if attack_probability >= self.family_threshold
            else self.full_mapping["Benign"]
        )
        return {
            "attack_probability": attack_probability,
            "conditional_probability": conditional,
            "conditional_id": conditional_id,
            "base_id": int(base_id),
        }

    def probability_features(self, base: dict[str, Any]) -> np.ndarray:
        """Build the 16D probability evidence used by the temporal expert."""
        attack = float(base["attack_probability"])
        conditional = np.asarray(
            base["conditional_probability"],
            dtype=np.float32,
        )

        ordered = np.sort(conditional)
        top1 = float(ordered[-1])
        top2 = float(ordered[-2])
        margin = top1 - top2
        clipped = np.clip(conditional, 1e-12, 1.0)
        entropy = float(-np.sum(clipped * np.log(clipped)))

        infiltration_id = self.attack_class_names.index("Infiltration")
        infiltration_conditional = float(conditional[infiltration_id])
        infiltration_joint = attack * infiltration_conditional
        benign_probability = 1.0 - attack

        other = conditional.copy()
        other[infiltration_id] = 0.0
        strongest_other_joint = attack * float(np.max(other))
        infiltration_advantage = (
            infiltration_joint
            - max(benign_probability, strongest_other_joint)
        )

        values = [
            attack,
            benign_probability,
            infiltration_conditional,
            infiltration_joint,
            strongest_other_joint,
            infiltration_advantage,
            top1,
            top2,
            margin,
            entropy,
            *[float(item) for item in conditional],
        ]
        return np.asarray(values, dtype=np.float32)

    def temporal_features(
        self,
        current: np.ndarray,
        context_id: str,
    ) -> tuple[np.ndarray, int]:
        """Create causal mean/std/z context and only then append current flow."""
        history = self.histories[context_id]
        depth = len(history)
        history_list = list(history)
        parts: list[np.ndarray] = []
        current64 = current.astype(np.float64, copy=True)

        for window in self.windows:
            count = min(depth, window)
            if count == 0:
                mean = current64.copy()
                std = np.zeros_like(current64)
            else:
                prior = np.stack(
                    history_list[-count:],
                    axis=0,
                ).astype(np.float64, copy=False)
                mean = prior.mean(axis=0)
                std = prior.std(axis=0)

            z = (current64 - mean) / (
                std + np.abs(mean) * 1e-6 + 1e-6
            )
            z = np.clip(z, -25.0, 25.0)
            parts.extend(
                [
                    mean.astype(np.float32),
                    std.astype(np.float32),
                    z.astype(np.float32),
                ]
            )

        history.append(current.astype(np.float32, copy=True))
        while len(history) > self.max_history:
            history.popleft()

        return np.concatenate(parts).astype(np.float32), depth

    def predict(self, req: FlowPredictionRequest) -> dict[str, Any]:
        if not self.ready:
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "model_not_ready",
                    "reason": self.error,
                },
            )

        with self.lock:
            raw = self.validate(req.features)
            base = self.base_predict(raw)
            base_id = int(base["base_id"])
            final_id = base_id
            expert_probability: Optional[float] = None
            history_depth = len(self.histories[req.context_id])
            temporal_applied = False

            if req.use_temporal:
                assert self.temporal_model is not None
                current = raw[self.context_indexes]
                temporal, history_depth = self.temporal_features(
                    current,
                    req.context_id,
                )
                augmented = np.concatenate(
                    [
                        raw,
                        self.probability_features(base),
                        temporal,
                    ]
                ).astype(np.float32).reshape(1, -1)
                expert_probability = float(
                    self.temporal_model.predict_proba(augmented)[0, 1]
                )

                benign_id = self.full_mapping["Benign"]
                infiltration_id = self.full_mapping["Infiltration"]
                if base_id in (benign_id, infiltration_id):
                    temporal_applied = True
                    final_id = (
                        infiltration_id
                        if expert_probability >= self.expert_threshold
                        else benign_id
                    )

            conditional = np.asarray(
                base["conditional_probability"],
                dtype=np.float32,
            )
            attack = float(base["attack_probability"])
            base_family = self.full_class_names[base_id]
            final_family = self.full_class_names[final_id]
            conditional_map = {
                name: float(conditional[index])
                for index, name in enumerate(self.attack_class_names)
            }

            if final_family == "Benign":
                confidence = 1.0 - attack
            elif (
                final_family == "Infiltration"
                and expert_probability is not None
                and temporal_applied
            ):
                confidence = expert_probability
            else:
                conditional_index = final_id - 1
                confidence = attack * float(conditional[conditional_index])

            evidence: list[dict[str, Any]] = [
                {
                    "type": "binary_attack_probability",
                    "value": attack,
                    "threshold": self.family_threshold,
                }
            ]
            strongest_conditional_id = int(np.argmax(conditional))
            evidence.append(
                {
                    "type": "conditional_family_probability",
                    "family": self.attack_class_names[strongest_conditional_id],
                    "value": float(conditional[strongest_conditional_id]),
                }
            )
            if expert_probability is not None:
                evidence.append(
                    {
                        "type": "temporal_infiltration_probability",
                        "value": expert_probability,
                        "threshold": self.expert_threshold,
                        "history_depth": history_depth,
                        "context_id": req.context_id,
                    }
                )

            self.request_count += 1

            return {
                "status": "ok",
                "family": final_family,
                "family_id": int(final_id),
                "base_family": base_family,
                "confidence": float(max(0.0, min(1.0, confidence))),
                "risk_score": float(max(0.0, min(100.0, attack * 100.0))),
                "attack_probability": attack,
                "temporal_infiltration_probability": expert_probability,
                "temporal_applied": temporal_applied,
                "context_id": req.context_id,
                "context_history_before_prediction": int(history_depth),
                "model_path": (
                    "hierarchical_catboost+causal_temporal_infiltration_expert"
                    if req.use_temporal
                    else "hierarchical_catboost"
                ),
                "conditional_probabilities": conditional_map,
                "evidence": evidence,
            }

    def reset_context(self, context_id: Optional[str] = None) -> int:
        with self.lock:
            if context_id is None:
                removed = len(self.histories)
                self.histories.clear()
                return removed
            existed = context_id in self.histories
            self.histories.pop(context_id, None)
            return int(existed)

    def augmented_feature_count(self) -> int:
        if not self.feature_columns:
            return 0
        return (
            len(self.feature_columns)
            + 10
            + len(self.attack_class_names)
            + len(self.context_columns) * len(self.windows) * 3
        )


runtime = Runtime()


def health() -> dict[str, Any]:
    with runtime.lock:
        return {
            "status": "ok" if runtime.ready else "degraded",
            "service": "aegisfusion-model-service",
            "model_ready": runtime.ready,
            "model_error": runtime.error,
            "loaded_at": runtime.loaded_at,
            "request_count": runtime.request_count,
            "contexts": {
                key: len(value)
                for key, value in runtime.histories.items()
            },
            "raw_feature_count": len(runtime.feature_columns),
            "augmented_feature_count": runtime.augmented_feature_count(),
        }


@app.get("/")
def root() -> dict[str, Any]:
    return {
        "service": "AegisFusion_NIDS",
        "version": app.version,
        "health": "/api/v1/aegisfusion/health",
        "docs": "/docs",
    }


@app.get("/health")
@app.get("/api/v1/aegisfusion/health")
def health_endpoint() -> JSONResponse:
    payload = health()
    return JSONResponse(
        status_code=200 if runtime.ready else 503,
        content=payload,
    )


@app.get("/api/v1/aegisfusion/features")
def features() -> dict[str, Any]:
    return {
        "feature_count": len(runtime.feature_columns),
        "feature_names": runtime.feature_columns,
        "context_columns": runtime.context_columns,
        "windows": runtime.windows,
        "probability_feature_count": 10 + len(runtime.attack_class_names),
        "temporal_feature_count": (
            len(runtime.context_columns) * len(runtime.windows) * 3
        ),
        "augmented_feature_count": runtime.augmented_feature_count(),
    }


@app.get("/api/v1/aegisfusion/models")
def models() -> dict[str, Any]:
    return {
        "model_ready": runtime.ready,
        "production_model": [
            "hierarchical_full_v1",
            "temporal_infiltration_full_v1",
        ],
        "family_threshold": runtime.family_threshold,
        "expert_threshold": runtime.expert_threshold,
        "attack_families": runtime.attack_class_names,
    }


@app.get("/api/v1/aegisfusion/metrics")
def metrics() -> dict[str, Any]:
    # Different evaluation tasks are intentionally reported separately.
    return {
        "project": "CipherGuard-AegisFusion",
        "production": {
            "main_iid_macro_f1": 0.903822,
            "infiltration_f1": 0.575132,
        },
        "generalization_boundaries": [
            {"name": "cross_date", "macro_f1": 0.6578},
            {"name": "unseen_subtype", "macro_f1": 0.6014},
            {"name": "mixed_stress", "macro_f1": 0.5827},
        ],
        "warning": (
            "These values belong to different evaluation settings and must "
            "not be averaged into one score."
        ),
    }


@app.post("/api/v1/aegisfusion/predict/flow")
def predict_flow(request: FlowPredictionRequest) -> dict[str, Any]:
    return runtime.predict(request)


@app.post("/api/v1/aegisfusion/predict/batch")
def predict_batch(request: BatchPredictionRequest) -> dict[str, Any]:
    if not 1 <= len(request.flows) <= 10_000:
        raise HTTPException(
            status_code=422,
            detail="batch size must be between 1 and 10000",
        )
    if request.reset_context_before:
        runtime.reset_context()
    results = [runtime.predict(flow) for flow in request.flows]
    return {
        "status": "ok",
        "count": len(results),
        "results": results,
    }


@app.post("/api/v1/aegisfusion/context/reset")
def reset_context(context_id: Optional[str] = None) -> dict[str, Any]:
    removed = runtime.reset_context(context_id)
    return {
        "status": "ok",
        "context_id": context_id,
        "removed_contexts": removed,
    }


@app.post("/api/v1/aegisfusion/reload")
def reload_models() -> JSONResponse:
    runtime.load()
    return JSONResponse(
        status_code=200 if runtime.ready else 503,
        content=health(),
    )
