#!/usr/bin/env python3
"""Portable ServiceShape service-relative representation core.

IMPORTANT PROVENANCE NOTE
-------------------------
The competition-final materials identify the original research entries as
``audit_service_relative_causal_v1.py``,
``train_serviceshape_xd_relative_v1.py`` and
``eval_serviceshape_xd_unsw.py``. Their complete source bodies were not
recoverable from the current sanitized evidence bundle, so this module is NOT
presented as a byte-for-byte or function-for-function mirror of those files.

Instead, it reconstructs only the method contract that is explicitly frozen in
the final technical materials:

    r(x, b) = log(1 + x) - log(1 + b)
    z_robust = (x - median(H_service)) / (IQR(H_service) + eps)

The service history used for a current flow is strictly past-only.  The current
observation is appended only after its representation has been emitted.
Service identity is a context key, not an output numeric model feature.

ServiceShape remains RESEARCH REPRESENTATION ONLY.  It must not be treated as
the production detector or as evidence that strong zero-shot generalization
has been solved.
"""
from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Iterable, Mapping, Optional


Number = int | float


def _finite_nonnegative(value: Number, *, name: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{name} must be finite")
    if result < 0.0:
        raise ValueError(f"{name} must be non-negative")
    return result


def _quantile(values: Iterable[Number], q: float) -> float:
    """Deterministic linear-interpolation quantile with no third-party deps."""
    data = sorted(float(value) for value in values)
    if not data:
        raise ValueError("quantile requires at least one value")
    if not 0.0 <= q <= 1.0:
        raise ValueError("q must be in [0, 1]")
    if len(data) == 1:
        return data[0]

    position = (len(data) - 1) * q
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return data[lower]
    weight = position - lower
    return data[lower] * (1.0 - weight) + data[upper] * weight


def median(values: Iterable[Number]) -> float:
    return _quantile(values, 0.5)


def iqr(values: Iterable[Number]) -> float:
    data = list(values)
    if not data:
        raise ValueError("IQR requires at least one value")
    return _quantile(data, 0.75) - _quantile(data, 0.25)


def log_relative(value: Number, baseline: Number) -> float:
    """Frozen ServiceShape relative-log transform r(x,b)."""
    x = _finite_nonnegative(value, name="value")
    b = _finite_nonnegative(baseline, name="baseline")
    return math.log1p(x) - math.log1p(b)


def robust_z(value: Number, history: Iterable[Number], *, eps: float = 1e-6) -> float:
    """Frozen robust service-history deviation transform."""
    x = _finite_nonnegative(value, name="value")
    if not math.isfinite(eps) or eps <= 0.0:
        raise ValueError("eps must be finite and positive")

    data = [_finite_nonnegative(item, name="history item") for item in history]
    if not data:
        raise ValueError("robust_z requires non-empty past history")
    center = median(data)
    spread = iqr(data)
    return (x - center) / (spread + eps)


@dataclass(frozen=True)
class FeatureRelativeValue:
    feature: str
    current: float
    history_count: int
    baseline_median: float
    history_iqr: float
    log_relative: float
    robust_z: float

    def as_dict(self) -> dict[str, float | int | str]:
        return {
            "feature": self.feature,
            "current": self.current,
            "history_count": self.history_count,
            "baseline_median": self.baseline_median,
            "history_iqr": self.history_iqr,
            "log_relative": self.log_relative,
            "robust_z": self.robust_z,
        }


class PastOnlyServiceShape:
    """Stateful, past-only ServiceShape encoder.

    ``service_key`` is deliberately opaque.  The caller may define a service as
    a destination-port/service-class tuple or another deployment-appropriate
    grouping.  The key is used only to select history and is never emitted as a
    numeric feature.

    No hard-coded history length is claimed to be competition-frozen.  The
    optional ``max_history`` is therefore an implementation control for this
    portable reconstruction, not an experimental hyperparameter claim.
    """

    def __init__(self, *, max_history: Optional[int] = None, eps: float = 1e-6):
        if max_history is not None and max_history <= 0:
            raise ValueError("max_history must be positive when provided")
        if not math.isfinite(eps) or eps <= 0.0:
            raise ValueError("eps must be finite and positive")
        self.max_history = max_history
        self.eps = float(eps)
        self._history: Dict[str, Dict[str, Deque[float]]] = defaultdict(dict)

    def _series(self, service_key: str, feature: str) -> Deque[float]:
        service = self._history[str(service_key)]
        if feature not in service:
            service[feature] = deque(maxlen=self.max_history)
        return service[feature]

    def history_count(self, service_key: str, feature: str) -> int:
        return len(self._series(str(service_key), str(feature)))

    def encode(
        self,
        service_key: str,
        values: Mapping[str, Number],
    ) -> dict[str, object]:
        """Encode a flow against history that existed before this call.

        This method never mutates history.  Features with no prior service
        history are reported under ``unavailable_features`` rather than being
        silently assigned a zero baseline.
        """
        encoded: dict[str, dict[str, float | int | str]] = {}
        unavailable: list[str] = []

        for feature in sorted(values):
            current = _finite_nonnegative(values[feature], name=feature)
            history = list(self._series(str(service_key), str(feature)))
            if not history:
                unavailable.append(str(feature))
                continue

            center = median(history)
            spread = iqr(history)
            item = FeatureRelativeValue(
                feature=str(feature),
                current=current,
                history_count=len(history),
                baseline_median=center,
                history_iqr=spread,
                log_relative=log_relative(current, center),
                robust_z=(current - center) / (spread + self.eps),
            )
            encoded[str(feature)] = item.as_dict()

        return {
            "representation": "serviceshape-service-relative",
            "role": "research_representation_only",
            "past_only": True,
            "history_updated": False,
            "feature_count": len(encoded),
            "features": encoded,
            "unavailable_features": unavailable,
        }

    def update(self, service_key: str, values: Mapping[str, Number]) -> None:
        """Append an observation after its representation has been computed."""
        for feature, value in values.items():
            numeric = _finite_nonnegative(value, name=str(feature))
            self._series(str(service_key), str(feature)).append(numeric)

    def encode_then_update(
        self,
        service_key: str,
        values: Mapping[str, Number],
    ) -> dict[str, object]:
        """Causal convenience operation: encode first, update second."""
        result = self.encode(service_key, values)
        self.update(service_key, values)
        result["history_updated"] = True
        return result

    def clear(self) -> None:
        self._history.clear()
