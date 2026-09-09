"""Temporal feature construction recovered from the competition freeze.

This module contains the reusable, inference-relevant feature construction from
``train_temporal_infiltration_expert.py``.  It intentionally contains no model
weights and no dataset-specific absolute paths.

The frozen expert uses:
    78 raw flow features
  + 16 probability-evidence features
  + 135 past-only temporal-context features
  = 229 dimensions
"""
from __future__ import annotations

import gc
from typing import Any

import numpy as np
import pandas as pd


CONTEXT_CANDIDATES = [
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Fwd Pkt Len Mean",
    "Bwd Pkt Len Mean",
    "Pkt Len Mean",
    "Pkt Len Std",
    "Active Mean",
    "Idle Mean",
    "Init Fwd Win Byts",
    "Init Bwd Win Byts",
]

DEFAULT_WINDOWS = [8, 32, 128]


def probability_entropy(probabilities: np.ndarray) -> np.ndarray:
    clipped = np.clip(probabilities, 1e-12, 1.0)
    return -np.sum(clipped * np.log(clipped), axis=1)


def build_probability_features(
    base: dict[str, np.ndarray],
    attack_class_names: list[str],
    infiltration_conditional_id: int,
) -> tuple[np.ndarray, list[str], np.ndarray]:
    """Build the 16D probability-evidence vector used by the expert.

    With the six attack families in the competition freeze, this produces ten
    derived statistics plus six conditional family probabilities.
    """
    attack_probability = base["attack_probability"].astype(np.float32)
    conditional = base["conditional_probability"].astype(np.float32)

    ordered = np.sort(conditional, axis=1)
    top1 = ordered[:, -1]
    top2 = ordered[:, -2]
    margin = top1 - top2
    entropy = probability_entropy(conditional).astype(np.float32)

    infiltration_conditional = conditional[:, infiltration_conditional_id]
    infiltration_joint = attack_probability * infiltration_conditional
    benign_probability = 1.0 - attack_probability

    other = conditional.copy()
    other[:, infiltration_conditional_id] = 0.0
    strongest_other_joint = attack_probability * np.max(other, axis=1)

    infiltration_advantage = (
        infiltration_joint
        - np.maximum(benign_probability, strongest_other_joint)
    )

    parts = [
        attack_probability[:, None],
        benign_probability[:, None],
        infiltration_conditional[:, None],
        infiltration_joint[:, None],
        strongest_other_joint[:, None],
        infiltration_advantage[:, None],
        top1[:, None],
        top2[:, None],
        margin[:, None],
        entropy[:, None],
    ]
    names = [
        "prob__attack",
        "prob__benign",
        "prob__infiltration_conditional",
        "prob__infiltration_joint",
        "prob__strongest_other_joint",
        "prob__infiltration_advantage",
        "prob__family_top1",
        "prob__family_top2",
        "prob__family_margin",
        "prob__family_entropy",
    ]

    for index, name in enumerate(attack_class_names):
        safe = name.lower().replace(" ", "_").replace("-", "_")
        parts.append(conditional[:, index : index + 1])
        names.append(f"prob__conditional_{safe}")

    features = np.ascontiguousarray(
        np.concatenate(parts, axis=1),
        dtype=np.float32,
    )

    hard_score = (
        infiltration_joint
        + 0.30 * attack_probability
        + 0.20 * (1.0 - margin)
        + 0.10 * entropy
    ).astype(np.float32)

    return features, names, hard_score


def causal_window_statistics(
    values: np.ndarray,
    windows: list[int],
) -> tuple[np.ndarray, list[str]]:
    """Compute past-only mean/std/z features for each temporal window.

    Row ``t`` is compared only with rows strictly before ``t``.  The current
    row is never included in its own historical summary.
    """
    row_count, feature_count = values.shape
    output_parts: list[np.ndarray] = []
    names: list[str] = []

    values64 = values.astype(np.float64, copy=False)
    cumulative = np.empty(
        (row_count + 1, feature_count),
        dtype=np.float64,
    )
    cumulative_sq = np.empty_like(cumulative)
    cumulative[0] = 0.0
    cumulative_sq[0] = 0.0
    np.cumsum(values64, axis=0, out=cumulative[1:])
    np.cumsum(values64 * values64, axis=0, out=cumulative_sq[1:])

    positions = np.arange(row_count, dtype=np.int64)

    for window in windows:
        starts = np.maximum(0, positions - window)
        counts = positions - starts
        safe_counts = np.maximum(counts, 1).astype(np.float64)

        sums = cumulative[positions] - cumulative[starts]
        sums_sq = cumulative_sq[positions] - cumulative_sq[starts]

        means = sums / safe_counts[:, None]
        variances = sums_sq / safe_counts[:, None] - means * means
        variances = np.maximum(variances, 0.0)
        stds = np.sqrt(variances)

        no_history = counts == 0
        if np.any(no_history):
            means[no_history] = values64[no_history]
            stds[no_history] = 0.0

        zscores = (
            (values64 - means)
            / (stds + np.abs(means) * 1e-6 + 1e-6)
        )
        zscores = np.clip(zscores, -25.0, 25.0)

        output_parts.extend(
            [
                means.astype(np.float32),
                stds.astype(np.float32),
                zscores.astype(np.float32),
            ]
        )

        names.extend(
            [f"ctx_w{window}__mean__{index}" for index in range(feature_count)]
        )
        names.extend(
            [f"ctx_w{window}__std__{index}" for index in range(feature_count)]
        )
        names.extend(
            [f"ctx_w{window}__z__{index}" for index in range(feature_count)]
        )

    return (
        np.ascontiguousarray(
            np.concatenate(output_parts, axis=1),
            dtype=np.float32,
        ),
        names,
    )


def build_temporal_context(
    frames: dict[str, pd.DataFrame],
    context_columns: list[str],
    windows: list[int] | None = None,
) -> tuple[dict[str, np.ndarray], list[str], dict[str, int]]:
    """Build causal context across train/val/test while respecting time order.

    The original freeze groups flows by source file, sorts by timestamp and a
    deterministic row hash, then computes the historical features.  Split
    positions are restored afterwards so callers receive arrays aligned to
    their original DataFrames.
    """
    if windows is None:
        windows = DEFAULT_WINDOWS

    pieces: list[pd.DataFrame] = []
    split_names = ["train", "val", "test"]

    for split_code, split in enumerate(split_names):
        piece = frames[split][
            [
                "meta__row_hash",
                "meta__source_file",
                "meta__timestamp",
            ]
            + context_columns
        ].copy()
        piece["_split_code"] = split_code
        piece["_split_position"] = np.arange(len(piece), dtype=np.int64)
        pieces.append(piece)

    stream = pd.concat(pieces, ignore_index=True)

    parsed_time = pd.to_datetime(
        stream["meta__timestamp"],
        errors="coerce",
        dayfirst=True,
        format="mixed",
    )
    stream["_timestamp_ns"] = parsed_time.astype("int64")
    invalid_timestamp_count = int(parsed_time.isna().sum())

    context_feature_count = len(context_columns) * len(windows) * 3
    context_matrix = np.zeros(
        (len(stream), context_feature_count),
        dtype=np.float32,
    )

    feature_names: list[str] | None = None

    for source_file, group_index in stream.groupby(
        "meta__source_file",
        sort=False,
    ).groups.items():
        indices = np.asarray(group_index, dtype=np.int64)
        timestamps = stream.loc[indices, "_timestamp_ns"].to_numpy(
            dtype=np.int64,
            copy=False,
        )
        hashes = stream.loc[indices, "meta__row_hash"].to_numpy(
            dtype=np.uint64,
            copy=False,
        )

        order = np.lexsort((hashes, timestamps))
        sorted_indices = indices[order]

        values = stream.loc[
            sorted_indices,
            context_columns,
        ].to_numpy(dtype=np.float32, copy=True)

        local_context, _ = causal_window_statistics(values, windows)
        context_matrix[sorted_indices] = local_context

        if feature_names is None:
            feature_names = []
            for window in windows:
                for statistic in ("mean", "std", "z"):
                    for column in context_columns:
                        feature_names.append(
                            f"ctx_w{window}__{statistic}__{column}"
                        )

    if feature_names is None:
        raise RuntimeError("No temporal context groups were constructed")

    output: dict[str, np.ndarray] = {}
    split_codes = stream["_split_code"].to_numpy()
    for split_code, split in enumerate(split_names):
        mask = split_codes == split_code
        positions = stream.loc[mask, "_split_position"].to_numpy(
            dtype=np.int64,
        )
        values = context_matrix[mask]
        ordered = np.empty_like(values)
        ordered[positions] = values
        output[split] = ordered

    diagnostics = {
        "combined_rows": int(len(stream)),
        "invalid_timestamp_rows": invalid_timestamp_count,
        "source_file_count": int(stream["meta__source_file"].nunique()),
    }

    del stream, context_matrix, pieces
    gc.collect()
    return output, feature_names, diagnostics


def expected_augmented_dimension(
    raw_feature_count: int,
    attack_family_count: int,
    context_column_count: int,
    windows: list[int] | None = None,
) -> int:
    """Return the exact augmented input dimension expected by the expert."""
    if windows is None:
        windows = DEFAULT_WINDOWS
    probability_feature_count = 10 + attack_family_count
    temporal_feature_count = context_column_count * len(windows) * 3
    return raw_feature_count + probability_feature_count + temporal_feature_count
