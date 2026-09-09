#!/usr/bin/env python3
"""Train the selective past-only Infiltration expert.

This is the GitHub-portable form of the competition freeze's
``train_temporal_infiltration_expert.py``.  Machine-specific paths and generated
competition artifacts were removed, while the frozen modeling logic is kept:

* load the 78D hierarchical Attack/Family models;
* derive 16D probability evidence;
* derive past-only temporal context over windows 8/32/128;
* train only on the Benign/Infiltration boundary with hard negatives;
* choose the expert threshold on Validation;
* report the untouched Test split.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pyarrow.dataset as ds
from catboost import CatBoostClassifier, Pool
from catboost.utils import get_gpu_device_count
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_recall_fscore_support,
    roc_auc_score,
)

from temporal_feature_pipeline import (
    CONTEXT_CANDIDATES,
    DEFAULT_WINDOWS,
    build_probability_features,
    build_temporal_context,
    expected_augmented_dimension,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Train the causal multi-flow temporal-context expert for "
            "Benign versus Infiltration."
        )
    )
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--base-model-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--iterations", type=int, default=1600)
    parser.add_argument("--depth", type=int, default=10)
    parser.add_argument("--learning-rate", type=float, default=0.05)
    parser.add_argument("--early-stopping-rounds", type=int, default=140)
    parser.add_argument("--devices", default="0:1:2:3")
    parser.add_argument("--seed", type=int, default=20260701)
    parser.add_argument("--windows", default="8,32,128")
    parser.add_argument("--hard-negative-ratio", type=float, default=6.0)
    parser.add_argument("--random-negative-ratio", type=float, default=2.0)
    parser.add_argument("--positive-class-weight", type=float, default=1.5)
    parser.add_argument("--max-train-rows", type=int, default=0)
    parser.add_argument("--max-val-rows", type=int, default=0)
    parser.add_argument("--max-test-rows", type=int, default=0)
    parser.add_argument("--cpu", action="store_true")
    return parser.parse_args()


def json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, np.integer):
        return int(value)
    if isinstance(value, np.floating):
        return float(value)
    return value


def class_aware_sample(
    frame: pd.DataFrame,
    max_rows: int,
    seed: int,
) -> pd.DataFrame:
    if max_rows <= 0 or len(frame) <= max_rows:
        return frame.reset_index(drop=True)

    infiltration = frame[frame["target_family"] == "Infiltration"]
    web = frame[frame["target_family"] == "WebAttack"]
    reserved = pd.concat([infiltration, web], ignore_index=False)
    reserved = reserved[~reserved.index.duplicated(keep="first")]

    if len(reserved) >= max_rows:
        return reserved.sample(
            n=max_rows,
            random_state=seed,
            replace=False,
        ).reset_index(drop=True)

    remainder = frame.loc[~frame.index.isin(reserved.index)]
    sampled = remainder.sample(
        n=min(max_rows - len(reserved), len(remainder)),
        random_state=seed,
        replace=False,
    )
    return (
        pd.concat([reserved, sampled], ignore_index=True)
        .sample(frac=1.0, random_state=seed)
        .reset_index(drop=True)
    )


def load_split(
    data_dir: Path,
    split: str,
    columns: list[str],
    max_rows: int,
    seed: int,
) -> pd.DataFrame:
    dataset = ds.dataset(str(data_dir / split), format="parquet")
    missing = [column for column in columns if column not in dataset.schema.names]
    if missing:
        raise RuntimeError(f"{split} missing columns: {missing}")
    frame = dataset.to_table(columns=columns).to_pandas()
    return class_aware_sample(frame, max_rows, seed)


def load_base_models(
    base_model_dir: Path,
) -> tuple[CatBoostClassifier, CatBoostClassifier]:
    binary = CatBoostClassifier()
    binary.load_model(str(base_model_dir / "binary" / "catboost_binary.cbm"))

    family = CatBoostClassifier()
    family.load_model(
        str(
            base_model_dir
            / "attack_family"
            / "catboost_attack_family.cbm"
        )
    )
    return binary, family


def base_predict(
    binary_model: CatBoostClassifier,
    family_model: CatBoostClassifier,
    x: np.ndarray,
    family_threshold: float,
) -> dict[str, np.ndarray]:
    attack_probability = binary_model.predict_proba(x)[:, 1]
    conditional_probability = family_model.predict_proba(x)
    conditional_prediction = np.argmax(
        conditional_probability,
        axis=1,
    ).astype(np.int64)
    family_prediction = np.where(
        attack_probability >= family_threshold,
        conditional_prediction + 1,
        0,
    ).astype(np.int64)
    return {
        "attack_probability": attack_probability,
        "conditional_probability": conditional_probability,
        "conditional_prediction": conditional_prediction,
        "family_prediction": family_prediction,
    }


def select_training_indices(
    true_family: np.ndarray,
    base_prediction: np.ndarray,
    hard_score: np.ndarray,
    benign_id: int,
    infiltration_id: int,
    hard_negative_ratio: float,
    random_negative_ratio: float,
    seed: int,
) -> np.ndarray:
    eligible = (
        ((true_family == benign_id) | (true_family == infiltration_id))
        & (
            (base_prediction == benign_id)
            | (base_prediction == infiltration_id)
        )
    )
    positives = np.flatnonzero(
        eligible & (true_family == infiltration_id)
    )
    negatives = np.flatnonzero(
        eligible & (true_family == benign_id)
    )
    if len(positives) == 0:
        raise RuntimeError("No eligible Infiltration positives")

    hard_count = min(
        len(negatives),
        int(round(len(positives) * hard_negative_ratio)),
    )
    if hard_count:
        negative_scores = hard_score[negatives]
        selected_positions = np.argpartition(
            negative_scores,
            -hard_count,
        )[-hard_count:]
        hard_negatives = negatives[selected_positions]
    else:
        hard_negatives = np.empty(0, dtype=np.int64)

    hard_set = set(hard_negatives.tolist())
    remaining = np.asarray(
        [index for index in negatives if int(index) not in hard_set],
        dtype=np.int64,
    )
    random_count = min(
        len(remaining),
        int(round(len(positives) * random_negative_ratio)),
    )
    rng = np.random.default_rng(seed)
    random_negatives = (
        rng.choice(remaining, size=random_count, replace=False)
        if random_count
        else np.empty(0, dtype=np.int64)
    )

    selected = np.concatenate(
        [positives, hard_negatives, random_negatives]
    )
    rng.shuffle(selected)
    return selected


def apply_gate(
    base_prediction: np.ndarray,
    expert_probability: np.ndarray,
    threshold: float,
    benign_id: int,
    infiltration_id: int,
) -> np.ndarray:
    prediction = base_prediction.copy()
    eligible = (
        (base_prediction == benign_id)
        | (base_prediction == infiltration_id)
    )
    prediction[
        eligible & (expert_probability >= threshold)
    ] = infiltration_id
    prediction[
        eligible & (expert_probability < threshold)
    ] = benign_id
    return prediction


def tune_threshold(
    y_true: np.ndarray,
    base_prediction: np.ndarray,
    expert_probability: np.ndarray,
    benign_id: int,
    infiltration_id: int,
) -> tuple[float, pd.DataFrame]:
    rows: list[dict[str, float]] = []
    for threshold in np.linspace(0.01, 0.99, 197):
        prediction = apply_gate(
            base_prediction,
            expert_probability,
            float(threshold),
            benign_id,
            infiltration_id,
        )
        rows.append(
            {
                "threshold": float(threshold),
                "macro_f1": f1_score(y_true, prediction, average="macro"),
                "balanced_accuracy": balanced_accuracy_score(
                    y_true,
                    prediction,
                ),
                "weighted_f1": f1_score(
                    y_true,
                    prediction,
                    average="weighted",
                ),
            }
        )
    frame = pd.DataFrame(rows)
    best = frame.sort_values(
        ["macro_f1", "balanced_accuracy", "weighted_f1"],
        ascending=False,
    ).iloc[0]
    return float(best["threshold"]), frame


def evaluate(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_names: list[str],
    threshold: float,
) -> dict[str, Any]:
    precision, recall, f1_values, support = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=np.arange(len(class_names)),
        zero_division=0,
    )
    return json_safe(
        {
            "threshold": threshold,
            "accuracy": accuracy_score(y_true, y_pred),
            "balanced_accuracy": balanced_accuracy_score(y_true, y_pred),
            "macro_f1": f1_score(y_true, y_pred, average="macro"),
            "weighted_f1": f1_score(y_true, y_pred, average="weighted"),
            "mcc": matthews_corrcoef(y_true, y_pred),
            "per_class": {
                class_names[index]: {
                    "precision": precision[index],
                    "recall": recall[index],
                    "f1": f1_values[index],
                    "support": support[index],
                }
                for index in range(len(class_names))
            },
            "confusion_matrix": confusion_matrix(
                y_true,
                y_pred,
                labels=np.arange(len(class_names)),
            ),
            "classification_report": classification_report(
                y_true,
                y_pred,
                labels=np.arange(len(class_names)),
                target_names=class_names,
                output_dict=True,
                zero_division=0,
            ),
        }
    )


def predict_in_chunks(
    model: CatBoostClassifier,
    features: np.ndarray,
    chunk_size: int = 250_000,
) -> np.ndarray:
    output = np.empty(len(features), dtype=np.float32)
    for start in range(0, len(features), chunk_size):
        end = min(start + chunk_size, len(features))
        output[start:end] = model.predict_proba(features[start:end])[:, 1]
    return output


def main() -> None:
    args = parse_args()
    started = time.time()

    windows = sorted(
        {
            int(item.strip())
            for item in args.windows.split(",")
            if item.strip()
        }
    )
    if not windows or any(window <= 0 for window in windows):
        raise SystemExit("All context windows must be positive integers")

    data_dir = Path(args.data_dir).resolve()
    base_model_dir = Path(args.base_model_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest = json.loads(
        (data_dir / "manifest.json").read_text(encoding="utf-8")
    )
    base_summary = json.loads(
        (base_model_dir / "summary.json").read_text(encoding="utf-8")
    )
    family_encoder = json.loads(
        (
            base_model_dir
            / "attack_family"
            / "label_encoder.json"
        ).read_text(encoding="utf-8")
    )

    raw_feature_columns = list(manifest["feature_columns"])
    context_columns = [
        column
        for column in CONTEXT_CANDIDATES
        if column in raw_feature_columns
    ]
    if len(context_columns) < 6:
        raise RuntimeError(
            f"Too few temporal context features: {context_columns}"
        )

    attack_class_names = list(family_encoder["class_names"])
    full_class_names = ["Benign"] + attack_class_names
    full_mapping = {
        name: index for index, name in enumerate(full_class_names)
    }
    benign_id = full_mapping["Benign"]
    infiltration_id = full_mapping["Infiltration"]
    infiltration_conditional_id = attack_class_names.index("Infiltration")
    family_threshold = float(
        base_summary["hierarchical_family"]["threshold"]
    )

    required_columns = raw_feature_columns + [
        "target_family",
        "meta__row_hash",
        "meta__source_file",
        "meta__timestamp",
    ]
    frames = {
        "train": load_split(
            data_dir,
            "train",
            required_columns,
            args.max_train_rows,
            args.seed,
        ),
        "val": load_split(
            data_dir,
            "val",
            required_columns,
            args.max_val_rows,
            args.seed + 1,
        ),
        "test": load_split(
            data_dir,
            "test",
            required_columns,
            args.max_test_rows,
            args.seed + 2,
        ),
    }

    temporal_features, temporal_names, temporal_diagnostics = (
        build_temporal_context(frames, context_columns, windows)
    )

    binary_model, family_model = load_base_models(base_model_dir)
    raw_x: dict[str, np.ndarray] = {}
    y_family: dict[str, np.ndarray] = {}
    base_outputs: dict[str, dict[str, np.ndarray]] = {}
    probability_features: dict[str, np.ndarray] = {}
    hard_scores: dict[str, np.ndarray] = {}
    probability_names: list[str] | None = None

    for split, frame in frames.items():
        raw_x[split] = np.ascontiguousarray(
            frame[raw_feature_columns].to_numpy(
                dtype=np.float32,
                copy=True,
            )
        )
        y_family[split] = (
            frame["target_family"]
            .astype(str)
            .map(full_mapping)
            .to_numpy(dtype=np.int64)
        )
        base_outputs[split] = base_predict(
            binary_model,
            family_model,
            raw_x[split],
            family_threshold,
        )
        prob_features, prob_names, hard_score = build_probability_features(
            base_outputs[split],
            attack_class_names,
            infiltration_conditional_id,
        )
        probability_features[split] = prob_features
        hard_scores[split] = hard_score
        if probability_names is None:
            probability_names = prob_names

    assert probability_names is not None

    selected = select_training_indices(
        y_family["train"],
        base_outputs["train"]["family_prediction"],
        hard_scores["train"],
        benign_id,
        infiltration_id,
        args.hard_negative_ratio,
        args.random_negative_ratio,
        args.seed,
    )

    augmented_feature_names = (
        raw_feature_columns + probability_names + temporal_names
    )
    expected = expected_augmented_dimension(
        len(raw_feature_columns),
        len(attack_class_names),
        len(context_columns),
        windows,
    )
    if len(augmented_feature_names) != expected:
        raise RuntimeError(
            "Augmented feature mismatch: "
            f"names={len(augmented_feature_names)} expected={expected}"
        )

    full_x = {
        split: np.ascontiguousarray(
            np.concatenate(
                [
                    raw_x[split],
                    probability_features[split],
                    temporal_features[split],
                ],
                axis=1,
            ),
            dtype=np.float32,
        )
        for split in ("train", "val", "test")
    }

    x_train = full_x["train"][selected]
    y_train = (
        y_family["train"][selected] == infiltration_id
    ).astype(np.int64)

    val_eligible = (
        (
            (y_family["val"] == benign_id)
            | (y_family["val"] == infiltration_id)
        )
        & (
            (base_outputs["val"]["family_prediction"] == benign_id)
            | (
                base_outputs["val"]["family_prediction"]
                == infiltration_id
            )
        )
    )
    x_val = full_x["val"][val_eligible]
    y_val = (
        y_family["val"][val_eligible] == infiltration_id
    ).astype(np.int64)

    gpu_count = int(get_gpu_device_count())
    use_gpu = not args.cpu and gpu_count > 0
    params: dict[str, Any] = {
        "iterations": args.iterations,
        "depth": args.depth,
        "learning_rate": args.learning_rate,
        "loss_function": "Logloss",
        "eval_metric": "F1",
        "custom_metric": ["AUC", "PRAUC", "Precision", "Recall", "F1"],
        "class_weights": [1.0, args.positive_class_weight],
        "random_seed": args.seed,
        "l2_leaf_reg": 8.0,
        "random_strength": 0.4,
        "border_count": 128,
        "boosting_type": "Plain",
        "bootstrap_type": "Bernoulli",
        "subsample": 0.85,
        "use_best_model": True,
        "early_stopping_rounds": args.early_stopping_rounds,
        "verbose": 50,
        "allow_writing_files": True,
        "train_dir": str(output_dir / "catboost_info"),
    }
    if use_gpu:
        params.update(
            {
                "task_type": "GPU",
                "devices": args.devices,
                "gpu_ram_part": 0.85,
            }
        )
    else:
        params.update(
            {
                "task_type": "CPU",
                "thread_count": max(1, os.cpu_count() or 1),
            }
        )

    train_pool = Pool(
        x_train,
        y_train,
        feature_names=augmented_feature_names,
    )
    val_pool = Pool(
        x_val,
        y_val,
        feature_names=augmented_feature_names,
    )
    expert = CatBoostClassifier(**params)
    expert.fit(train_pool, eval_set=val_pool)
    expert.save_model(
        str(output_dir / "catboost_temporal_infiltration_expert.cbm")
    )

    val_probability = predict_in_chunks(expert, full_x["val"])
    test_probability = predict_in_chunks(expert, full_x["test"])

    threshold, threshold_frame = tune_threshold(
        y_family["val"],
        base_outputs["val"]["family_prediction"],
        val_probability,
        benign_id,
        infiltration_id,
    )
    threshold_frame.to_csv(
        output_dir / "threshold_search.csv",
        index=False,
    )

    base_test_prediction = base_outputs["test"]["family_prediction"]
    gated_test_prediction = apply_gate(
        base_test_prediction,
        test_probability,
        threshold,
        benign_id,
        infiltration_id,
    )
    base_metrics = evaluate(
        y_family["test"],
        base_test_prediction,
        full_class_names,
        family_threshold,
    )
    gated_metrics = evaluate(
        y_family["test"],
        gated_test_prediction,
        full_class_names,
        threshold,
    )

    eligible_test = (
        (
            (y_family["test"] == benign_id)
            | (y_family["test"] == infiltration_id)
        )
        & (
            (base_test_prediction == benign_id)
            | (base_test_prediction == infiltration_id)
        )
    )
    eligible_target = (
        y_family["test"][eligible_test] == infiltration_id
    ).astype(np.int64)
    eligible_probability = test_probability[eligible_test]
    expert_metrics = {
        "roc_auc": roc_auc_score(
            eligible_target,
            eligible_probability,
        ),
        "pr_auc": average_precision_score(
            eligible_target,
            eligible_probability,
        ),
        "eligible_rows": int(eligible_test.sum()),
        "positive_rows": int(eligible_target.sum()),
    }

    result = {
        "data_dir": str(data_dir),
        "base_model_dir": str(base_model_dir),
        "output_dir": str(output_dir),
        "raw_feature_count": len(raw_feature_columns),
        "context_columns": context_columns,
        "windows": windows,
        "probability_feature_count": len(probability_names),
        "temporal_feature_count": len(temporal_names),
        "augmented_feature_count": len(augmented_feature_names),
        "base_family_threshold": family_threshold,
        "expert_threshold": threshold,
        "selected_train_rows": int(len(selected)),
        "selected_positive_rows": int(y_train.sum()),
        "selected_negative_rows": int((y_train == 0).sum()),
        "expert_best_iteration": int(expert.get_best_iteration()),
        "temporal_diagnostics": temporal_diagnostics,
        "expert_binary_metrics": json_safe(expert_metrics),
        "arguments": vars(args),
        "base_metrics": base_metrics,
        "gated_metrics": gated_metrics,
        "macro_f1_gain": (
            gated_metrics["macro_f1"] - base_metrics["macro_f1"]
        ),
        "infiltration_f1_gain": (
            gated_metrics["per_class"]["Infiltration"]["f1"]
            - base_metrics["per_class"]["Infiltration"]["f1"]
        ),
        "duration_seconds": time.time() - started,
    }
    (output_dir / "summary.json").write_text(
        json.dumps(json_safe(result), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    pd.DataFrame(
        gated_metrics["classification_report"]
    ).transpose().to_csv(
        output_dir / "classification_report.csv",
        index=True,
    )

    print("========== TEMPORAL EXPERT RESULT ==========")
    print(f"augmented_feature_count={len(augmented_feature_names)}")
    print(f"expert_threshold={threshold:.6f}")
    print(f"base_macro_f1={base_metrics['macro_f1']:.6f}")
    print(f"gated_macro_f1={gated_metrics['macro_f1']:.6f}")
    print(
        "base_infiltration_f1="
        f"{base_metrics['per_class']['Infiltration']['f1']:.6f}"
    )
    print(
        "gated_infiltration_f1="
        f"{gated_metrics['per_class']['Infiltration']['f1']:.6f}"
    )
    print(f"summary={output_dir / 'summary.json'}")


if __name__ == "__main__":
    main()
