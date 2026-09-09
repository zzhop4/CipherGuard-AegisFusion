#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gc
import json
import os
import time
from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pyarrow.dataset as ds
from catboost import CatBoostClassifier, Pool
from catboost.utils import get_gpu_device_count
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_recall_fscore_support,
    roc_auc_score,
    average_precision_score,
)
from sklearn.preprocessing import LabelEncoder


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hierarchical CatBoost baseline for CIC-IDS2018."
    )
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--binary-iterations", type=int, default=1400)
    parser.add_argument("--family-iterations", type=int, default=1600)
    parser.add_argument("--depth", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=0.07)
    parser.add_argument("--early-stopping-rounds", type=int, default=120)
    parser.add_argument("--devices", default="0:1:2:3")
    parser.add_argument("--seed", type=int, default=20260701)
    parser.add_argument(
        "--binary-weight-mode",
        choices=("none", "balanced", "sqrt-balanced"),
        default="sqrt-balanced",
    )
    parser.add_argument(
        "--family-weight-mode",
        choices=("none", "balanced", "sqrt-balanced"),
        default="sqrt-balanced",
    )
    parser.add_argument("--binary-max-weight", type=float, default=10.0)
    parser.add_argument("--family-max-weight", type=float, default=12.0)
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

    counts = frame["target_family"].value_counts()
    rare_limit = max(1000, int(max_rows * 0.01))
    selected_parts: list[pd.DataFrame] = []
    selected_indices: set[int] = set()

    for label, count in counts.items():
        group = frame[frame["target_family"] == label]
        if count <= rare_limit:
            chosen = group
        else:
            quota = max(
                rare_limit,
                int(round(max_rows * count / len(frame))),
            )
            quota = min(quota, count)
            chosen = group.sample(
                n=quota,
                random_state=seed + len(selected_parts),
                replace=False,
            )
        selected_parts.append(chosen)
        selected_indices.update(chosen.index.tolist())

    selected = pd.concat(selected_parts, ignore_index=False)
    if len(selected) > max_rows:
        rare_labels = set(counts[counts <= rare_limit].index)
        rare = selected[selected["target_family"].isin(rare_labels)]
        common = selected[~selected["target_family"].isin(rare_labels)]
        remaining = max_rows - len(rare)
        if remaining < 0:
            selected = rare.sample(
                n=max_rows,
                random_state=seed,
                replace=False,
            )
        else:
            selected = pd.concat(
                [
                    rare,
                    common.sample(
                        n=min(remaining, len(common)),
                        random_state=seed,
                        replace=False,
                    ),
                ],
                ignore_index=False,
            )

    if len(selected) < max_rows:
        remaining_pool = frame.loc[~frame.index.isin(selected.index)]
        extra_count = min(max_rows - len(selected), len(remaining_pool))
        if extra_count > 0:
            selected = pd.concat(
                [
                    selected,
                    remaining_pool.sample(
                        n=extra_count,
                        random_state=seed + 999,
                        replace=False,
                    ),
                ],
                ignore_index=False,
            )

    return selected.sample(
        frac=1.0,
        random_state=seed,
    ).reset_index(drop=True)


def load_split(
    data_dir: Path,
    split: str,
    columns: list[str],
    max_rows: int,
    seed: int,
) -> pd.DataFrame:
    split_dir = data_dir / split
    dataset = ds.dataset(str(split_dir), format="parquet")
    table = dataset.to_table(columns=columns)
    frame = table.to_pandas()
    frame = class_aware_sample(frame, max_rows, seed)

    print(
        f"[LOAD] {split}: rows={len(frame):,}, "
        f"memory={frame.memory_usage(deep=True).sum() / 1024**3:.2f} GiB",
        flush=True,
    )
    print(
        f"[LOAD] {split} family_counts="
        f"{frame['target_family'].value_counts().to_dict()}",
        flush=True,
    )
    return frame


def compute_weights(
    labels: np.ndarray,
    class_count: int,
    mode: str,
    maximum: float,
) -> list[float] | None:
    if mode == "none":
        return None

    counts = np.bincount(labels, minlength=class_count).astype(np.float64)
    if np.any(counts == 0):
        raise RuntimeError(f"Empty class in training data: {counts.tolist()}")

    largest = counts.max()
    if mode == "balanced":
        weights = largest / counts
    else:
        weights = np.sqrt(largest / counts)

    return np.clip(weights, 1.0, maximum).tolist()


def make_model(
    task: str,
    iterations: int,
    class_weights: list[float] | None,
    output_dir: Path,
    args: argparse.Namespace,
    use_gpu: bool,
) -> CatBoostClassifier:
    params: dict[str, Any] = {
        "iterations": iterations,
        "depth": args.depth,
        "learning_rate": args.learning_rate,
        "loss_function": "Logloss" if task == "binary" else "MultiClass",
        "eval_metric": "F1" if task == "binary" else "TotalF1:average=Macro",
        "random_seed": args.seed,
        "l2_leaf_reg": 6.0,
        "random_strength": 0.4,
        "border_count": 128,
        "boosting_type": "Plain",
        "bootstrap_type": "Bernoulli",
        "subsample": 0.85,
        "class_weights": class_weights,
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

    return CatBoostClassifier(**params)


def binary_metrics(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    threshold: float,
) -> dict[str, Any]:
    y_pred = (probabilities >= threshold).astype(np.int64)
    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1],
    ).ravel()

    precision, recall, f1_values, support = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=[0, 1],
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
            "roc_auc": roc_auc_score(y_true, probabilities),
            "pr_auc": average_precision_score(y_true, probabilities),
            "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
            "false_negative_rate": fn / (fn + tp) if fn + tp else 0.0,
            "per_class": {
                "Benign": {
                    "precision": precision[0],
                    "recall": recall[0],
                    "f1": f1_values[0],
                    "support": support[0],
                },
                "Attack": {
                    "precision": precision[1],
                    "recall": recall[1],
                    "f1": f1_values[1],
                    "support": support[1],
                },
            },
            "confusion_matrix": [[tn, fp], [fn, tp]],
        }
    )


def tune_binary_threshold(
    y_true: np.ndarray,
    probabilities: np.ndarray,
) -> tuple[float, pd.DataFrame]:
    rows = []
    for threshold in np.linspace(0.05, 0.95, 181):
        pred = (probabilities >= threshold).astype(np.int64)
        rows.append(
            {
                "threshold": float(threshold),
                "macro_f1": f1_score(y_true, pred, average="macro"),
                "balanced_accuracy": balanced_accuracy_score(y_true, pred),
                "attack_recall": precision_recall_fscore_support(
                    y_true,
                    pred,
                    labels=[1],
                    zero_division=0,
                )[1][0],
            }
        )

    frame = pd.DataFrame(rows)
    best = frame.sort_values(
        ["macro_f1", "balanced_accuracy", "attack_recall"],
        ascending=False,
    ).iloc[0]
    return float(best["threshold"]), frame


def hierarchical_predict(
    attack_probability: np.ndarray,
    conditional_family_probabilities: np.ndarray,
    threshold: float,
) -> np.ndarray:
    attack_family = np.argmax(
        conditional_family_probabilities,
        axis=1,
    ).astype(np.int64)
    return np.where(
        attack_probability >= threshold,
        attack_family + 1,
        0,
    ).astype(np.int64)


def tune_family_threshold(
    y_true_family: np.ndarray,
    attack_probability: np.ndarray,
    conditional_family_probabilities: np.ndarray,
) -> tuple[float, pd.DataFrame]:
    rows = []
    for threshold in np.linspace(0.02, 0.95, 187):
        pred = hierarchical_predict(
            attack_probability,
            conditional_family_probabilities,
            float(threshold),
        )
        rows.append(
            {
                "threshold": float(threshold),
                "macro_f1": f1_score(
                    y_true_family,
                    pred,
                    average="macro",
                ),
                "balanced_accuracy": balanced_accuracy_score(
                    y_true_family,
                    pred,
                ),
                "weighted_f1": f1_score(
                    y_true_family,
                    pred,
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


def multiclass_metrics(
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


def save_confusion(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_names: list[str],
    output_dir: Path,
    prefix: str,
) -> None:
    size = max(8.0, len(class_names) * 1.25)
    for normalize, suffix in ((None, "raw"), ("true", "normalized")):
        fig, ax = plt.subplots(figsize=(size, size))
        ConfusionMatrixDisplay.from_predictions(
            y_true,
            y_pred,
            labels=np.arange(len(class_names)),
            display_labels=class_names,
            normalize=normalize,
            xticks_rotation=45,
            values_format=".3f" if normalize else "d",
            ax=ax,
        )
        ax.set_title(f"{prefix} confusion matrix ({suffix})")
        fig.tight_layout()
        fig.savefig(
            output_dir / f"{prefix}_confusion_{suffix}.png",
            dpi=180,
        )
        plt.close(fig)


def main() -> None:
    args = parse_args()
    started = time.time()

    data_dir = Path(args.data_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest = json.loads(
        (data_dir / "manifest.json").read_text(encoding="utf-8")
    )
    feature_columns = list(manifest["feature_columns"])
    required_columns = feature_columns + [
        "target_binary",
        "target_family",
        "meta__row_hash",
    ]

    print("========== HIERARCHICAL CATBOOST ==========")
    print(f"data_dir={data_dir}")
    print(f"output_dir={output_dir}")
    print(f"feature_count={len(feature_columns)}")
    print(flush=True)

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

    gpu_count = int(get_gpu_device_count())
    use_gpu = not args.cpu and gpu_count > 0

    print(f"catboost_gpu_count={gpu_count}")
    print(f"training_device={'GPU' if use_gpu else 'CPU'}")
    print(f"devices={args.devices if use_gpu else 'CPU'}")
    print(flush=True)

    x_train = np.ascontiguousarray(
        frames["train"][feature_columns].to_numpy(
            dtype=np.float32,
            copy=True,
        )
    )
    x_val = np.ascontiguousarray(
        frames["val"][feature_columns].to_numpy(
            dtype=np.float32,
            copy=True,
        )
    )
    x_test = np.ascontiguousarray(
        frames["test"][feature_columns].to_numpy(
            dtype=np.float32,
            copy=True,
        )
    )

    y_train_binary = frames["train"]["target_binary"].to_numpy(
        dtype=np.int64
    )
    y_val_binary = frames["val"]["target_binary"].to_numpy(
        dtype=np.int64
    )
    y_test_binary = frames["test"]["target_binary"].to_numpy(
        dtype=np.int64
    )

    binary_weights = compute_weights(
        y_train_binary,
        2,
        args.binary_weight_mode,
        args.binary_max_weight,
    )
    print(f"binary_class_weights={binary_weights}", flush=True)

    binary_dir = output_dir / "binary"
    binary_dir.mkdir(parents=True, exist_ok=True)

    binary_model = make_model(
        "binary",
        args.binary_iterations,
        binary_weights,
        binary_dir,
        args,
        use_gpu,
    )

    binary_train_pool = Pool(
        x_train,
        y_train_binary,
        feature_names=feature_columns,
    )
    binary_val_pool = Pool(
        x_val,
        y_val_binary,
        feature_names=feature_columns,
    )

    binary_model.fit(
        binary_train_pool,
        eval_set=binary_val_pool,
    )
    binary_model.save_model(binary_dir / "catboost_binary.cbm")

    val_attack_probability = binary_model.predict_proba(x_val)[:, 1]
    test_attack_probability = binary_model.predict_proba(x_test)[:, 1]

    binary_threshold, binary_curve = tune_binary_threshold(
        y_val_binary,
        val_attack_probability,
    )
    binary_curve.to_csv(
        binary_dir / "threshold_search.csv",
        index=False,
    )

    binary_result = binary_metrics(
        y_test_binary,
        test_attack_probability,
        binary_threshold,
    )
    binary_result["best_iteration"] = int(binary_model.get_best_iteration())
    binary_result["class_weights"] = binary_weights
    (binary_dir / "metrics.json").write_text(
        json.dumps(binary_result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    binary_prediction = (
        test_attack_probability >= binary_threshold
    ).astype(np.int64)
    save_confusion(
        y_test_binary,
        binary_prediction,
        ["Benign", "Attack"],
        binary_dir,
        "binary",
    )

    print()
    print("========== BINARY RESULT ==========")
    for key in (
        "threshold",
        "accuracy",
        "balanced_accuracy",
        "macro_f1",
        "weighted_f1",
        "mcc",
        "roc_auc",
        "pr_auc",
        "false_positive_rate",
        "false_negative_rate",
    ):
        print(f"{key}={binary_result[key]:.6f}")
    print(flush=True)

    del binary_train_pool, binary_val_pool
    gc.collect()

    attack_train_mask = y_train_binary == 1
    attack_val_mask = y_val_binary == 1

    family_encoder = LabelEncoder()
    y_train_attack_family = family_encoder.fit_transform(
        frames["train"].loc[
            attack_train_mask,
            "target_family",
        ].astype(str)
    )
    attack_class_names = family_encoder.classes_.tolist()

    y_val_attack_family = family_encoder.transform(
        frames["val"].loc[
            attack_val_mask,
            "target_family",
        ].astype(str)
    )

    family_weights = compute_weights(
        y_train_attack_family,
        len(attack_class_names),
        args.family_weight_mode,
        args.family_max_weight,
    )

    print(f"attack_family_classes={attack_class_names}", flush=True)
    print(f"attack_family_weights={family_weights}", flush=True)

    family_dir = output_dir / "attack_family"
    family_dir.mkdir(parents=True, exist_ok=True)
    (family_dir / "label_encoder.json").write_text(
        json.dumps(
            {
                "class_names": attack_class_names,
                "mapping": {
                    name: index
                    for index, name in enumerate(attack_class_names)
                },
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    family_model = make_model(
        "family",
        args.family_iterations,
        family_weights,
        family_dir,
        args,
        use_gpu,
    )

    family_train_pool = Pool(
        x_train[attack_train_mask],
        y_train_attack_family,
        feature_names=feature_columns,
    )
    family_val_pool = Pool(
        x_val[attack_val_mask],
        y_val_attack_family,
        feature_names=feature_columns,
    )

    family_model.fit(
        family_train_pool,
        eval_set=family_val_pool,
    )
    family_model.save_model(
        family_dir / "catboost_attack_family.cbm"
    )

    val_conditional_family_probability = family_model.predict_proba(x_val)
    test_conditional_family_probability = family_model.predict_proba(x_test)

    full_class_names = ["Benign"] + attack_class_names
    full_encoder = {
        name: index
        for index, name in enumerate(full_class_names)
    }

    y_val_family = frames["val"]["target_family"].astype(str).map(
        full_encoder
    ).to_numpy(dtype=np.int64)
    y_test_family = frames["test"]["target_family"].astype(str).map(
        full_encoder
    ).to_numpy(dtype=np.int64)

    family_threshold, family_curve = tune_family_threshold(
        y_val_family,
        val_attack_probability,
        val_conditional_family_probability,
    )
    family_curve.to_csv(
        family_dir / "threshold_search.csv",
        index=False,
    )

    hierarchical_prediction = hierarchical_predict(
        test_attack_probability,
        test_conditional_family_probability,
        family_threshold,
    )

    family_result = multiclass_metrics(
        y_test_family,
        hierarchical_prediction,
        full_class_names,
        family_threshold,
    )
    family_result["best_iteration"] = int(
        family_model.get_best_iteration()
    )
    family_result["class_weights"] = family_weights
    family_result["attack_class_names"] = attack_class_names

    (family_dir / "metrics.json").write_text(
        json.dumps(family_result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    pd.DataFrame(
        family_result["classification_report"]
    ).transpose().to_csv(
        family_dir / "classification_report.csv",
        index=True,
    )
    save_confusion(
        y_test_family,
        hierarchical_prediction,
        full_class_names,
        family_dir,
        "hierarchical_family",
    )

    prediction_frame = pd.DataFrame(
        {
            "meta__row_hash": frames["test"]["meta__row_hash"].to_numpy(),
            "true_binary": y_test_binary,
            "predicted_binary": binary_prediction,
            "attack_probability": test_attack_probability,
            "true_family_id": y_test_family,
            "predicted_family_id": hierarchical_prediction,
            "true_family": [
                full_class_names[index]
                for index in y_test_family
            ],
            "predicted_family": [
                full_class_names[index]
                for index in hierarchical_prediction
            ],
        }
    )
    for index, name in enumerate(attack_class_names):
        safe = name.lower().replace(" ", "_").replace("-", "_")
        prediction_frame[f"conditional_prob__{safe}"] = (
            test_conditional_family_probability[:, index]
        )
    prediction_frame.to_parquet(
        output_dir / "test_predictions.parquet",
        index=False,
        compression="zstd",
    )

    print()
    print("========== HIERARCHICAL FAMILY RESULT ==========")
    for key in (
        "threshold",
        "accuracy",
        "balanced_accuracy",
        "macro_f1",
        "weighted_f1",
        "mcc",
    ):
        print(f"{key}={family_result[key]:.6f}")
    for name, values in family_result["per_class"].items():
        print(
            f"{name}: "
            f"P={values['precision']:.6f} "
            f"R={values['recall']:.6f} "
            f"F1={values['f1']:.6f} "
            f"N={values['support']}"
        )
    print(flush=True)

    summary = {
        "data_dir": str(data_dir),
        "output_dir": str(output_dir),
        "feature_count": len(feature_columns),
        "gpu_count": gpu_count,
        "training_device": "GPU" if use_gpu else "CPU",
        "arguments": vars(args),
        "binary": binary_result,
        "hierarchical_family": family_result,
        "duration_seconds": time.time() - started,
    }
    (output_dir / "summary.json").write_text(
        json.dumps(json_safe(summary), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print()
    print("========== COMPLETE ==========")
    print(f"summary={output_dir / 'summary.json'}")
    print(f"duration_seconds={time.time() - started:.1f}")


if __name__ == "__main__":
    main()
