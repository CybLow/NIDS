#!/usr/bin/env python3
"""Evaluate a trained CNN-BiLSTM model: confusion matrix, per-class metrics, ROC curves.

Usage:
    python scripts/ml/evaluate.py --checkpoint models/best_model.pt --data-dir data/processed/
"""

import argparse
import json
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
_NUM_WORKERS = min(4, os.cpu_count() or 1)

import matplotlib

matplotlib.use("Agg")  # Non-interactive backend for headless environments
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import torch
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    roc_curve,
)
from torch.utils.data import DataLoader, TensorDataset

sys.path.insert(0, str(Path(__file__).parent))
from train_model import CnnBiLstm


def load_model(checkpoint_path: str, device: torch.device) -> tuple:
    """Load the trained model from a checkpoint."""
    checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=True)
    n_features = checkpoint["n_features"]
    n_classes = checkpoint["n_classes"]
    lstm_hidden = checkpoint.get("lstm_hidden", 128)

    model = CnnBiLstm(n_features, n_classes, lstm_hidden=lstm_hidden)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.to(device)
    model.eval()

    return model, n_features, n_classes


@torch.no_grad()
def get_predictions(
    model: torch.nn.Module,
    loader: DataLoader,
    device: torch.device,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Run inference and collect predictions, true labels, and probabilities."""
    all_preds = []
    all_labels = []
    all_probs = []

    softmax = torch.nn.Softmax(dim=1)

    for x_batch, y_batch in loader:
        x_batch = x_batch.to(device, non_blocking=True)
        logits = model(x_batch)
        probs = softmax(logits)

        all_preds.append(logits.argmax(dim=1).cpu().numpy())
        all_labels.append(y_batch.numpy())
        all_probs.append(probs.cpu().numpy())

    return (
        np.concatenate(all_preds),
        np.concatenate(all_labels),
        np.concatenate(all_probs),
    )


def plot_confusion_matrix(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_names: list[str],
    output_path: Path,
) -> None:
    """Generate and save a confusion matrix heatmap."""
    labels = list(range(len(class_names)))
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    row_sums = cm.sum(axis=1, keepdims=True)
    # Avoid division by zero for classes absent from the test set
    cm_normalized = np.divide(
        cm.astype(float),
        row_sums,
        out=np.zeros_like(cm, dtype=float),
        where=row_sums != 0,
    )

    _, axes = plt.subplots(1, 2, figsize=(24, 10))

    # Raw counts
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=class_names,
        yticklabels=class_names,
        ax=axes[0],
    )
    axes[0].set_title("Confusion Matrix (Counts)")
    axes[0].set_xlabel("Predicted")
    axes[0].set_ylabel("True")
    axes[0].tick_params(axis="x", rotation=45)
    axes[0].tick_params(axis="y", rotation=0)

    # Normalized
    sns.heatmap(
        cm_normalized,
        annot=True,
        fmt=".2f",
        cmap="Blues",
        xticklabels=class_names,
        yticklabels=class_names,
        ax=axes[1],
    )
    axes[1].set_title("Confusion Matrix (Normalized)")
    axes[1].set_xlabel("Predicted")
    axes[1].set_ylabel("True")
    axes[1].tick_params(axis="x", rotation=45)
    axes[1].tick_params(axis="y", rotation=0)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Confusion matrix saved: {output_path}")


def plot_roc_curves(
    y_true: np.ndarray,
    y_probs: np.ndarray,
    class_names: list[str],
    output_path: Path,
) -> None:
    """Generate and save per-class ROC curves."""
    n_classes = len(class_names)

    _, ax = plt.subplots(figsize=(12, 10))

    # One-hot encode true labels
    y_true_onehot = np.eye(n_classes)[y_true]

    for i in range(n_classes):
        if y_true_onehot[:, i].sum() == 0:
            continue
        fpr, tpr, _ = roc_curve(y_true_onehot[:, i], y_probs[:, i])
        auc = roc_auc_score(y_true_onehot[:, i], y_probs[:, i])
        ax.plot(fpr, tpr, label=f"{class_names[i]} (AUC={auc:.3f})")

    ax.plot([0, 1], [0, 1], "k--", alpha=0.3, label="Random")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curves (One-vs-Rest)")
    ax.legend(bbox_to_anchor=(1.05, 1), loc="upper left", fontsize=8)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"ROC curves saved: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate CNN-BiLSTM model")
    parser.add_argument(
        "--checkpoint",
        "-c",
        type=str,
        default=str(SCRIPT_DIR.parent / "models" / "best_model.pt"),
        help="Path to model checkpoint",
    )
    parser.add_argument(
        "--data-dir",
        "-d",
        type=Path,
        default=SCRIPT_DIR / "data" / "processed",
        help="Directory with preprocessed test data",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=SCRIPT_DIR.parent / "models" / "evaluation",
        help="Directory to save evaluation results",
    )
    parser.add_argument("--batch-size", type=int, default=1024)
    parser.add_argument("--no-cuda", action="store_true")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    device = torch.device("cpu")
    if not args.no_cuda and torch.cuda.is_available():
        device = torch.device("cuda")
    print(f"Device: {device}")

    # Load model
    model, n_features, n_classes = load_model(args.checkpoint, device)
    print(f"Model loaded: {n_features} features, {n_classes} classes")

    # Load class names from metadata
    metadata_path = args.data_dir / "model_metadata.json"
    if metadata_path.exists():
        with open(metadata_path) as f:
            metadata = json.load(f)
        class_names = [
            metadata.get("index_to_label", {}).get(str(i), f"Class {i}")
            for i in range(n_classes)
        ]
    else:
        class_names = [f"Class {i}" for i in range(n_classes)]

    # Load test data
    X_test = np.load(args.data_dir / "X_test.npy")
    y_test = np.load(args.data_dir / "y_test.npy")
    print(f"Test set: {len(X_test)} samples")

    test_dataset = TensorDataset(
        torch.tensor(X_test, dtype=torch.float32),
        torch.tensor(y_test, dtype=torch.long),
    )
    test_loader = DataLoader(
        test_dataset,
        batch_size=args.batch_size,
        shuffle=False,
        num_workers=_NUM_WORKERS,
        pin_memory=device.type == "cuda",
    )

    # Get predictions
    y_pred, y_true, y_probs = get_predictions(model, test_loader, device)

    # Classification report (specify labels so all classes appear even if absent
    # from the test split)
    all_labels = list(range(n_classes))
    report = classification_report(
        y_true,
        y_pred,
        labels=all_labels,
        target_names=class_names,
        digits=4,
        zero_division=0,
    )
    print("\nClassification Report:")
    print(report)

    report_path = args.output_dir / "classification_report.txt"
    with open(report_path, "w") as f:
        f.write(report)
    print(f"Classification report saved: {report_path}")

    # Per-class metrics as JSON
    report_dict = classification_report(
        y_true,
        y_pred,
        labels=all_labels,
        target_names=class_names,
        digits=6,
        output_dict=True,
        zero_division=0,
    )
    metrics_path = args.output_dir / "metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(report_dict, f, indent=2)
    print(f"Detailed metrics saved: {metrics_path}")

    # Confusion matrix
    plot_confusion_matrix(
        y_true,
        y_pred,
        class_names,
        args.output_dir / "confusion_matrix.png",
    )

    # ROC curves
    try:
        plot_roc_curves(
            y_true,
            y_probs,
            class_names,
            args.output_dir / "roc_curves.png",
        )
    except ValueError as e:
        print(f"WARNING: Could not generate ROC curves: {e}")

    # Overall accuracy
    accuracy = (y_pred == y_true).mean()
    print(f"\nOverall Test Accuracy: {accuracy:.4f} ({accuracy * 100:.2f}%)")

    # Macro-averaged AUC (only over classes that appear in the test set)
    try:
        present = sorted(set(y_true))
        if len(present) >= 2:
            y_true_onehot = np.eye(n_classes)[y_true][:, present]
            y_probs_present = y_probs[:, present]
            macro_auc = roc_auc_score(
                y_true_onehot, y_probs_present, average="macro", multi_class="ovr"
            )
            print(f"Macro AUC-ROC: {macro_auc:.4f}")
            if len(present) < n_classes:
                absent = [class_names[i] for i in range(n_classes) if i not in present]
                print(
                    f"  (excluded {len(absent)} classes with no test samples: "
                    f"{', '.join(absent)})"
                )
        else:
            print("Macro AUC-ROC: N/A (fewer than 2 classes in test set)")
    except ValueError as e:
        print(f"WARNING: Could not compute Macro AUC-ROC: {e}")

    print(f"\nAll evaluation results saved to: {args.output_dir}/")


if __name__ == "__main__":
    main()
