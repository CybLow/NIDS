#!/usr/bin/env python3
"""Train a CNN-BiLSTM model on the LSNM2024 dataset for network intrusion detection.

Architecture:
    Input (batch, n_features) -> Reshape (batch, 1, n_features)
    -> Conv1D(64, k=3) -> BN -> ReLU -> Dropout(0.2)
    -> Conv1D(128, k=3) -> BN -> ReLU -> Dropout(0.2)
    -> MaxPool1D(2)
    -> BiLSTM(128) -> Dropout(0.3)
    -> Dense(256) -> BN -> ReLU -> Dropout(0.4)
    -> Dense(128) -> BN -> ReLU -> Dropout(0.3)
    -> Dense(n_classes)

The number of input features (77 for CICFlowMeter flow features) and output
classes (16 for LSNM2024) are determined dynamically from the preprocessed data.

Usage:
    python scripts/train_model.py --data-dir scripts/data/processed/ --output-dir models/
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset, WeightedRandomSampler
from tqdm import tqdm

SCRIPT_DIR = Path(__file__).resolve().parent

# Adaptive num_workers: use up to 4, but cap at available CPUs
_NUM_WORKERS = min(4, os.cpu_count() or 1)


class CnnBiLstm(nn.Module):
    """CNN-BiLSTM hybrid model for network intrusion detection.

    The CNN block extracts local feature patterns (port combinations, flag patterns).
    The BiLSTM captures bidirectional dependencies across the feature sequence.
    Dense layers perform the final classification.
    """

    def __init__(self, n_features: int, n_classes: int, lstm_hidden: int = 128):
        super().__init__()

        # CNN block
        self.cnn = nn.Sequential(
            # Conv1D expects (batch, channels, length)
            nn.Conv1d(in_channels=1, out_channels=64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Conv1d(in_channels=64, out_channels=128, kernel_size=3, padding=1),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.MaxPool1d(kernel_size=2),
        )

        # BiLSTM block
        # After MaxPool1d(2): (batch, 128, n_features // 2)
        # LSTM expects (batch, seq_len, input_size) with batch_first=True
        self.lstm = nn.LSTM(
            input_size=128,
            hidden_size=lstm_hidden,
            num_layers=1,
            batch_first=True,
            bidirectional=True,
        )
        self.lstm_dropout = nn.Dropout(0.3)

        # Dense block
        # BiLSTM output: 2 * lstm_hidden (bidirectional)
        self.classifier = nn.Sequential(
            nn.Linear(2 * lstm_hidden, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(0.4),
            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, n_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass.

        Args:
            x: Input tensor of shape (batch, n_features).

        Returns:
            Logits tensor of shape (batch, n_classes).
        """
        # Reshape for Conv1D: (batch, n_features) -> (batch, 1, n_features)
        x = x.unsqueeze(1)

        # CNN: (batch, 1, n_features) -> (batch, 128, n_features // 2)
        x = self.cnn(x)

        # Transpose for LSTM: (batch, 128, seq_len) -> (batch, seq_len, 128)
        x = x.permute(0, 2, 1)

        # BiLSTM: (batch, seq_len, 128) -> (batch, seq_len, 2*hidden)
        x, _ = self.lstm(x)

        # Take only the last time step output
        x = x[:, -1, :]
        x = self.lstm_dropout(x)

        # Dense classifier
        x = self.classifier(x)
        return x


def create_dataloaders(
    data_dir: Path,
    batch_size: int,
    use_weighted_sampling: bool = True,
) -> tuple[DataLoader, DataLoader, DataLoader, int, int]:
    """Load preprocessed data and create PyTorch DataLoaders.

    Returns:
        train_loader, val_loader, test_loader, n_features, n_classes
    """
    X_train = np.load(data_dir / "X_train.npy")
    X_val = np.load(data_dir / "X_val.npy")
    X_test = np.load(data_dir / "X_test.npy")
    y_train = np.load(data_dir / "y_train.npy")
    y_val = np.load(data_dir / "y_val.npy")
    y_test = np.load(data_dir / "y_test.npy")

    n_features = X_train.shape[1]
    n_classes = int(y_train.max()) + 1

    print(
        f"Data loaded: {X_train.shape[0]} train, {X_val.shape[0]} val, {X_test.shape[0]} test"
    )
    print(f"Features: {n_features}, Classes: {n_classes}")

    # Convert to tensors
    train_dataset = TensorDataset(
        torch.tensor(X_train, dtype=torch.float32),
        torch.tensor(y_train, dtype=torch.long),
    )
    val_dataset = TensorDataset(
        torch.tensor(X_val, dtype=torch.float32),
        torch.tensor(y_val, dtype=torch.long),
    )
    test_dataset = TensorDataset(
        torch.tensor(X_test, dtype=torch.float32),
        torch.tensor(y_test, dtype=torch.long),
    )

    # Weighted random sampling for class imbalance
    if use_weighted_sampling:
        class_counts = np.bincount(y_train, minlength=n_classes)
        # Inverse-frequency weights, but cap the maximum weight to prevent
        # extreme over-sampling of classes with very few samples (e.g., 3).
        # Without capping, a class with 3 samples gets weight ~200K, which
        # causes the model to see those 3 samples thousands of times per epoch.
        class_weights = np.zeros(n_classes, dtype=np.float64)
        for i in range(n_classes):
            if class_counts[i] > 0:
                class_weights[i] = 1.0 / class_counts[i]
        # Cap: no class weight exceeds 100x the median non-zero weight
        nonzero_weights = class_weights[class_weights > 0]
        if len(nonzero_weights) > 0:
            median_w = np.median(nonzero_weights)
            max_w = 100.0 * median_w
            class_weights = np.minimum(class_weights, max_w)

        sample_weights = class_weights[y_train]
        sampler = WeightedRandomSampler(
            weights=torch.tensor(sample_weights, dtype=torch.double),
            num_samples=len(y_train),
            replacement=True,
        )
        train_loader = DataLoader(
            train_dataset,
            batch_size=batch_size,
            sampler=sampler,
            num_workers=_NUM_WORKERS,
            pin_memory=True,
        )
    else:
        train_loader = DataLoader(
            train_dataset,
            batch_size=batch_size,
            shuffle=True,
            num_workers=_NUM_WORKERS,
            pin_memory=True,
        )

    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size * 2,
        shuffle=False,
        num_workers=_NUM_WORKERS,
        pin_memory=True,
    )
    test_loader = DataLoader(
        test_dataset,
        batch_size=batch_size * 2,
        shuffle=False,
        num_workers=_NUM_WORKERS,
        pin_memory=True,
    )

    return train_loader, val_loader, test_loader, n_features, n_classes


def train_one_epoch(
    model: nn.Module,
    loader: DataLoader,
    criterion: nn.Module,
    optimizer: torch.optim.Optimizer,
    device: torch.device,
) -> tuple[float, float]:
    """Train for one epoch. Returns (avg_loss, accuracy)."""
    model.train()
    total_loss = 0.0
    correct = 0
    total = 0

    for X_batch, y_batch in tqdm(loader, desc="  Train", leave=False):
        X_batch = X_batch.to(device, non_blocking=True)
        y_batch = y_batch.to(device, non_blocking=True)

        optimizer.zero_grad()
        logits = model(X_batch)
        loss = criterion(logits, y_batch)
        loss.backward()

        # Gradient clipping to prevent exploding gradients in LSTM
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)

        optimizer.step()

        total_loss += loss.item() * X_batch.size(0)
        preds = logits.argmax(dim=1)
        correct += (preds == y_batch).sum().item()
        total += X_batch.size(0)

    return total_loss / total, correct / total


@torch.no_grad()
def evaluate(
    model: nn.Module,
    loader: DataLoader,
    criterion: nn.Module,
    device: torch.device,
) -> tuple[float, float]:
    """Evaluate the model. Returns (avg_loss, accuracy)."""
    model.eval()
    total_loss = 0.0
    correct = 0
    total = 0

    for X_batch, y_batch in tqdm(loader, desc="  Eval ", leave=False):
        X_batch = X_batch.to(device, non_blocking=True)
        y_batch = y_batch.to(device, non_blocking=True)

        logits = model(X_batch)
        loss = criterion(logits, y_batch)

        total_loss += loss.item() * X_batch.size(0)
        preds = logits.argmax(dim=1)
        correct += (preds == y_batch).sum().item()
        total += X_batch.size(0)

    return total_loss / total, correct / total


def main() -> None:
    parser = argparse.ArgumentParser(description="Train CNN-BiLSTM on LSNM2024")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=SCRIPT_DIR / "data" / "processed",
        help="Directory with preprocessed .npy files",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=SCRIPT_DIR.parent / "models",
        help="Directory to save trained model",
    )
    parser.add_argument(
        "--epochs", type=int, default=50, help="Maximum training epochs (default: 50)"
    )
    parser.add_argument(
        "--batch-size", type=int, default=512, help="Batch size (default: 512)"
    )
    parser.add_argument(
        "--lr", type=float, default=1e-3, help="Initial learning rate (default: 1e-3)"
    )
    parser.add_argument(
        "--patience", type=int, default=7, help="Early stopping patience (default: 7)"
    )
    parser.add_argument(
        "--lstm-hidden", type=int, default=128, help="LSTM hidden size (default: 128)"
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument(
        "--no-cuda", action="store_true", help="Disable CUDA even if available"
    )
    args = parser.parse_args()

    # Reproducibility
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(args.seed)

    # Device
    device = torch.device("cpu")
    if not args.no_cuda and torch.cuda.is_available():
        device = torch.device("cuda")
    print(f"Device: {device}")

    # Data
    train_loader, val_loader, test_loader, n_features, n_classes = create_dataloaders(
        args.data_dir, args.batch_size
    )

    # Model
    model = CnnBiLstm(n_features, n_classes, lstm_hidden=args.lstm_hidden).to(device)
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Model: {total_params:,} total params, {trainable_params:,} trainable\n")
    print(model)
    print()

    # Loss function
    # NOTE: We use WeightedRandomSampler for class rebalancing at the sampling
    # level, so we do NOT also use class-weighted CrossEntropyLoss (that would
    # cause double-compensation, biasing the model toward rare classes).
    # Label smoothing (0.1) helps regularize and prevents over-confident
    # predictions on the resampled batches.
    criterion = nn.CrossEntropyLoss(label_smoothing=0.1)
    print(
        "Using CrossEntropyLoss with label_smoothing=0.1 (class rebalancing via sampler)"
    )

    # Optimizer and scheduler
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer,
        mode="min",
        factor=0.5,
        patience=3,
    )

    # Training loop with early stopping
    args.output_dir.mkdir(parents=True, exist_ok=True)
    best_val_loss = float("inf")
    best_epoch = 0
    patience_counter = 0
    best_model_path = args.output_dir / "best_model.pt"

    print(f"\nTraining for up to {args.epochs} epochs (patience={args.patience})...\n")
    start_time = time.time()

    for epoch in range(1, args.epochs + 1):
        epoch_start = time.time()

        train_loss, train_acc = train_one_epoch(
            model, train_loader, criterion, optimizer, device
        )
        val_loss, val_acc = evaluate(model, val_loader, criterion, device)
        scheduler.step(val_loss)

        elapsed = time.time() - epoch_start
        current_lr = optimizer.param_groups[0]["lr"]

        print(
            f"Epoch {epoch:3d}/{args.epochs} "
            f"| Train Loss: {train_loss:.4f} Acc: {train_acc:.4f} "
            f"| Val Loss: {val_loss:.4f} Acc: {val_acc:.4f} "
            f"| LR: {current_lr:.2e} "
            f"| {elapsed:.1f}s"
        )

        # Early stopping check
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_epoch = epoch
            patience_counter = 0
            torch.save(
                {
                    "epoch": epoch,
                    "model_state_dict": model.state_dict(),
                    "optimizer_state_dict": optimizer.state_dict(),
                    "val_loss": val_loss,
                    "val_acc": val_acc,
                    "n_features": n_features,
                    "n_classes": n_classes,
                    "lstm_hidden": args.lstm_hidden,
                },
                best_model_path,
            )
            print(f"  -> Best model saved (val_loss={val_loss:.4f})")
        else:
            patience_counter += 1
            if patience_counter >= args.patience:
                print(f"\nEarly stopping at epoch {epoch} (patience={args.patience})")
                break

    total_time = time.time() - start_time
    print(f"\nTraining complete in {total_time:.1f}s")
    print(f"Best epoch: {best_epoch}, Best val loss: {best_val_loss:.4f}")

    # Final evaluation on test set
    print("\nLoading best model for test evaluation...")
    checkpoint = torch.load(best_model_path, map_location=device, weights_only=True)
    model.load_state_dict(checkpoint["model_state_dict"])

    test_loss, test_acc = evaluate(model, test_loader, criterion, device)
    print(f"Test Loss: {test_loss:.4f}, Test Accuracy: {test_acc:.4f}")

    # Save training summary
    summary = {
        "best_epoch": best_epoch,
        "best_val_loss": round(best_val_loss, 6),
        "test_loss": round(test_loss, 6),
        "test_accuracy": round(test_acc, 6),
        "total_params": total_params,
        "trainable_params": trainable_params,
        "n_features": n_features,
        "n_classes": n_classes,
        "lstm_hidden": args.lstm_hidden,
        "batch_size": args.batch_size,
        "learning_rate": args.lr,
        "training_time_seconds": round(total_time, 1),
    }
    summary_path = args.output_dir / "training_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nTraining summary saved to: {summary_path}")
    print(f"Best model saved to: {best_model_path}")
    print(f"\nNext step: python scripts/export_onnx.py --checkpoint {best_model_path}")


if __name__ == "__main__":
    main()
