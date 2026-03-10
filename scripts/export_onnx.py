#!/usr/bin/env python3
"""Export a trained CNN-BiLSTM model to ONNX format for C++ inference.

The exported model accepts a flat feature vector (batch, n_features) and
outputs class probabilities (batch, n_classes). This matches the OnnxAnalyzer
input format in the C++ codebase.

Usage:
    python scripts/export_onnx.py --checkpoint models/best_model.pt --output src/model/model.onnx
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

import numpy as np
import torch
import torch.nn as nn

# Import the model class from train_model
sys.path.insert(0, str(Path(__file__).parent))
from train_model import CnnBiLstm


class CnnBiLstmExport(nn.Module):
    """Wrapper that adds softmax to the model output for ONNX export.

    The training model outputs raw logits (for CrossEntropyLoss), but the C++
    inference code expects probabilities (softmax output). This wrapper applies
    softmax at export time.
    """

    def __init__(self, model: CnnBiLstm):
        super().__init__()
        self.model = model
        self.softmax = nn.Softmax(dim=1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        logits = self.model(x)
        return self.softmax(logits)


def export_to_onnx(
    checkpoint_path: str,
    output_path: str,
    opset: int = 17,
) -> None:
    """Export a trained model checkpoint to ONNX format."""
    print(f"Loading checkpoint: {checkpoint_path}")
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=True)

    n_features = checkpoint["n_features"]
    n_classes = checkpoint["n_classes"]
    lstm_hidden = checkpoint.get("lstm_hidden", 128)

    print(
        f"Model config: {n_features} features, {n_classes} classes, LSTM hidden={lstm_hidden}"
    )

    # Reconstruct model
    model = CnnBiLstm(n_features, n_classes, lstm_hidden=lstm_hidden)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()

    # Flatten LSTM parameters for contiguous memory layout (required by ONNX tracer)
    if hasattr(model, "lstm"):
        model.lstm.flatten_parameters()

    # Wrap with softmax for export
    export_model = CnnBiLstmExport(model)
    export_model.eval()

    # Create dummy input
    dummy_input = torch.randn(1, n_features)

    # Export to ONNX
    print(f"Exporting to ONNX (opset {opset})...")
    with torch.no_grad():
        torch.onnx.export(
            export_model,
            (dummy_input,),
            output_path,
            opset_version=opset,
            input_names=["input"],
            output_names=["output"],
            dynamic_axes={"input": {0: "batch_size"}, "output": {0: "batch_size"}},
            do_constant_folding=True,
        )
    print(f"ONNX model saved: {output_path}")

    # Verify with ONNX Runtime
    verify_onnx(output_path, export_model, n_features, n_classes)


def verify_onnx(
    model_path: str,
    pytorch_model: nn.Module,
    n_features: int,
    n_classes: int,
) -> None:
    """Verify the exported ONNX model with ONNX Runtime."""
    try:
        import onnx
        import onnxruntime as ort
    except ImportError:
        print("WARNING: onnx/onnxruntime not installed, skipping verification.")
        return

    # Structural validation
    onnx_model = onnx.load(model_path)
    onnx.checker.check_model(onnx_model)
    print("ONNX structural validation passed.")

    # Runtime verification
    session = ort.InferenceSession(model_path)
    input_info = session.get_inputs()[0]
    output_info = session.get_outputs()[0]

    print(
        f"  Input:  name='{input_info.name}', shape={input_info.shape}, type={input_info.type}"
    )
    print(
        f"  Output: name='{output_info.name}', shape={output_info.shape}, type={output_info.type}"
    )

    # Run inference with dummy data
    dummy = np.random.randn(1, n_features).astype(np.float32)
    result = session.run([output_info.name], {input_info.name: dummy})
    output = result[0]  # type: ignore[index]

    print(f"  Output shape: {output.shape}")
    print(f"  Output sum (should be ~1.0): {output.sum():.6f}")
    print(f"  Predicted class: {output.argmax()}")

    assert output.shape == (1, n_classes), (
        f"Expected (1, {n_classes}), got {output.shape}"
    )
    assert abs(float(output.sum()) - 1.0) < 1e-4, (
        f"Softmax sum should be ~1.0, got {output.sum()}"
    )
    print("ONNX Runtime verification passed.")

    # Numerical equivalence: PyTorch vs ONNX Runtime
    test_inputs = np.random.randn(32, n_features).astype(np.float32)
    with torch.no_grad():
        pt_out = pytorch_model(torch.from_numpy(test_inputs)).numpy()
    ort_out = session.run([output_info.name], {input_info.name: test_inputs})[0]

    max_diff = float(np.abs(pt_out - ort_out).max())
    mean_diff = float(np.abs(pt_out - ort_out).mean())
    print(f"  Max diff:  {max_diff:.8f}")
    print(f"  Mean diff: {mean_diff:.8f}")
    assert max_diff < 1e-4, f"ONNX output diverges from PyTorch! max_diff={max_diff}"
    print("Numerical equivalence: PASSED")


def copy_metadata(data_dir: Path, output_dir: Path) -> None:
    """Copy model_metadata.json alongside the ONNX model."""
    src = data_dir / "model_metadata.json"
    if src.exists():
        dst = output_dir / "model_metadata.json"
        shutil.copy2(src, dst)
        print(f"Metadata copied to: {dst}")
    else:
        print(f"WARNING: {src} not found. Model metadata not copied.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Export CNN-BiLSTM to ONNX")
    parser.add_argument(
        "--checkpoint",
        "-c",
        type=str,
        default=str(SCRIPT_DIR.parent / "models" / "best_model.pt"),
        help="Path to the training checkpoint (.pt file)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=str(SCRIPT_DIR.parent / "models" / "model.onnx"),
        help="Output ONNX model path",
    )
    parser.add_argument(
        "--opset",
        type=int,
        default=17,
        help="ONNX opset version (default: 17)",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=SCRIPT_DIR / "data" / "processed",
        help="Directory with model_metadata.json (for copying alongside model)",
    )
    args = parser.parse_args()

    if not Path(args.checkpoint).exists():
        print(f"Error: Checkpoint not found: {args.checkpoint}", file=sys.stderr)
        sys.exit(1)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    export_to_onnx(args.checkpoint, args.output, args.opset)
    copy_metadata(args.data_dir, output_path.parent)

    print(f"\nModel ready for deployment at: {args.output}")
    print("Copy to src/model/ and rebuild the C++ project.")


if __name__ == "__main__":
    main()
