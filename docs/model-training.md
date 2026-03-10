# Model Training Guide

This document describes how to train, export, and deploy the CNN-BiLSTM model used by
NIDS for network traffic classification.

## Prerequisites

- Python 3.10 or later
- CUDA-capable GPU (recommended, not required)
- 8 GB+ RAM (16 GB recommended for full dataset)

Install Python dependencies:

```bash
pip install -r scripts/requirements.txt
```

## Step 1: Download the LSNM2024 Dataset

```bash
python scripts/download_dataset.py
```

This downloads the dataset from Mendeley Data (~2 GB) and verifies the SHA-256 checksum.
Files are saved to `data/raw/`.

## Step 2: Preprocess

```bash
python scripts/preprocess.py
```

Preprocessing steps:
1. Loads all CSV files from the dataset
2. Removes NaN, infinity, and duplicate rows
3. Encodes attack labels to integer indices (matching `AttackType.h` enum order)
4. Applies `StandardScaler` normalization per feature
5. Splits into train/validation/test sets (70/15/15)
6. Saves `.npy` arrays and `model_metadata.json`

Output files:
- `data/processed/X_train.npy`, `y_train.npy`
- `data/processed/X_val.npy`, `y_val.npy`
- `data/processed/X_test.npy`, `y_test.npy`
- `data/processed/model_metadata.json` (feature names, scaler params, label mapping)

## Step 3: Train the Model

```bash
python scripts/train_model.py
```

### Architecture: CNN-BiLSTM

```
Input (batch, n_features)
    |
    v
Unsqueeze to (batch, 1, n_features)     # done inside model
    |
    v
Conv1D(64, kernel=3, padding=1) -> BatchNorm -> ReLU -> Dropout(0.2)
Conv1D(128, kernel=3, padding=1) -> BatchNorm -> ReLU -> Dropout(0.2)
MaxPool1D(pool_size=2)
    |
    v
Permute for LSTM input
BiLSTM(hidden=128) -> Dropout(0.3)
    |
    v
Dense(256) -> BatchNorm -> ReLU -> Dropout(0.4)
Dense(128) -> BatchNorm -> ReLU -> Dropout(0.3)
Dense(16, softmax)
    |
    v
Output: probability distribution over 16 classes
```

### Training Configuration
- **Optimizer**: AdamW (lr=1e-3, weight_decay=1e-4)
- **Scheduler**: ReduceLROnPlateau (factor=0.5, patience=3)
- **Early stopping**: patience=10 on validation loss
- **Class balancing**: WeightedRandomSampler based on inverse class frequency
- **Batch size**: 512
- **Max epochs**: 100

The best model checkpoint is saved to `models/best_model.pt`.

## Step 4: Export to ONNX

```bash
python scripts/export_onnx.py
```

This wraps the trained model with a softmax output layer and exports to ONNX format:
- Opset version: 15
- Dynamic batch axes enabled
- Input shape: `(batch, n_features)` — the model reshapes internally
- Output: softmax probabilities `(batch, 16)`

The exported model is saved to `src/model/model.onnx`.

Verification runs automatically: a dummy input is fed through both the PyTorch model
and the ONNX model to ensure outputs match within tolerance.

## Step 5: Evaluate

```bash
python scripts/evaluate.py
```

Generates:
- Classification report (precision, recall, F1 per class)
- Confusion matrix heatmap (`evaluation/confusion_matrix.png`)
- ROC curves per class (`evaluation/roc_curves.png`)
- Metrics JSON (`evaluation/metrics.json`)

### Expected Performance

| Metric     | Target  |
|------------|---------|
| Accuracy   | > 95%   |
| F1 (macro) | > 93%   |
| F1 (per-class min) | > 85% |

## Step 6: Deploy

Copy the exported model to the NIDS model directory:

```bash
cp src/model/model.onnx <install-prefix>/share/nids/model/
cp data/processed/model_metadata.json <install-prefix>/share/nids/model/
```

Or simply rebuild NIDS — the CMake install target includes the model file:

```bash
cmake --install build --prefix /usr/local
```

## Retraining Tips

- To train on a custom dataset, ensure CSV columns match the 77 flow features produced
  by `NativeFlowExtractor`. Update the label mapping in `preprocess.py` if attack
  classes differ.
- GPU training: ensure CUDA and cuDNN are installed. PyTorch auto-detects GPU.
- For larger datasets, increase batch size and reduce learning rate.
- Monitor validation loss for overfitting; the early stopping callback handles this
  automatically.
