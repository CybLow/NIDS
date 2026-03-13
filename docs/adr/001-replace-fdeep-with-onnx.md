# ADR-001: Replace frugally-deep with ONNX Runtime

## Status

Accepted (implemented in Phase 2)

## Context

The original NIDS used [frugally-deep](https://github.com/Dobiasd/frugally-deep) for
neural network inference. frugally-deep is a header-only C++ library that loads Keras
models exported as JSON via a custom converter.

Problems encountered:
1. **Model format lock-in**: Only supports Keras `.h5`/`.keras` models via a fragile
   JSON intermediate format. No support for PyTorch, TensorFlow SavedModel, or other
   frameworks.
2. **No GPU acceleration**: CPU-only inference with no path to GPU/NPU acceleration.
3. **Complex dependency chain**: Requires FunctionalPlus + Eigen3 + frugally-deep, each
   needing manual installation or `git clone` in Docker builds.
4. **Unpinned versions**: Dockerfile cloned frugally-deep at HEAD, making builds
   non-reproducible.
5. **Performance**: Inference throughput insufficient for real-time per-flow detection
   at high packet rates.

## Decision

Replace frugally-deep with [ONNX Runtime](https://onnxruntime.ai/) as the sole ML
inference backend.

- ONNX Runtime is available in vcpkg (`onnxruntime`) for reproducible builds.
- Models are exported to `.onnx` format, which is supported by PyTorch, TensorFlow,
  scikit-learn, and most ML frameworks.
- GPU acceleration available via CUDA, DirectML, and TensorRT execution providers.
- Dynamic input/output tensor name querying eliminates hardcoded assumptions.

## Consequences

### Positive
- Single vcpkg dependency replaces three manual `git clone` builds.
- PyTorch models can be exported directly via `torch.onnx.export()`.
- Future GPU acceleration requires only changing the execution provider, no code changes.
- 5-10x inference speedup on CPU alone (optimized ONNX graph execution).
- Broader ecosystem: ONNX is the industry standard for ML model interchange.

### Negative
- ONNX Runtime binary is larger than header-only frugally-deep (~50 MB shared library).
- Old Keras `.h5` models need a one-time conversion via `tf2onnx` or retraining.
- Requires C++17 or later (already our minimum).

### Migration Path
1. Added `onnxruntime` to `vcpkg.json`, removed `frugally-deep`.
2. Rewrote `OnnxAnalyzer` to use ONNX Runtime C++ API.
3. Created `scripts/convert_model.py` for legacy Keras model conversion.
4. Deleted `FdeepAnalyzer.h/.cpp`, `model.json`, `keras_converter.py`.
5. Rewrote Dockerfile to use vcpkg instead of manual dependency builds.
