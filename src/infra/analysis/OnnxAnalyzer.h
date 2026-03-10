#pragma once

// ONNX Runtime-based analyzer for ML inference.
//
// This provides a drop-in replacement for FdeepAnalyzer with superior
// performance characteristics:
// - GPU acceleration (CUDA, DirectML, TensorRT providers)
// - Broader model format support (.onnx from PyTorch, TensorFlow, etc.)
// - Better inference throughput for real-time detection
//
// To enable:
// 1. Add onnxruntime to vcpkg.json: "onnxruntime-gpu" or "onnxruntime"
// 2. Convert the Keras model: python -m tf2onnx.convert --keras model.keras --output model.onnx
// 3. Set NIDS_USE_ONNX=ON in CMake
// 4. The IPacketAnalyzer interface is shared with FdeepAnalyzer

#include "core/services/IPacketAnalyzer.h"

#include <string>
#include <vector>
#include <memory>

namespace nids::infra {

class OnnxAnalyzer : public nids::core::IPacketAnalyzer {
public:
    OnnxAnalyzer();
    ~OnnxAnalyzer() override;

    [[nodiscard]] bool loadModel(const std::string& modelPath) override;
    [[nodiscard]] nids::core::AttackType predict(const std::vector<float>& features) override;
    [[nodiscard]] nids::core::PredictionResult predictWithConfidence(
        const std::vector<float>& features) override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace nids::infra
