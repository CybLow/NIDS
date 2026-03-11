#pragma once

// ONNX Runtime-based analyzer for ML inference.
//
// Performance characteristics:
// - GPU acceleration (CUDA, DirectML, TensorRT providers)
// - Broader model format support (.onnx from PyTorch, TensorFlow, etc.)
// - Better inference throughput for real-time detection
//
// Model conversion:
//   python -m tf2onnx.convert --keras model.keras --output model.onnx

#include "core/services/IPacketAnalyzer.h"

#include <string>
#include <vector>
#include <memory>

namespace nids::infra {

/** ONNX Runtime-based packet analyzer for ML inference. */
class OnnxAnalyzer : public nids::core::IPacketAnalyzer {
public:
    /** Construct analyzer and initialize the ONNX Runtime environment. */
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
