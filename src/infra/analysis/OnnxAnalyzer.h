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

#include <memory>
#include <span>
#include <string>
#include <vector>

namespace nids::infra {

/** ONNX Runtime-based packet analyzer for ML inference. */
class OnnxAnalyzer : public nids::core::IPacketAnalyzer {
public:
    /** Construct analyzer and initialize the ONNX Runtime environment. */
    OnnxAnalyzer();
    ~OnnxAnalyzer() override;

    OnnxAnalyzer(const OnnxAnalyzer&) = delete;
    OnnxAnalyzer& operator=(const OnnxAnalyzer&) = delete;
    OnnxAnalyzer(OnnxAnalyzer&&) = delete;
    OnnxAnalyzer& operator=(OnnxAnalyzer&&) = delete;

    [[nodiscard]] std::expected<void, std::string> loadModel(
        const std::string& modelPath) override;
    [[nodiscard]] nids::core::AttackType predict(std::span<const float> features) override;
    [[nodiscard]] nids::core::PredictionResult predictWithConfidence(
        std::span<const float> features) override;

    /// Native batched inference — runs N flows in a single session.Run() call.
    [[nodiscard]] std::vector<nids::core::PredictionResult> predictBatch(
        std::span<const float> batch, std::size_t featureCount) override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_{nullptr};
};

} // namespace nids::infra
