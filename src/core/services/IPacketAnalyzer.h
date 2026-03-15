#pragma once

#include "core/model/AttackType.h"
#include "core/model/PredictionResult.h"

#include <span>
#include <string>
#include <vector>

namespace nids::core {

/** Abstract interface for ML-based packet/flow classification. */
class IPacketAnalyzer {
public:
    virtual ~IPacketAnalyzer() = default;

    /**
     * Load an ML model from the given file path.
     * @param modelPath Path to the ONNX model file.
     * @return True if the model was loaded successfully.
     */
    [[nodiscard]] virtual bool loadModel(const std::string& modelPath) = 0;

    /**
     * Classify a flow given its feature vector.
     * @param features Normalized feature vector (kFlowFeatureCount elements).
     * @return Predicted attack type.
     */
    [[nodiscard]] virtual AttackType predict(const std::vector<float>& features) = 0;

    /// Enhanced prediction returning confidence scores and full probability distribution.
    /// Default implementation delegates to predict() and wraps the result.
    [[nodiscard]] virtual PredictionResult predictWithConfidence(
        const std::vector<float>& features) {
        auto type = predict(features);
        PredictionResult result;
        result.classification = type;
        result.confidence = (type == AttackType::Unknown) ? 0.0f : 1.0f;
        // Probabilities unavailable from bare predict() -- leave as zeros.
        return result;
    }

    /// Batched prediction for multiple flows at once.
    ///
    /// Runs inference on N flows in a single ONNX Runtime session.Run() call.
    /// This amortizes per-call overhead and enables SIMD/parallelism within
    /// the ONNX Runtime engine, yielding 5-20x throughput improvement over
    /// single-flow inference for batch sizes 16-64.
    ///
    /// @param batch  Flat contiguous buffer of shape [N * featureCount].
    ///               Each consecutive featureCount floats is one flow.
    /// @param featureCount  Number of features per flow (e.g. 77).
    /// @return One PredictionResult per flow, in the same order as input.
    ///
    /// Default implementation falls back to per-flow predictWithConfidence().
    [[nodiscard]] virtual std::vector<PredictionResult> predictBatch(
        std::span<const float> batch, std::size_t featureCount) {
        std::vector<PredictionResult> results;
        if (featureCount == 0) return results;
        auto flowCount = batch.size() / featureCount;
        results.reserve(flowCount);
        for (std::size_t i = 0; i < flowCount; ++i) {
            auto flowData = batch.subspan(i * featureCount, featureCount);
            results.push_back(predictWithConfidence(
                std::vector<float>(flowData.begin(), flowData.end())));
        }
        return results;
    }
};

} // namespace nids::core
