#pragma once

#include "core/model/AttackType.h"
#include "core/model/PredictionResult.h"

#include <vector>
#include <string>

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
};

} // namespace nids::core
