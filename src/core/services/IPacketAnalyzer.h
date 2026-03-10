#pragma once

#include "core/model/AttackType.h"
#include "core/model/PredictionResult.h"

#include <vector>
#include <string>

namespace nids::core {

class IPacketAnalyzer {
public:
    virtual ~IPacketAnalyzer() = default;

    [[nodiscard]] virtual bool loadModel(const std::string& modelPath) = 0;
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
