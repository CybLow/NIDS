#pragma once

/**
 * Prediction result from the ML classifier.
 *
 * Wraps the raw model output: the top predicted class plus the full
 * softmax probability distribution. This replaces the bare AttackType
 * return from IPacketAnalyzer::predict(), enabling downstream consumers
 * (HybridDetectionService) to make confidence-aware decisions.
 */

#include "core/model/AttackType.h"

#include <array>

namespace nids::core {

/** Prediction result from the ML classifier. */
struct PredictionResult {
    /** Top predicted attack class from the ML model. */
    AttackType classification = AttackType::Unknown;
    /** Confidence score (softmax probability) of the top prediction [0.0, 1.0]. */
    float confidence = 0.0f;
    /** Full softmax probability distribution over all kAttackTypeCount classes. */
    std::array<float, kAttackTypeCount> probabilities{};

    /// True if the classifier had no result (model not loaded, inference failed).
    [[nodiscard]] constexpr bool isUnknown() const noexcept {
        return classification == AttackType::Unknown;
    }

    /// True if confidence exceeds the given threshold.
    [[nodiscard]] constexpr bool isHighConfidence(float threshold = 0.7f) const noexcept {
        return confidence >= threshold;
    }

    /// True if the top prediction is any attack type (not Benign, not Unknown).
    [[nodiscard]] constexpr bool isAttack() const noexcept {
        return classification != AttackType::Benign
            && classification != AttackType::Unknown;
    }
};

} // namespace nids::core
