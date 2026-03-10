#pragma once

/// Hybrid detection service combining ML, threat intelligence, and heuristic rules.
///
/// Orchestrates the three detection layers to produce a unified DetectionResult
/// for each flow. Implements the escalation logic described in ADR-005:
/// - TI matches always escalate (override benign ML verdicts)
/// - Low ML confidence + heuristic match = escalate
/// - High ML confidence with no corroboration = trust ML
///
/// Located in the app/ layer per Clean Architecture (depends on core/ interfaces,
/// injected with infra/ implementations).

#include "core/model/DetectionResult.h"
#include "core/model/PredictionResult.h"
#include "core/services/IThreatIntelligence.h"
#include "core/services/IRuleEngine.h"

#include <string>
#include <memory>

namespace nids::app {

class HybridDetectionService {
public:
    /// Weights for combining detection signals into a unified score.
    struct Weights {
        float ml = 0.5f;
        float threatIntel = 0.3f;
        float heuristic = 0.2f;
    };

    /// Construct with optional TI and rule engine.
    /// Either or both can be nullptr (graceful degradation to ML-only).
    explicit HybridDetectionService(
        nids::core::IThreatIntelligence* threatIntel = nullptr,
        nids::core::IRuleEngine* ruleEngine = nullptr);

    /// Set the weights for combining detection signals.
    void setWeights(const Weights& weights) noexcept;

    /// Set the ML confidence threshold below which other signals are consulted
    /// more aggressively. Default: 0.7
    void setConfidenceThreshold(float threshold) noexcept;

    /// Evaluate a single flow through all detection layers.
    ///
    /// @param mlResult   The ML classifier's prediction (from OnnxAnalyzer)
    /// @param srcIp      Source IP of the flow (for TI lookup)
    /// @param dstIp      Destination IP of the flow (for TI lookup)
    /// @param flowMeta   Flow metadata (for heuristic rule evaluation)
    [[nodiscard]] nids::core::DetectionResult evaluate(
        const nids::core::PredictionResult& mlResult,
        const std::string& srcIp,
        const std::string& dstIp,
        const nids::core::FlowMetadata& flowMeta) const;

    /// Simplified evaluation when flow metadata is not available.
    /// Only runs ML + TI layers (skips heuristic rules).
    [[nodiscard]] nids::core::DetectionResult evaluate(
        const nids::core::PredictionResult& mlResult,
        const std::string& srcIp,
        const std::string& dstIp) const;

private:
    /// Compute the combined threat score from individual layer scores.
    [[nodiscard]] float computeCombinedScore(
        const nids::core::PredictionResult& mlResult,
        bool hasTiMatch,
        float maxRuleSeverity) const noexcept;

    /// Determine the detection source based on which layers contributed.
    [[nodiscard]] static nids::core::DetectionSource determineSource(
        bool mlIsAttack,
        bool hasTiMatch,
        bool hasRuleMatch) noexcept;

    /// Determine the final verdict using escalation logic.
    [[nodiscard]] nids::core::AttackType determineVerdict(
        const nids::core::PredictionResult& mlResult,
        bool hasTiMatch,
        bool hasRuleMatch,
        float maxRuleSeverity) const noexcept;

    nids::core::IThreatIntelligence* threatIntel_ = nullptr;  // non-owning
    nids::core::IRuleEngine* ruleEngine_ = nullptr;           // non-owning
    Weights weights_;
    float confidenceThreshold_ = 0.7f;
};

} // namespace nids::app
