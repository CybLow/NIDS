#pragma once

/**
 * Hybrid detection service combining ML, threat intelligence, heuristic rules,
 * and content scanning (YARA).
 *
 * Orchestrates up to 5 detection layers to produce a unified DetectionResult
 * for each flow. Implements the escalation logic described in ADR-005/ADR-008:
 * - TI matches always escalate (override benign ML verdicts)
 * - Low ML confidence + heuristic match = escalate
 * - YARA content matches contribute to combined score
 * - High ML confidence with no corroboration = trust ML
 *
 * Located in the app/ layer per Clean Architecture (depends on core/ interfaces,
 * injected with infra/ implementations).
 */

#include "core/model/ContentMatch.h"
#include "core/model/DetectionResult.h"
#include "core/model/FlowInfo.h"
#include "core/model/PredictionResult.h"
#include "core/services/IThreatIntelligence.h"
#include "core/services/IRuleEngine.h"

#include <span>
#include <string>
#include <vector>

namespace nids::app {

/** Hybrid detection service combining ML, threat intelligence, and heuristic rules. */
class HybridDetectionService {
public:
    /// Weights for combining detection signals into a unified score.
    struct Weights {
        /** ML classifier weight (0.0–1.0). */
        float ml = 0.5f;
        /** Threat intelligence weight (0.0–1.0). */
        float threatIntel = 0.3f;
        /** Heuristic rule engine weight (0.0–1.0). */
        float heuristic = 0.2f;
        /** YARA content scanning weight (0.0–1.0). Phase 14. */
        float contentScan = 0.0f;
    };

    /// Construct with optional TI and rule engine.
    /// Either or both can be nullptr (graceful degradation to ML-only).
    explicit HybridDetectionService(
        core::IThreatIntelligence* threatIntel = nullptr,
        core::IRuleEngine* ruleEngine = nullptr);

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
    /// @param flowInfo   Flow metadata (for heuristic rule evaluation)
    [[nodiscard]] core::DetectionResult evaluate(
        const core::PredictionResult& mlResult,
        const std::string& srcIp,
        const std::string& dstIp,
        const core::FlowInfo& flowInfo) const;

    /// Simplified evaluation when flow metadata is not available.
    /// Only runs ML + TI layers (skips heuristic rules).
    [[nodiscard]] core::DetectionResult evaluate(
        const core::PredictionResult& mlResult,
        const std::string& srcIp,
        const std::string& dstIp) const;

    /// Full 5-layer evaluation including YARA content scan results.
    [[nodiscard]] core::DetectionResult evaluate(
        const core::PredictionResult& mlResult,
        const std::string& srcIp,
        const std::string& dstIp,
        const core::FlowInfo& flowInfo,
        std::span<const core::ContentMatch> contentMatches) const;

private:
    /// Compute the combined threat score from individual layer scores.
    [[nodiscard]] float computeCombinedScore(
        const core::PredictionResult& mlResult,
        bool hasTiMatch,
        float maxRuleSeverity,
        float maxContentSeverity = 0.0f) const noexcept;

    /// Determine the detection source based on which layers contributed.
    [[nodiscard]] static core::DetectionSource determineSource(
        bool mlIsAttack,
        bool hasTiMatch,
        bool hasRuleMatch,
        bool hasContentMatch = false) noexcept;

    /// Determine the final verdict using escalation logic.
    [[nodiscard]] core::AttackType determineVerdict(
        const core::PredictionResult& mlResult,
        bool hasTiMatch,
        bool hasRuleMatch,
        float maxRuleSeverity) const noexcept;

    /// Escalation logic when ML classifies as benign.
    [[nodiscard]] core::AttackType verdictForBenign(
        const core::PredictionResult& mlResult,
        bool hasTiMatch,
        bool hasRuleMatch,
        float maxRuleSeverity) const noexcept;

    /// Populate threat intelligence matches for src/dst IPs.
    /// Shared by both evaluate() overloads to eliminate duplication (DRY).
    void populateThreatIntel(
        core::DetectionResult& result,
        const std::string& srcIp,
        const std::string& dstIp) const;

    core::IThreatIntelligence* threatIntel_ = nullptr;  // non-owning
    core::IRuleEngine* ruleEngine_ = nullptr;           // non-owning
    Weights weights_;
    float confidenceThreshold_ = 0.7f;
};

} // namespace nids::app
