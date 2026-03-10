#include "app/HybridDetectionService.h"

#include <spdlog/spdlog.h>

#include <algorithm>

namespace nids::app {

HybridDetectionService::HybridDetectionService(
    nids::core::IThreatIntelligence* threatIntel,
    nids::core::IRuleEngine* ruleEngine)
    : threatIntel_(threatIntel)
    , ruleEngine_(ruleEngine) {}

void HybridDetectionService::setWeights(const Weights& weights) noexcept {
    weights_ = weights;
}

void HybridDetectionService::setConfidenceThreshold(float threshold) noexcept {
    confidenceThreshold_ = threshold;
}

nids::core::DetectionResult HybridDetectionService::evaluate(
    const nids::core::PredictionResult& mlResult,
    const std::string& srcIp,
    const std::string& dstIp,
    const nids::core::FlowMetadata& flowMeta) const {

    nids::core::DetectionResult result;
    result.mlResult = mlResult;

    // -- Layer 2: Threat Intelligence --
    if (threatIntel_ != nullptr) {
        auto srcLookup = threatIntel_->lookup(srcIp);
        if (srcLookup.matched) {
            result.threatIntelMatches.push_back({
                .ip = srcIp,
                .feedName = srcLookup.feedName,
                .isSource = true
            });
        }

        auto dstLookup = threatIntel_->lookup(dstIp);
        if (dstLookup.matched) {
            result.threatIntelMatches.push_back({
                .ip = dstIp,
                .feedName = dstLookup.feedName,
                .isSource = false
            });
        }
    }

    // -- Layer 3: Heuristic Rules --
    if (ruleEngine_ != nullptr) {
        auto ruleResults = ruleEngine_->evaluate(flowMeta);
        for (auto& r : ruleResults) {
            result.ruleMatches.push_back({
                .ruleName = std::move(r.ruleName),
                .description = std::move(r.description),
                .severity = r.severity
            });
        }
    }

    // -- Combine signals --
    bool hasTi = result.hasThreatIntelMatch();
    bool hasRules = result.hasRuleMatch();
    float maxSev = result.maxRuleSeverity();

    result.combinedScore = computeCombinedScore(mlResult, hasTi, maxSev);
    result.finalVerdict = determineVerdict(mlResult, hasTi, hasRules, maxSev);
    result.detectionSource = determineSource(mlResult.isAttack(), hasTi, hasRules);

    if (hasTi && !mlResult.isAttack()) {
        spdlog::info("TI override: ML classified flow as {} (conf={:.3f}) but "
                     "IP matched threat intel feed",
                     nids::core::attackTypeToString(mlResult.classification),
                     mlResult.confidence);
    }

    return result;
}

nids::core::DetectionResult HybridDetectionService::evaluate(
    const nids::core::PredictionResult& mlResult,
    const std::string& srcIp,
    const std::string& dstIp) const {

    // Simplified: only ML + TI, no heuristic rules
    nids::core::FlowMetadata emptyMeta;
    auto result = evaluate(mlResult, srcIp, dstIp, emptyMeta);
    // Clear any spurious rule matches from empty metadata
    result.ruleMatches.clear();
    // Recompute without rules
    result.combinedScore = computeCombinedScore(mlResult,
        result.hasThreatIntelMatch(), 0.0f);
    result.detectionSource = determineSource(mlResult.isAttack(),
        result.hasThreatIntelMatch(), false);
    result.finalVerdict = determineVerdict(mlResult,
        result.hasThreatIntelMatch(), false, 0.0f);

    return result;
}

float HybridDetectionService::computeCombinedScore(
    const nids::core::PredictionResult& mlResult,
    bool hasTiMatch,
    float maxRuleSeverity) const noexcept {

    // ML score: probability of being malicious
    float mlScore = 0.0f;
    if (mlResult.isAttack()) {
        mlScore = mlResult.confidence;
    } else if (mlResult.classification == nids::core::AttackType::Benign) {
        // Invert: benign with high confidence = low threat
        mlScore = 1.0f - mlResult.confidence;
    }
    // Unknown: mlScore stays 0.0

    float tiScore = hasTiMatch ? 1.0f : 0.0f;
    float ruleScore = maxRuleSeverity;

    float combined = weights_.ml * mlScore
                   + weights_.threatIntel * tiScore
                   + weights_.heuristic * ruleScore;

    return std::clamp(combined, 0.0f, 1.0f);
}

nids::core::DetectionSource HybridDetectionService::determineSource(
    bool mlIsAttack,
    bool hasTiMatch,
    bool hasRuleMatch) noexcept {

    if (mlIsAttack && hasTiMatch && hasRuleMatch) {
        return nids::core::DetectionSource::Ensemble;
    }
    if (mlIsAttack && hasTiMatch) {
        return nids::core::DetectionSource::MlPlusThreatIntel;
    }
    if (mlIsAttack && hasRuleMatch) {
        return nids::core::DetectionSource::MlPlusHeuristic;
    }
    if (hasTiMatch) {
        return nids::core::DetectionSource::ThreatIntel;
    }
    if (hasRuleMatch) {
        return nids::core::DetectionSource::HeuristicRule;
    }
    if (mlIsAttack) {
        return nids::core::DetectionSource::MlOnly;
    }
    return nids::core::DetectionSource::None;
}

nids::core::AttackType HybridDetectionService::determineVerdict(
    const nids::core::PredictionResult& mlResult,
    bool hasTiMatch,
    bool hasRuleMatch,
    float maxRuleSeverity) const noexcept {

    // Case 1: ML says attack with high confidence -- trust ML
    if (mlResult.isAttack() && mlResult.isHighConfidence(confidenceThreshold_)) {
        return mlResult.classification;
    }

    // Case 2: ML says attack with low confidence
    if (mlResult.isAttack()) {
        // TI or rules corroborate -- keep ML classification
        if (hasTiMatch || hasRuleMatch) {
            return mlResult.classification;
        }
        // No corroboration -- still report ML classification but with low confidence
        return mlResult.classification;
    }

    // Case 3: ML says benign
    if (mlResult.classification == nids::core::AttackType::Benign) {
        // TI match overrides benign verdict -- this is the key escalation
        if (hasTiMatch) {
            return nids::core::AttackType::Unknown;  // Suspicious, not classifiable
        }

        // High-severity heuristic rule + low ML confidence = escalate
        if (hasRuleMatch && maxRuleSeverity >= 0.7f
            && !mlResult.isHighConfidence(confidenceThreshold_)) {
            return nids::core::AttackType::Unknown;  // Suspicious
        }

        // Otherwise trust ML
        return nids::core::AttackType::Benign;
    }

    // Case 4: Unknown ML result -- defer to TI/rules
    if (hasTiMatch) {
        return nids::core::AttackType::Unknown;  // Suspicious
    }

    return mlResult.classification;
}

} // namespace nids::app
