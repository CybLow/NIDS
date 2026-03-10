#pragma once

/// Unified detection result combining ML, threat intelligence, and heuristic signals.
///
/// Produced by HybridDetectionService after evaluating a flow through all three
/// detection layers. Provides full traceability: the final verdict, which layer(s)
/// contributed, individual scores, and human-readable explanations.

#include "core/model/AttackType.h"
#include "core/model/PredictionResult.h"

#include <string>
#include <vector>
#include <cstdint>

namespace nids::core {

/// Identifies which detection layer drove the final verdict.
enum class DetectionSource : std::uint8_t {
    MlOnly,          ///< ML classifier alone (high confidence, no TI/rule match)
    ThreatIntel,     ///< Threat intelligence match overrode or confirmed ML
    HeuristicRule,   ///< Heuristic rule fired
    MlPlusThreatIntel,   ///< ML + TI corroboration
    MlPlusHeuristic,     ///< ML + heuristic corroboration
    Ensemble,        ///< All three layers contributed
    None             ///< No detection (benign, no flags)
};

[[nodiscard]] constexpr std::string_view detectionSourceToString(
    DetectionSource source) noexcept {
    switch (source) {
        case DetectionSource::MlOnly:           return "ML Classifier";
        case DetectionSource::ThreatIntel:      return "Threat Intelligence";
        case DetectionSource::HeuristicRule:     return "Heuristic Rule";
        case DetectionSource::MlPlusThreatIntel: return "ML + Threat Intel";
        case DetectionSource::MlPlusHeuristic:  return "ML + Heuristic";
        case DetectionSource::Ensemble:         return "Ensemble (ML + TI + Rules)";
        case DetectionSource::None:             return "None";
    }
    return "Unknown";
}

/// Describes a single threat intelligence match.
struct ThreatIntelMatch {
    std::string ip;          ///< The IP address that matched
    std::string feedName;    ///< Which feed it was found in (e.g., "feodo", "spamhaus")
    bool isSource = false;   ///< True if source IP matched, false if destination
};

/// Describes a single heuristic rule match.
struct RuleMatch {
    std::string ruleName;    ///< Machine-readable rule ID (e.g., "suspicious_port")
    std::string description; ///< Human-readable explanation
    float severity = 0.0f;  ///< Severity score [0.0, 1.0]
};

/// Full detection result for a single flow.
struct DetectionResult {
    // -- ML layer --
    PredictionResult mlResult;

    // -- Threat intelligence layer --
    std::vector<ThreatIntelMatch> threatIntelMatches;

    // -- Heuristic rules layer --
    std::vector<RuleMatch> ruleMatches;

    // -- Combined verdict --
    AttackType finalVerdict = AttackType::Unknown;
    float combinedScore = 0.0f;       ///< Unified threat score [0.0, 1.0]
    DetectionSource detectionSource = DetectionSource::None;

    // -- Convenience accessors --

    [[nodiscard]] bool hasThreatIntelMatch() const noexcept {
        return !threatIntelMatches.empty();
    }

    [[nodiscard]] bool hasRuleMatch() const noexcept {
        return !ruleMatches.empty();
    }

    /// Maximum severity across all matched heuristic rules, or 0.0 if none.
    [[nodiscard]] float maxRuleSeverity() const noexcept {
        float maxSev = 0.0f;
        for (const auto& rule : ruleMatches) {
            if (rule.severity > maxSev) {
                maxSev = rule.severity;
            }
        }
        return maxSev;
    }

    /// True if any detection layer flagged this flow as suspicious.
    [[nodiscard]] bool isFlagged() const noexcept {
        return mlResult.isAttack()
            || hasThreatIntelMatch()
            || hasRuleMatch();
    }
};

} // namespace nids::core
