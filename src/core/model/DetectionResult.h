#pragma once

/// Unified detection result combining ML, threat intelligence, and heuristic signals.
///
/// Produced by HybridDetectionService after evaluating a flow through all three
/// detection layers. Provides full traceability: the final verdict, which layer(s)
/// contributed, individual scores, and human-readable explanations.

#include "core/model/AttackType.h"
#include "core/model/DetectionSource.h"
#include "core/model/PredictionResult.h"
#include "core/model/RuleMatch.h"
#include "core/model/ThreatIntelMatch.h"

#include <algorithm>
#include <ranges>
#include <vector>

namespace nids::core {

/// Full detection result for a single flow.
struct DetectionResult {
    /** ML classifier prediction result for this flow. */
    PredictionResult mlResult;

    /** Threat intelligence matches found for source/destination IPs. */
    std::vector<ThreatIntelMatch> threatIntelMatches;

    /** Heuristic rule matches triggered by flow metadata. */
    std::vector<RuleMatch> ruleMatches;

    /** Final attack classification after combining all detection layers. */
    AttackType finalVerdict = AttackType::Unknown;
    float combinedScore = 0.0f;       ///< Unified threat score [0.0, 1.0]
    /** Identifies which detection layer(s) drove the final verdict. */
    DetectionSource detectionSource = DetectionSource::None;

    /** Check whether any threat intelligence feed matched this flow. */
    [[nodiscard]] bool hasThreatIntelMatch() const noexcept {
        return !threatIntelMatches.empty();
    }

    /** Check whether any heuristic rule fired for this flow. */
    [[nodiscard]] bool hasRuleMatch() const noexcept {
        return !ruleMatches.empty();
    }

    /// Maximum severity across all matched heuristic rules, or 0.0 if none.
    [[nodiscard]] float maxRuleSeverity() const noexcept {
        if (ruleMatches.empty())
            return 0.0f;
        auto it = std::ranges::max_element(ruleMatches, {},
            [](const RuleMatch& r) { return r.severity; });
        return it->severity;
    }

    /// True if any detection layer flagged this flow as suspicious.
    [[nodiscard]] bool isFlagged() const noexcept {
        return mlResult.isAttack()
            || hasThreatIntelMatch()
            || hasRuleMatch();
    }
};

} // namespace nids::core
