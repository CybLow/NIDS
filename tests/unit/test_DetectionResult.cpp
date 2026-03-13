#include <gtest/gtest.h>
#include "core/model/DetectionResult.h"

using nids::core::DetectionResult;
using nids::core::DetectionSource;
using nids::core::AttackType;
using nids::core::ThreatIntelMatch;
using nids::core::RuleMatch;

TEST(DetectionResult, defaultConstruction_hasUnknownVerdict) {
    DetectionResult result;
    EXPECT_EQ(result.finalVerdict, AttackType::Unknown);
    EXPECT_FLOAT_EQ(result.combinedScore, 0.0f);
    EXPECT_EQ(result.detectionSource, DetectionSource::None);
}

TEST(DetectionResult, defaultConstruction_hasNoMatches) {
    DetectionResult result;
    EXPECT_FALSE(result.hasThreatIntelMatch());
    EXPECT_FALSE(result.hasRuleMatch());
    EXPECT_FALSE(result.isFlagged());
}

TEST(DetectionResult, hasThreatIntelMatch_trueWhenPopulated) {
    DetectionResult result;
    result.threatIntelMatches.emplace_back("1.2.3.4", "feodo", true);
    EXPECT_TRUE(result.hasThreatIntelMatch());
}

TEST(DetectionResult, hasRuleMatch_trueWhenPopulated) {
    DetectionResult result;
    result.ruleMatches.emplace_back("suspicious_port", "Port 4444 detected", 0.6f);
    EXPECT_TRUE(result.hasRuleMatch());
}

TEST(DetectionResult, maxRuleSeverity_returnsHighestSeverity) {
    DetectionResult result;
    result.ruleMatches.emplace_back("rule_a", "Low severity", 0.2f);
    result.ruleMatches.emplace_back("rule_b", "High severity", 0.9f);
    result.ruleMatches.emplace_back("rule_c", "Medium severity", 0.5f);
    EXPECT_FLOAT_EQ(result.maxRuleSeverity(), 0.9f);
}

TEST(DetectionResult, maxRuleSeverity_zeroWhenEmpty) {
    DetectionResult result;
    EXPECT_FLOAT_EQ(result.maxRuleSeverity(), 0.0f);
}

TEST(DetectionResult, isFlagged_trueWhenMlIsAttack) {
    DetectionResult result;
    result.mlResult.classification = AttackType::DdosIcmp;
    result.mlResult.confidence = 0.95f;
    EXPECT_TRUE(result.isFlagged());
}

TEST(DetectionResult, isFlagged_trueWhenThreatIntelMatch) {
    DetectionResult result;
    result.threatIntelMatches.emplace_back("10.0.0.1", "spamhaus", false);
    EXPECT_TRUE(result.isFlagged());
}

TEST(DetectionResult, isFlagged_trueWhenRuleMatch) {
    DetectionResult result;
    result.ruleMatches.emplace_back("syn_flood", "SYN flood detected", 0.8f);
    EXPECT_TRUE(result.isFlagged());
}

TEST(DetectionResult, isFlagged_falseWhenBenignAndNoMatches) {
    DetectionResult result;
    result.mlResult.classification = AttackType::Benign;
    result.mlResult.confidence = 0.99f;
    EXPECT_FALSE(result.isFlagged());
}

TEST(DetectionSource, toStringCoversAllValues) {
    using nids::core::detectionSourceToString;

    EXPECT_EQ(detectionSourceToString(DetectionSource::MlOnly), "ML Classifier");
    EXPECT_EQ(detectionSourceToString(DetectionSource::ThreatIntel), "Threat Intelligence");
    EXPECT_EQ(detectionSourceToString(DetectionSource::HeuristicRule), "Heuristic Rule");
    EXPECT_EQ(detectionSourceToString(DetectionSource::MlPlusThreatIntel), "ML + Threat Intel");
    EXPECT_EQ(detectionSourceToString(DetectionSource::MlPlusHeuristic), "ML + Heuristic");
    EXPECT_EQ(detectionSourceToString(DetectionSource::Ensemble), "Ensemble (ML + TI + Rules)");
    EXPECT_EQ(detectionSourceToString(DetectionSource::None), "None");
}

TEST(DetectionSource, toStringInvalidEnum_returnsUnknown) {
    using nids::core::detectionSourceToString;

    // Cast an out-of-range value to DetectionSource to exercise the
    // post-switch fallback `return "Unknown"` (line 47 in DetectionResult.h).
    auto invalid = static_cast<DetectionSource>(static_cast<std::uint8_t>(255));
    EXPECT_EQ(detectionSourceToString(invalid), "Unknown");
}
