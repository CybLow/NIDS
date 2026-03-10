#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "app/HybridDetectionService.h"
#include "core/services/IThreatIntelligence.h"
#include "core/services/IRuleEngine.h"
#include "core/model/PredictionResult.h"
#include "core/model/DetectionResult.h"
#include "core/model/AttackType.h"

using namespace nids::core;
using namespace nids::app;
using ::testing::_;
using ::testing::Return;

// ── Mocks ────────────────────────────────────────────────────────────

class MockThreatIntel : public IThreatIntelligence {
public:
    MOCK_METHOD(std::size_t, loadFeeds, (const std::string&), (override));
    MOCK_METHOD(ThreatIntelLookup, lookup, (std::string_view), (const, override));
    MOCK_METHOD(ThreatIntelLookup, lookup, (std::uint32_t), (const, override));
    MOCK_METHOD(std::size_t, entryCount, (), (const, noexcept, override));
    MOCK_METHOD(std::size_t, feedCount, (), (const, noexcept, override));
};

class MockRuleEngine : public IRuleEngine {
public:
    MOCK_METHOD(std::vector<HeuristicRuleResult>, evaluate,
                (const FlowMetadata&), (const, override));
    MOCK_METHOD(std::vector<HeuristicRuleResult>, evaluatePortScan,
                (std::string_view, const std::vector<std::uint16_t>&),
                (const, override));
    MOCK_METHOD(std::size_t, ruleCount, (), (const, noexcept, override));
};

// ── Fixture ──────────────────────────────────────────────────────────

class HybridDetectionServiceTest : public ::testing::Test {
protected:
    MockThreatIntel mockTi_;
    MockRuleEngine mockRules_;

    /// Build a PredictionResult with given classification and confidence.
    static PredictionResult makePrediction(AttackType type, float confidence) {
        PredictionResult pred;
        pred.classification = type;
        pred.confidence = confidence;
        return pred;
    }

    /// Build a benign flow metadata.
    static FlowMetadata makeBenignFlowMeta() {
        FlowMetadata flow;
        flow.srcIp = "192.168.1.10";
        flow.dstIp = "10.0.0.1";
        flow.srcPort = 45000;
        flow.dstPort = 80;
        flow.protocol = "TCP";
        flow.totalFwdPackets = 10;
        flow.totalBwdPackets = 8;
        return flow;
    }
};

// ── ML-only (no TI, no rules) ────────────────────────────────────────

TEST_F(HybridDetectionServiceTest, mlOnly_highConfidenceAttack_trustedAsIs) {
    HybridDetectionService service(nullptr, nullptr);

    auto pred = makePrediction(AttackType::DdosIcmp, 0.95f);
    auto result = service.evaluate(pred, "192.168.1.10", "10.0.0.1");

    EXPECT_EQ(result.finalVerdict, AttackType::DdosIcmp);
    EXPECT_FALSE(result.hasThreatIntelMatch());
    EXPECT_FALSE(result.hasRuleMatch());
}

TEST_F(HybridDetectionServiceTest, mlOnly_benign_staysBenign) {
    HybridDetectionService service(nullptr, nullptr);

    auto pred = makePrediction(AttackType::Benign, 0.99f);
    auto result = service.evaluate(pred, "192.168.1.10", "10.0.0.1");

    EXPECT_EQ(result.finalVerdict, AttackType::Benign);
}

// ── TI escalation ────────────────────────────────────────────────────

TEST_F(HybridDetectionServiceTest, tiMatch_benignMl_escalatesToUnknown) {
    EXPECT_CALL(mockTi_, lookup(std::string_view("192.168.1.10")))
        .WillOnce(Return(ThreatIntelLookup{true, "feodo"}));
    EXPECT_CALL(mockTi_, lookup(std::string_view("10.0.0.1")))
        .WillOnce(Return(ThreatIntelLookup{false, ""}));

    HybridDetectionService service(&mockTi_, nullptr);

    auto pred = makePrediction(AttackType::Benign, 0.8f);
    auto result = service.evaluate(pred, "192.168.1.10", "10.0.0.1");

    // TI match should override benign ML verdict
    EXPECT_EQ(result.finalVerdict, AttackType::Unknown);
    EXPECT_TRUE(result.hasThreatIntelMatch());
}

TEST_F(HybridDetectionServiceTest, tiMatch_attackMl_trustsMlClassification) {
    EXPECT_CALL(mockTi_, lookup(std::string_view("192.168.1.10")))
        .WillOnce(Return(ThreatIntelLookup{true, "spamhaus"}));
    EXPECT_CALL(mockTi_, lookup(std::string_view("10.0.0.1")))
        .WillOnce(Return(ThreatIntelLookup{false, ""}));

    HybridDetectionService service(&mockTi_, nullptr);

    auto pred = makePrediction(AttackType::SshBruteForce, 0.9f);
    auto result = service.evaluate(pred, "192.168.1.10", "10.0.0.1");

    // ML says attack + TI confirms → keep ML classification
    EXPECT_EQ(result.finalVerdict, AttackType::SshBruteForce);
    EXPECT_TRUE(result.hasThreatIntelMatch());
}

TEST_F(HybridDetectionServiceTest, noTiMatch_staysOriginal) {
    EXPECT_CALL(mockTi_, lookup(std::string_view("192.168.1.10")))
        .WillOnce(Return(ThreatIntelLookup{false, ""}));
    EXPECT_CALL(mockTi_, lookup(std::string_view("10.0.0.1")))
        .WillOnce(Return(ThreatIntelLookup{false, ""}));

    HybridDetectionService service(&mockTi_, nullptr);

    auto pred = makePrediction(AttackType::Benign, 0.95f);
    auto result = service.evaluate(pred, "192.168.1.10", "10.0.0.1");

    EXPECT_EQ(result.finalVerdict, AttackType::Benign);
    EXPECT_FALSE(result.hasThreatIntelMatch());
}

// ── Heuristic rule escalation ────────────────────────────────────────

TEST_F(HybridDetectionServiceTest, highSeverityRule_lowConfBenign_escalates) {
    EXPECT_CALL(mockTi_, lookup(std::string_view("192.168.1.10")))
        .WillOnce(Return(ThreatIntelLookup{false, ""}));
    EXPECT_CALL(mockTi_, lookup(std::string_view("10.0.0.1")))
        .WillOnce(Return(ThreatIntelLookup{false, ""}));

    std::vector<HeuristicRuleResult> ruleMatches = {
        {"syn_flood", "SYN flood detected", 0.85f}
    };
    EXPECT_CALL(mockRules_, evaluate(_)).WillOnce(Return(ruleMatches));

    HybridDetectionService service(&mockTi_, &mockRules_);

    auto pred = makePrediction(AttackType::Benign, 0.55f); // low confidence
    auto flow = makeBenignFlowMeta();
    auto result = service.evaluate(pred, "192.168.1.10", "10.0.0.1", flow);

    // High-severity rule + low ML confidence → escalate
    EXPECT_EQ(result.finalVerdict, AttackType::Unknown);
    EXPECT_TRUE(result.hasRuleMatch());
}

TEST_F(HybridDetectionServiceTest, highSeverityRule_highConfBenign_staysBenign) {
    EXPECT_CALL(mockTi_, lookup(std::string_view("192.168.1.10")))
        .WillOnce(Return(ThreatIntelLookup{false, ""}));
    EXPECT_CALL(mockTi_, lookup(std::string_view("10.0.0.1")))
        .WillOnce(Return(ThreatIntelLookup{false, ""}));

    std::vector<HeuristicRuleResult> ruleMatches = {
        {"syn_flood", "SYN flood detected", 0.85f}
    };
    EXPECT_CALL(mockRules_, evaluate(_)).WillOnce(Return(ruleMatches));

    HybridDetectionService service(&mockTi_, &mockRules_);

    auto pred = makePrediction(AttackType::Benign, 0.95f); // high confidence
    auto flow = makeBenignFlowMeta();
    auto result = service.evaluate(pred, "192.168.1.10", "10.0.0.1", flow);

    // ML high confidence benign overrides rules
    EXPECT_EQ(result.finalVerdict, AttackType::Benign);
}

// ── Detection source ─────────────────────────────────────────────────

TEST_F(HybridDetectionServiceTest, detectionSource_mlOnly_whenNoOtherSignals) {
    HybridDetectionService service(nullptr, nullptr);

    auto pred = makePrediction(AttackType::PortScanning, 0.9f);
    auto result = service.evaluate(pred, "192.168.1.10", "10.0.0.1");

    EXPECT_EQ(result.detectionSource, DetectionSource::MlOnly);
}

TEST_F(HybridDetectionServiceTest, detectionSource_noneForBenign) {
    HybridDetectionService service(nullptr, nullptr);

    auto pred = makePrediction(AttackType::Benign, 0.99f);
    auto result = service.evaluate(pred, "192.168.1.10", "10.0.0.1");

    EXPECT_EQ(result.detectionSource, DetectionSource::None);
}

// ── Weight configuration ─────────────────────────────────────────────

TEST_F(HybridDetectionServiceTest, setWeights_affectsCombinedScore) {
    EXPECT_CALL(mockTi_, lookup(std::string_view("192.168.1.10")))
        .WillRepeatedly(Return(ThreatIntelLookup{true, "feodo"}));
    EXPECT_CALL(mockTi_, lookup(std::string_view("10.0.0.1")))
        .WillRepeatedly(Return(ThreatIntelLookup{false, ""}));

    HybridDetectionService service(&mockTi_, nullptr);

    auto pred = makePrediction(AttackType::DdosIcmp, 0.8f);

    // Default weights
    auto result1 = service.evaluate(pred, "192.168.1.10", "10.0.0.1");
    float score1 = result1.combinedScore;

    // Change weights to heavily favor TI
    HybridDetectionService::Weights weights;
    weights.ml = 0.1f;
    weights.threatIntel = 0.8f;
    weights.heuristic = 0.1f;
    service.setWeights(weights);

    auto result2 = service.evaluate(pred, "192.168.1.10", "10.0.0.1");
    float score2 = result2.combinedScore;

    // Scores should differ due to different weights
    EXPECT_NE(score1, score2);
}

// ── Confidence threshold ─────────────────────────────────────────────

TEST_F(HybridDetectionServiceTest, combinedScore_inValidRange) {
    HybridDetectionService service(nullptr, nullptr);

    auto pred = makePrediction(AttackType::SynFlood, 0.75f);
    auto result = service.evaluate(pred, "10.0.0.1", "10.0.0.2");

    EXPECT_GE(result.combinedScore, 0.0f);
    EXPECT_LE(result.combinedScore, 1.0f);
}

// ── Ensemble (all three layers) ──────────────────────────────────────

TEST_F(HybridDetectionServiceTest, allThreeLayers_detectionSourceIsEnsemble) {
    // TI match
    EXPECT_CALL(mockTi_, lookup(std::string_view("192.168.1.10")))
        .WillOnce(Return(ThreatIntelLookup{true, "feodo"}));
    EXPECT_CALL(mockTi_, lookup(std::string_view("10.0.0.1")))
        .WillOnce(Return(ThreatIntelLookup{false, ""}));

    // Rule match
    std::vector<HeuristicRuleResult> ruleMatches = {
        {"suspicious_port", "Port 4444", 0.6f}
    };
    EXPECT_CALL(mockRules_, evaluate(_)).WillOnce(Return(ruleMatches));

    HybridDetectionService service(&mockTi_, &mockRules_);

    // ML attack
    auto pred = makePrediction(AttackType::DdosIcmp, 0.9f);
    auto flow = makeBenignFlowMeta();
    auto result = service.evaluate(pred, "192.168.1.10", "10.0.0.1", flow);

    EXPECT_EQ(result.detectionSource, DetectionSource::Ensemble);
    EXPECT_TRUE(result.hasThreatIntelMatch());
    EXPECT_TRUE(result.hasRuleMatch());
    EXPECT_EQ(result.finalVerdict, AttackType::DdosIcmp);
}
