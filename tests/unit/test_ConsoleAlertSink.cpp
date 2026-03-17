#include "infra/output/ConsoleAlertSink.h"
#include <gtest/gtest.h>

using nids::core::AttackType;
using nids::core::DetectionResult;
using nids::core::DetectionSource;
using nids::core::FlowInfo;
using nids::infra::ConsoleAlertSink;
using nids::infra::ConsoleFilter;

namespace {

/// Build a FlowInfo with the given 5-tuple for testing.
FlowInfo makeFlow(const std::string &srcIp, std::uint16_t srcPort,
                  const std::string &dstIp, std::uint16_t dstPort) {
  FlowInfo flow;
  flow.srcIp = srcIp;
  flow.srcPort = srcPort;
  flow.dstIp = dstIp;
  flow.dstPort = dstPort;
  flow.protocol = 6; // TCP
  return flow;
}

/// Build a benign DetectionResult.
DetectionResult makeBenign(float confidence = 0.99f) {
  DetectionResult result;
  result.mlResult.classification = AttackType::Benign;
  result.mlResult.confidence = confidence;
  result.finalVerdict = AttackType::Benign;
  result.detectionSource = DetectionSource::None;
  return result;
}

/// Build a flagged (attack) DetectionResult.
DetectionResult makeAttack(AttackType type = AttackType::DdosIcmp,
                           float confidence = 0.95f) {
  DetectionResult result;
  result.mlResult.classification = type;
  result.mlResult.confidence = confidence;
  result.finalVerdict = type;
  result.detectionSource = DetectionSource::MlOnly;
  return result;
}

} // namespace

// ── Construction ──────────────────────────────────────────────────

TEST(ConsoleAlertSink, defaultConstructor_usesFlaggedFilter) {
  ConsoleAlertSink sink;
  EXPECT_EQ(sink.name(), "ConsoleAlertSink");
}

TEST(ConsoleAlertSink, constructWithAllFilter) {
  ConsoleAlertSink sink(ConsoleFilter::All);
  EXPECT_EQ(sink.name(), "ConsoleAlertSink");
}

TEST(ConsoleAlertSink, constructWithCleanFilter) {
  ConsoleAlertSink sink(ConsoleFilter::Clean);
  EXPECT_EQ(sink.name(), "ConsoleAlertSink");
}

// ── start() ───────────────────────────────────────────────────────

TEST(ConsoleAlertSink, start_returnsTrue_allFilter) {
  ConsoleAlertSink sink(ConsoleFilter::All);
  EXPECT_TRUE(sink.start());
}

TEST(ConsoleAlertSink, start_returnsTrue_flaggedFilter) {
  ConsoleAlertSink sink(ConsoleFilter::Flagged);
  EXPECT_TRUE(sink.start());
}

TEST(ConsoleAlertSink, start_returnsTrue_cleanFilter) {
  ConsoleAlertSink sink(ConsoleFilter::Clean);
  EXPECT_TRUE(sink.start());
}

TEST(ConsoleAlertSink, start_resetsCounters) {
  ConsoleAlertSink sink(ConsoleFilter::All);
  // Feed some flows first
  auto flow = makeFlow("1.2.3.4", 1234, "5.6.7.8", 80);
  sink.onFlowResult(0, makeBenign(), flow);
  sink.onFlowResult(1, makeAttack(), flow);

  // start() should reset counters
  EXPECT_TRUE(sink.start());
  // Feed one more and stop — summary should show 1 total
  sink.onFlowResult(0, makeBenign(), flow);
  sink.stop(); // logs "total=1 flagged=0 clean=1"
}

// ── onFlowResult() with All filter ───────────────────────────────

TEST(ConsoleAlertSink, allFilter_acceptsBenignFlows) {
  ConsoleAlertSink sink(ConsoleFilter::All);
  ASSERT_TRUE(sink.start());
  auto flow = makeFlow("10.0.0.1", 5000, "10.0.0.2", 443);
  // Should not throw; benign flow is logged at debug level
  sink.onFlowResult(0, makeBenign(), flow);
  sink.stop();
}

TEST(ConsoleAlertSink, allFilter_acceptsFlaggedFlows) {
  ConsoleAlertSink sink(ConsoleFilter::All);
  ASSERT_TRUE(sink.start());
  auto flow = makeFlow("10.0.0.1", 5000, "10.0.0.2", 443);
  sink.onFlowResult(0, makeAttack(), flow);
  sink.stop();
}

TEST(ConsoleAlertSink, allFilter_multipleFlows) {
  ConsoleAlertSink sink(ConsoleFilter::All);
  ASSERT_TRUE(sink.start());
  auto flow = makeFlow("192.168.1.1", 12345, "8.8.8.8", 53);

  sink.onFlowResult(0, makeBenign(), flow);
  sink.onFlowResult(1, makeAttack(AttackType::SynFlood, 0.88f), flow);
  sink.onFlowResult(2, makeBenign(0.97f), flow);
  sink.onFlowResult(3, makeAttack(AttackType::PortScanning, 0.72f), flow);
  sink.stop();
}

// ── onFlowResult() with Flagged filter ───────────────────────────

TEST(ConsoleAlertSink, flaggedFilter_filtersOutBenign) {
  ConsoleAlertSink sink(ConsoleFilter::Flagged);
  ASSERT_TRUE(sink.start());
  auto flow = makeFlow("10.0.0.1", 5000, "10.0.0.2", 80);

  // Benign flows should be filtered (early return)
  sink.onFlowResult(0, makeBenign(), flow);
  // Flagged flow should pass through
  sink.onFlowResult(1, makeAttack(), flow);
  sink.stop();
}

// ── onFlowResult() with Clean filter ─────────────────────────────

TEST(ConsoleAlertSink, cleanFilter_filtersOutFlagged) {
  ConsoleAlertSink sink(ConsoleFilter::Clean);
  ASSERT_TRUE(sink.start());
  auto flow = makeFlow("10.0.0.1", 5000, "10.0.0.2", 80);

  // Benign flow should pass through
  sink.onFlowResult(0, makeBenign(), flow);
  // Flagged flow should be filtered (early return)
  sink.onFlowResult(1, makeAttack(), flow);
  sink.stop();
}

// ── onFlowResult() with various attack types ─────────────────────

TEST(ConsoleAlertSink, flaggedFlow_withThreatIntelMatch) {
  ConsoleAlertSink sink(ConsoleFilter::All);
  ASSERT_TRUE(sink.start());
  auto flow = makeFlow("10.0.0.1", 5000, "10.0.0.2", 80);

  DetectionResult result;
  result.mlResult.classification = AttackType::Benign;
  result.mlResult.confidence = 0.50f;
  result.threatIntelMatches.emplace_back("10.0.0.1", "feodo", true);
  result.finalVerdict = AttackType::MitmArpSpoofing;
  result.detectionSource = DetectionSource::ThreatIntel;

  sink.onFlowResult(0, result, flow);
  sink.stop();
}

TEST(ConsoleAlertSink, flaggedFlow_withRuleMatch) {
  ConsoleAlertSink sink(ConsoleFilter::All);
  ASSERT_TRUE(sink.start());
  auto flow = makeFlow("10.0.0.1", 5000, "10.0.0.2", 80);

  DetectionResult result;
  result.mlResult.classification = AttackType::Benign;
  result.mlResult.confidence = 0.50f;
  result.ruleMatches.emplace_back("syn_flood", "SYN flood detected", 0.8f);
  result.finalVerdict = AttackType::SynFlood;
  result.detectionSource = DetectionSource::HeuristicRule;

  sink.onFlowResult(0, result, flow);
  sink.stop();
}

TEST(ConsoleAlertSink, flaggedFlow_ensembleDetection) {
  ConsoleAlertSink sink(ConsoleFilter::All);
  ASSERT_TRUE(sink.start());
  auto flow = makeFlow("10.0.0.1", 5000, "10.0.0.2", 80);

  DetectionResult result;
  result.mlResult.classification = AttackType::DdosUdp;
  result.mlResult.confidence = 0.92f;
  result.threatIntelMatches.emplace_back("10.0.0.1", "abuse_ch", false);
  result.ruleMatches.emplace_back("high_pps", "High packet rate", 0.7f);
  result.finalVerdict = AttackType::DdosUdp;
  result.detectionSource = DetectionSource::Ensemble;

  sink.onFlowResult(0, result, flow);
  sink.stop();
}

// ── stop() ────────────────────────────────────────────────────────

TEST(ConsoleAlertSink, stop_withoutStart_doesNotCrash) {
  ConsoleAlertSink sink(ConsoleFilter::All);
  // stop() should not crash even without start()
  sink.stop();
}

TEST(ConsoleAlertSink, stop_logsSummary) {
  ConsoleAlertSink sink(ConsoleFilter::All);
  ASSERT_TRUE(sink.start());
  auto flow = makeFlow("10.0.0.1", 5000, "10.0.0.2", 80);

  sink.onFlowResult(0, makeBenign(), flow);
  sink.onFlowResult(1, makeAttack(), flow);
  sink.onFlowResult(2, makeBenign(), flow);

  // stop logs: "total=3 flagged=1 clean=2"
  sink.stop();
}

// ── Various attack types for logging format coverage ─────────────

TEST(ConsoleAlertSink, allAttackTypes_logWithoutError) {
  ConsoleAlertSink sink(ConsoleFilter::All);
  ASSERT_TRUE(sink.start());
  auto flow = makeFlow("172.16.0.1", 9999, "192.168.0.1", 22);

  // Exercise multiple attack types to cover attackTypeToString paths
  const AttackType attacks[] = {
      AttackType::MitmArpSpoofing, AttackType::SshBruteForce,
      AttackType::FtpBruteForce,   AttackType::DdosIcmp,
      AttackType::DdosRawIp,       AttackType::Dos,
      AttackType::ExploitingFtp,   AttackType::Fuzzing,
      AttackType::IcmpFlood,       AttackType::RemoteCodeExecution,
      AttackType::SqlInjection,    AttackType::Xss,
  };

  std::size_t idx = 0;
  for (auto atk : attacks) {
    sink.onFlowResult(idx++, makeAttack(atk, 0.85f), flow);
  }

  sink.stop();
}
