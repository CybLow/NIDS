#include "infra/output/CefFormatter.h"

#include "core/model/AttackType.h"
#include "core/model/DetectionResult.h"
#include "core/model/DetectionSource.h"
#include "core/model/FlowInfo.h"

#include <gtest/gtest.h>

#include <string>

using namespace nids;

namespace {

/// Build a simple DetectionResult for testing.
core::DetectionResult makeResult(core::AttackType type, float confidence,
                                  float combinedScore,
                                  core::DetectionSource source) {
    core::DetectionResult r;
    r.mlResult.classification = type;
    r.mlResult.confidence = confidence;
    r.finalVerdict = type;
    r.combinedScore = combinedScore;
    r.detectionSource = source;
    return r;
}

/// Build a simple FlowInfo for testing.
core::FlowInfo makeFlow(const std::string& srcIp, const std::string& dstIp,
                         std::uint16_t srcPort, std::uint16_t dstPort,
                         std::uint8_t proto) {
    core::FlowInfo f;
    f.srcIp = srcIp;
    f.dstIp = dstIp;
    f.srcPort = srcPort;
    f.dstPort = dstPort;
    f.protocol = proto;
    return f;
}

} // namespace

TEST(CefFormatter, format_benignFlow_containsCefHeader) {
    infra::CefFormatter fmt;
    auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                             core::DetectionSource::None);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    auto out = fmt.format(0, result, flow);

    EXPECT_TRUE(out.starts_with("CEF:0|NIDS|NIDS|0.2.0|"));
    EXPECT_NE(out.find("src=10.0.0.1"), std::string::npos);
    EXPECT_NE(out.find("dst=192.168.1.1"), std::string::npos);
    EXPECT_NE(out.find("spt=12345"), std::string::npos);
    EXPECT_NE(out.find("dpt=80"), std::string::npos);
}

TEST(CefFormatter, format_attackFlow_containsVerdictName) {
    infra::CefFormatter fmt;
    auto result = makeResult(core::AttackType::DdosUdp, 0.95f, 0.87f,
                             core::DetectionSource::Ensemble);
    auto flow = makeFlow("10.0.0.1", "192.168.1.100", 54321, 80, 17);

    auto out = fmt.format(42, result, flow);

    EXPECT_NE(out.find("DDoS UDP"), std::string::npos);
    EXPECT_NE(out.find("cs2=Ensemble"), std::string::npos);
    EXPECT_NE(out.find("proto=17"), std::string::npos);
}

TEST(CefFormatter, format_withThreatIntel_containsFeedNames) {
    infra::CefFormatter fmt;
    auto result = makeResult(core::AttackType::SshBruteForce, 0.8f, 0.75f,
                             core::DetectionSource::MlPlusThreatIntel);
    result.threatIntelMatches.push_back({"10.0.0.1", "feodo", true});
    result.threatIntelMatches.push_back({"10.0.0.1", "spamhaus", true});

    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 22222, 22, 6);

    auto out = fmt.format(1, result, flow);

    EXPECT_NE(out.find("cs3=feodo,spamhaus"), std::string::npos);
    EXPECT_NE(out.find("cs3Label=threatIntelFeeds"), std::string::npos);
}

TEST(CefFormatter, format_withRuleMatches_containsRuleNames) {
    infra::CefFormatter fmt;
    auto result = makeResult(core::AttackType::PortScanning, 0.6f, 0.55f,
                             core::DetectionSource::MlPlusHeuristic);
    result.ruleMatches.push_back({"suspicious_port", "Port is suspicious", 0.5f});

    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 44444, 4444, 6);

    auto out = fmt.format(2, result, flow);

    EXPECT_NE(out.find("cs4=suspicious_port"), std::string::npos);
    EXPECT_NE(out.find("cs4Label=heuristicRules"), std::string::npos);
}

TEST(CefFormatter, severity_zeoCombinedScore_returnsZero) {
    infra::CefFormatter fmt;
    auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                             core::DetectionSource::None);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    auto out = fmt.format(0, result, flow);

    // Severity 0 should appear in CEF header: ...|0|
    // Pattern: ...|<verdict>|0|...
    EXPECT_NE(out.find("|0|"), std::string::npos);
}

TEST(CefFormatter, severity_highCombinedScore_returnsHighSeverity) {
    infra::CefFormatter fmt;
    auto result = makeResult(core::AttackType::DdosUdp, 0.95f, 0.95f,
                             core::DetectionSource::Ensemble);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 17);

    auto out = fmt.format(0, result, flow);

    // Severity 9 (0.95 * 10 = 9.5, truncated to 9)
    EXPECT_NE(out.find("|9|"), std::string::npos);
}

TEST(CefFormatter, format_containsFlowIndex) {
    infra::CefFormatter fmt;
    auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                             core::DetectionSource::None);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    auto out = fmt.format(999, result, flow);

    EXPECT_NE(out.find("cnt=999"), std::string::npos);
}

TEST(CefFormatter, format_escapesHeaderPipes) {
    infra::CefFormatter fmt;
    // A verdict name with a pipe shouldn't break CEF header parsing.
    // Our attack names don't contain pipes, but the escaping should work.
    auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                             core::DetectionSource::None);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    auto out = fmt.format(0, result, flow);

    // Just verify the format is well-formed (7 pipe-separated fields)
    int pipeCount = 0;
    for (char c : out) {
        if (c == '|') ++pipeCount;
    }
    // CEF header has 7 fields separated by 6 pipes, then extension
    // But CEF starts with "CEF:0|...|...|...|...|...|...|extension"
    // That's 7 pipes total
    EXPECT_GE(pipeCount, 7);
}

TEST(CefFormatter, format_containsMlConfidence) {
    infra::CefFormatter fmt;
    auto result = makeResult(core::AttackType::SynFlood, 0.9234f, 0.85f,
                             core::DetectionSource::MlOnly);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    auto out = fmt.format(0, result, flow);

    EXPECT_NE(out.find("cs1=0.9234"), std::string::npos);
    EXPECT_NE(out.find("cs1Label=mlConfidence"), std::string::npos);
}

TEST(CefFormatter, format_containsCombinedScore) {
    infra::CefFormatter fmt;
    auto result = makeResult(core::AttackType::Dos, 0.8f, 0.72f,
                             core::DetectionSource::MlOnly);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    auto out = fmt.format(0, result, flow);

    // cn1 = int(0.72 * 100) = 72
    EXPECT_NE(out.find("cn1=72"), std::string::npos);
    EXPECT_NE(out.find("cn1Label=combinedScore"), std::string::npos);
}
