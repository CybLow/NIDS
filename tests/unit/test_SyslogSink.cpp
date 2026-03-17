#include "infra/output/SyslogSink.h"

#include "core/model/AttackType.h"
#include "core/model/DetectionResult.h"
#include "core/model/DetectionSource.h"
#include "core/model/FlowInfo.h"

#include <gtest/gtest.h>

#include <string>

using namespace nids;

namespace {

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

// Test formatting only — no real socket connection.

TEST(SyslogSink, formatMessage_rfc5424_containsStructuredData) {
    infra::SyslogConfig cfg;
    cfg.format = infra::SyslogFormat::Rfc5424;
    cfg.hostname = "test-host";

    infra::SyslogSink sink(std::move(cfg));

    auto result = makeResult(core::AttackType::DdosUdp, 0.95f, 0.87f,
                             core::DetectionSource::Ensemble);
    auto flow = makeFlow("10.0.0.1", "192.168.1.100", 54321, 80, 17);

    auto msg = sink.formatMessage(42, result, flow);

    // Should contain structured data element
    EXPECT_NE(msg.find("[nids@49999"), std::string::npos);
    EXPECT_NE(msg.find("srcIp=\"10.0.0.1\""), std::string::npos);
    EXPECT_NE(msg.find("dstIp=\"192.168.1.100\""), std::string::npos);
    EXPECT_NE(msg.find("srcPort=\"54321\""), std::string::npos);
    EXPECT_NE(msg.find("dstPort=\"80\""), std::string::npos);
    EXPECT_NE(msg.find("verdict=\"DDoS UDP\""), std::string::npos);
}

TEST(SyslogSink, formatMessage_rfc5424_containsHostname) {
    infra::SyslogConfig cfg;
    cfg.format = infra::SyslogFormat::Rfc5424;
    cfg.hostname = "my-nids-box";

    infra::SyslogSink sink(std::move(cfg));

    auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                             core::DetectionSource::None);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    auto msg = sink.formatMessage(0, result, flow);

    EXPECT_NE(msg.find("my-nids-box"), std::string::npos);
}

TEST(SyslogSink, formatMessage_rfc5424_containsProtocol) {
    infra::SyslogConfig cfg;
    cfg.format = infra::SyslogFormat::Rfc5424;
    cfg.hostname = "test-host";

    infra::SyslogSink sink(std::move(cfg));

    auto result = makeResult(core::AttackType::SshBruteForce, 0.8f, 0.65f,
                             core::DetectionSource::MlOnly);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 22222, 22, 6);

    auto msg = sink.formatMessage(1, result, flow);

    EXPECT_NE(msg.find("protocol=\"TCP\""), std::string::npos);
}

TEST(SyslogSink, formatMessage_rfc5424_containsTiMatches) {
    infra::SyslogConfig cfg;
    cfg.format = infra::SyslogFormat::Rfc5424;
    cfg.hostname = "test-host";

    infra::SyslogSink sink(std::move(cfg));

    auto result = makeResult(core::AttackType::SshBruteForce, 0.8f, 0.75f,
                             core::DetectionSource::MlPlusThreatIntel);
    result.threatIntelMatches.push_back({"10.0.0.1", "feodo", true});

    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 22222, 22, 6);

    auto msg = sink.formatMessage(1, result, flow);

    EXPECT_NE(msg.find("tiMatches=\"feodo\""), std::string::npos);
}

TEST(SyslogSink, formatMessage_rfc5424_containsRuleMatches) {
    infra::SyslogConfig cfg;
    cfg.format = infra::SyslogFormat::Rfc5424;
    cfg.hostname = "test-host";

    infra::SyslogSink sink(std::move(cfg));

    auto result = makeResult(core::AttackType::PortScanning, 0.6f, 0.55f,
                             core::DetectionSource::MlPlusHeuristic);
    result.ruleMatches.push_back({"suspicious_port", "Port is suspicious", 0.5f});

    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 44444, 4444, 6);

    auto msg = sink.formatMessage(2, result, flow);

    EXPECT_NE(msg.find("ruleMatches=\"suspicious_port\""), std::string::npos);
}

TEST(SyslogSink, formatMessage_cef_returnsCefFormat) {
    infra::SyslogConfig cfg;
    cfg.format = infra::SyslogFormat::Cef;
    cfg.hostname = "test-host";

    infra::SyslogSink sink(std::move(cfg));

    auto result = makeResult(core::AttackType::DdosUdp, 0.95f, 0.87f,
                             core::DetectionSource::Ensemble);
    auto flow = makeFlow("10.0.0.1", "192.168.1.100", 54321, 80, 17);

    auto msg = sink.formatMessage(1, result, flow);

    EXPECT_TRUE(msg.starts_with("CEF:0|"));
}

TEST(SyslogSink, formatMessage_leef_returnsLeefFormat) {
    infra::SyslogConfig cfg;
    cfg.format = infra::SyslogFormat::Leef;
    cfg.hostname = "test-host";

    infra::SyslogSink sink(std::move(cfg));

    auto result = makeResult(core::AttackType::DdosUdp, 0.95f, 0.87f,
                             core::DetectionSource::Ensemble);
    auto flow = makeFlow("10.0.0.1", "192.168.1.100", 54321, 80, 17);

    auto msg = sink.formatMessage(1, result, flow);

    EXPECT_TRUE(msg.starts_with("LEEF:2.0|"));
}

TEST(SyslogSink, severity_lowScore_returnsInformational) {
    infra::SyslogConfig cfg;
    cfg.format = infra::SyslogFormat::Rfc5424;
    cfg.hostname = "test-host";

    infra::SyslogSink sink(std::move(cfg));

    auto result = makeResult(core::AttackType::Benign, 0.99f, 0.1f,
                             core::DetectionSource::None);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    auto msg = sink.formatMessage(0, result, flow);

    // PRI = facility*8 + severity. facility=16, severity=6 (info) → PRI=134
    EXPECT_TRUE(msg.starts_with("<134>"));
}

TEST(SyslogSink, severity_highScore_returnsCritical) {
    infra::SyslogConfig cfg;
    cfg.format = infra::SyslogFormat::Rfc5424;
    cfg.hostname = "test-host";

    infra::SyslogSink sink(std::move(cfg));

    auto result = makeResult(core::AttackType::DdosUdp, 0.99f, 0.9f,
                             core::DetectionSource::Ensemble);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 17);

    auto msg = sink.formatMessage(0, result, flow);

    // PRI = 16*8 + 2 (critical) = 130
    EXPECT_TRUE(msg.starts_with("<130>"));
}

TEST(SyslogSink, severity_mediumScore_returnsWarning) {
    infra::SyslogConfig cfg;
    cfg.format = infra::SyslogFormat::Rfc5424;
    cfg.hostname = "test-host";

    infra::SyslogSink sink(std::move(cfg));

    auto result = makeResult(core::AttackType::Fuzzing, 0.7f, 0.6f,
                             core::DetectionSource::MlOnly);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    auto msg = sink.formatMessage(0, result, flow);

    // PRI = 16*8 + 4 (warning) = 132
    EXPECT_TRUE(msg.starts_with("<132>"));
}

TEST(SyslogSink, name_returnsSyslogSink) {
    infra::SyslogConfig cfg;
    infra::SyslogSink sink(std::move(cfg));

    EXPECT_EQ(sink.name(), "SyslogSink");
}

TEST(SyslogSink, formatMessage_rfc5424_containsFlowIndex) {
    infra::SyslogConfig cfg;
    cfg.format = infra::SyslogFormat::Rfc5424;
    cfg.hostname = "test-host";

    infra::SyslogSink sink(std::move(cfg));

    auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                             core::DetectionSource::None);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    auto msg = sink.formatMessage(123, result, flow);

    EXPECT_NE(msg.find("flow #123"), std::string::npos);
}

TEST(SyslogSink, formatMessage_rfc5424_containsDetectionSource) {
    infra::SyslogConfig cfg;
    cfg.format = infra::SyslogFormat::Rfc5424;
    cfg.hostname = "test-host";

    infra::SyslogSink sink(std::move(cfg));

    auto result = makeResult(core::AttackType::SshBruteForce, 0.85f, 0.78f,
                             core::DetectionSource::MlOnly);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 22222, 22, 6);

    auto msg = sink.formatMessage(0, result, flow);

    EXPECT_NE(msg.find("detectionSource=\"ML Classifier\""), std::string::npos);
}
