#include "infra/output/SyslogSink.h"

#include "core/model/AttackType.h"
#include "core/model/DetectionResult.h"
#include "core/model/DetectionSource.h"
#include "core/model/FlowInfo.h"

#include <gtest/gtest.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <array>
#include <cstring>
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

core::FlowInfo makeFlow(const std::string &srcIp, const std::string &dstIp,
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

TEST(SyslogSink, stop_beforeStart_isNoOp) {
  infra::SyslogConfig cfg;
  cfg.hostname = "test-host";
  infra::SyslogSink sink(std::move(cfg));

  // stop() on a non-started sink should not crash.
  EXPECT_NO_THROW(sink.stop());
}

TEST(SyslogSink, destructor_beforeStart_isNoOp) {
  // Destructor calls stop(), which should be safe on a non-started sink.
  EXPECT_NO_THROW({
    infra::SyslogConfig cfg;
    cfg.hostname = "test-host";
    infra::SyslogSink sink(std::move(cfg));
  });
}

TEST(SyslogSink, onFlowResult_beforeStart_isNoOp) {
  infra::SyslogConfig cfg;
  cfg.hostname = "test-host";
  infra::SyslogSink sink(std::move(cfg));

  auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                           core::DetectionSource::None);
  auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

  // onFlowResult formats + tries to send; send returns immediately
  // when socket is invalid.
  EXPECT_NO_THROW(sink.onFlowResult(0, result, flow));
}

TEST(SyslogSink, severity_noticeBand_returnsNotice) {
  infra::SyslogConfig cfg;
  cfg.format = infra::SyslogFormat::Rfc5424;
  cfg.hostname = "test-host";

  infra::SyslogSink sink(std::move(cfg));

  auto result = makeResult(core::AttackType::Dos, 0.5f, 0.4f,
                           core::DetectionSource::MlOnly);
  auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

  auto msg = sink.formatMessage(0, result, flow);

  // PRI = 16*8 + 5 (notice) = 133
  EXPECT_TRUE(msg.starts_with("<133>"));
}

TEST(SyslogSink, severity_errorBand_returnsError) {
  infra::SyslogConfig cfg;
  cfg.format = infra::SyslogFormat::Rfc5424;
  cfg.hostname = "test-host";

  infra::SyslogSink sink(std::move(cfg));

  auto result = makeResult(core::AttackType::DdosUdp, 0.9f, 0.75f,
                           core::DetectionSource::MlOnly);
  auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 17);

  auto msg = sink.formatMessage(0, result, flow);

  // PRI = 16*8 + 3 (error) = 131
  EXPECT_TRUE(msg.starts_with("<131>"));
}

TEST(SyslogSink, formatMessage_rfc5424_containsAppName) {
  infra::SyslogConfig cfg;
  cfg.format = infra::SyslogFormat::Rfc5424;
  cfg.hostname = "test-host";
  cfg.appName = "my-nids-app";

  infra::SyslogSink sink(std::move(cfg));

  auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                           core::DetectionSource::None);
  auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

  auto msg = sink.formatMessage(0, result, flow);

  EXPECT_NE(msg.find("my-nids-app"), std::string::npos);
}

TEST(SyslogSink, formatMessage_rfc5424_containsConfidence) {
  infra::SyslogConfig cfg;
  cfg.format = infra::SyslogFormat::Rfc5424;
  cfg.hostname = "test-host";

  infra::SyslogSink sink(std::move(cfg));

  auto result = makeResult(core::AttackType::SynFlood, 0.9234f, 0.85f,
                           core::DetectionSource::MlOnly);
  auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

  auto msg = sink.formatMessage(0, result, flow);

  EXPECT_NE(msg.find("confidence=\"0.9234\""), std::string::npos);
  EXPECT_NE(msg.find("combinedScore=\"0.8500\""), std::string::npos);
}

TEST(SyslogSink, formatMessage_rfc5424_multipleRulesCommaSeparated) {
  infra::SyslogConfig cfg;
  cfg.format = infra::SyslogFormat::Rfc5424;
  cfg.hostname = "test-host";

  infra::SyslogSink sink(std::move(cfg));

  auto result = makeResult(core::AttackType::PortScanning, 0.6f, 0.55f,
                           core::DetectionSource::MlPlusHeuristic);
  result.ruleMatches.push_back({"rule_a", "Rule A", 0.3f});
  result.ruleMatches.push_back({"rule_b", "Rule B", 0.5f});

  auto flow = makeFlow("10.0.0.1", "192.168.1.1", 44444, 4444, 6);

  auto msg = sink.formatMessage(0, result, flow);

  EXPECT_NE(msg.find("ruleMatches=\"rule_a,rule_b\""), std::string::npos);
}

TEST(SyslogSink, formatMessage_rfc5424_multipleTiMatchesCommaSeparated) {
  infra::SyslogConfig cfg;
  cfg.format = infra::SyslogFormat::Rfc5424;
  cfg.hostname = "test-host";

  infra::SyslogSink sink(std::move(cfg));

  auto result = makeResult(core::AttackType::SshBruteForce, 0.8f, 0.75f,
                           core::DetectionSource::MlPlusThreatIntel);
  result.threatIntelMatches.push_back({"10.0.0.1", "feodo", true});
  result.threatIntelMatches.push_back({"10.0.0.1", "spamhaus", true});

  auto flow = makeFlow("10.0.0.1", "192.168.1.1", 22222, 22, 6);

  auto msg = sink.formatMessage(0, result, flow);

  EXPECT_NE(msg.find("tiMatches=\"feodo,spamhaus\""), std::string::npos);
}

// ── UDP loopback tests — exercise start/send/stop with a real socket ──
#ifndef _WIN32

namespace {

/// RAII helper: opens a UDP socket bound to loopback on an ephemeral port.
/// The test reads received datagrams from this socket to verify SyslogSink sent
/// them.
struct UdpReceiver {
  int fd = -1;
  std::uint16_t port = 0;

  UdpReceiver() {
    fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    EXPECT_NE(fd, -1);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; // OS picks an ephemeral port

    EXPECT_EQ(::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)), 0);

    socklen_t len = sizeof(addr);
    ::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len);
    port = ntohs(addr.sin_port);
  }

  ~UdpReceiver() {
    if (fd >= 0)
      ::close(fd);
  }

  /// Read one datagram (up to 4096 bytes). Returns empty string on failure.
  [[nodiscard]] std::string receive() const {
    std::array<char, 4096> buf{};
    timeval tv{};
    tv.tv_sec = 2;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    auto n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0)
      return {};
    return {buf.data(), static_cast<std::size_t>(n)};
  }

  UdpReceiver(const UdpReceiver &) = delete;
  UdpReceiver &operator=(const UdpReceiver &) = delete;
};

} // namespace

TEST(SyslogSink, startUdp_sendsMessageToReceiver) {
  UdpReceiver receiver;

  infra::SyslogConfig cfg;
  cfg.host = "127.0.0.1";
  cfg.port = receiver.port;
  cfg.transport = infra::SyslogTransport::Udp;
  cfg.format = infra::SyslogFormat::Rfc5424;
  cfg.hostname = "test-host";

  infra::SyslogSink sink(std::move(cfg));
  ASSERT_TRUE(sink.start());

  auto result = makeResult(core::AttackType::DdosUdp, 0.95f, 0.87f,
                           core::DetectionSource::Ensemble);
  auto flow = makeFlow("10.0.0.1", "192.168.1.100", 54321, 80, 17);

  sink.onFlowResult(0, result, flow);

  auto received = receiver.receive();
  EXPECT_FALSE(received.empty());
  EXPECT_NE(received.find("[nids@49999"), std::string::npos);
  EXPECT_NE(received.find("DDoS UDP"), std::string::npos);

  sink.stop();
}

TEST(SyslogSink, startUdp_multipleMessages_allReceived) {
  UdpReceiver receiver;

  infra::SyslogConfig cfg;
  cfg.host = "127.0.0.1";
  cfg.port = receiver.port;
  cfg.transport = infra::SyslogTransport::Udp;
  cfg.format = infra::SyslogFormat::Rfc5424;
  cfg.hostname = "test-host";

  infra::SyslogSink sink(std::move(cfg));
  ASSERT_TRUE(sink.start());

  auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                           core::DetectionSource::None);
  auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

  sink.onFlowResult(0, result, flow);
  sink.onFlowResult(1, result, flow);
  sink.onFlowResult(2, result, flow);

  for (int i = 0; i < 3; ++i) {
    auto msg = receiver.receive();
    EXPECT_FALSE(msg.empty()) << "Failed to receive message " << i;
  }

  sink.stop();
}

TEST(SyslogSink, startUdp_cefFormat_sendsCefMessage) {
  UdpReceiver receiver;

  infra::SyslogConfig cfg;
  cfg.host = "127.0.0.1";
  cfg.port = receiver.port;
  cfg.transport = infra::SyslogTransport::Udp;
  cfg.format = infra::SyslogFormat::Cef;
  cfg.hostname = "test-host";

  infra::SyslogSink sink(std::move(cfg));
  ASSERT_TRUE(sink.start());

  auto result = makeResult(core::AttackType::SynFlood, 0.9f, 0.85f,
                           core::DetectionSource::MlOnly);
  auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

  sink.onFlowResult(0, result, flow);

  auto received = receiver.receive();
  EXPECT_TRUE(received.starts_with("CEF:0|"));

  sink.stop();
}

TEST(SyslogSink, startUdp_leefFormat_sendsLeefMessage) {
  UdpReceiver receiver;

  infra::SyslogConfig cfg;
  cfg.host = "127.0.0.1";
  cfg.port = receiver.port;
  cfg.transport = infra::SyslogTransport::Udp;
  cfg.format = infra::SyslogFormat::Leef;
  cfg.hostname = "test-host";

  infra::SyslogSink sink(std::move(cfg));
  ASSERT_TRUE(sink.start());

  auto result = makeResult(core::AttackType::DdosIcmp, 0.88f, 0.72f,
                           core::DetectionSource::MlOnly);
  auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 1);

  sink.onFlowResult(0, result, flow);

  auto received = receiver.receive();
  EXPECT_TRUE(received.starts_with("LEEF:2.0|"));

  sink.stop();
}

TEST(SyslogSink, startUdp_stopThenDestruct_noDoubleFree) {
  UdpReceiver receiver;

  infra::SyslogConfig cfg;
  cfg.host = "127.0.0.1";
  cfg.port = receiver.port;
  cfg.transport = infra::SyslogTransport::Udp;
  cfg.hostname = "test-host";

  EXPECT_NO_THROW({
    infra::SyslogSink sink(std::move(cfg));
    ASSERT_TRUE(sink.start());
    sink.stop();
    // Destructor calls stop() again — should be a no-op.
  });
}

TEST(SyslogSink, resolveHostname_emptyHostname_autoDetects) {
  UdpReceiver receiver;

  infra::SyslogConfig cfg;
  cfg.host = "127.0.0.1";
  cfg.port = receiver.port;
  cfg.transport = infra::SyslogTransport::Udp;
  cfg.format = infra::SyslogFormat::Rfc5424;
  cfg.hostname = ""; // Empty — should be auto-detected

  infra::SyslogSink sink(std::move(cfg));
  ASSERT_TRUE(sink.start());

  auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                           core::DetectionSource::None);
  auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

  sink.onFlowResult(0, result, flow);

  auto received = receiver.receive();
  EXPECT_FALSE(received.empty());
  EXPECT_NE(received.find("[nids@49999"), std::string::npos);

  sink.stop();
}

TEST(SyslogSink, start_unreachableHost_returnsFalse) {
  infra::SyslogConfig cfg;
  cfg.host = "invalid.host.that.does.not.exist.example";
  cfg.port = 514;
  cfg.transport = infra::SyslogTransport::Tcp;
  cfg.hostname = "test-host";

  infra::SyslogSink sink(std::move(cfg));

  // TCP connect to unresolvable host should fail
  EXPECT_FALSE(sink.start());
}

#endif // !_WIN32
