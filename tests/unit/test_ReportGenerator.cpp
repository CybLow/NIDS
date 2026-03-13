#include <gtest/gtest.h>
#include "app/ReportGenerator.h"
#include "core/model/CaptureSession.h"

#include <filesystem>
#include <fstream>
#include <string>

using nids::app::ReportGenerator;
using nids::core::CaptureSession;
using nids::core::PacketInfo;
using nids::core::AttackType;
using nids::core::DetectionResult;

namespace fs = std::filesystem;

class ReportGeneratorTest : public ::testing::Test {
protected:
    const std::string testReportPath = "test_report.txt";

    void TearDown() override {
        std::error_code ec;
        fs::remove(testReportPath, ec);
    }
};

TEST_F(ReportGeneratorTest, generatesFileSuccessfully) {
    CaptureSession session;
    PacketInfo pkt;
    pkt.protocol = "TCP";
    pkt.ipSource = "192.168.1.1";
    pkt.ipDestination = "10.0.0.1";
    pkt.portSource = "12345";
    pkt.portDestination = "443";
    pkt.application = "HTTPS";
    session.addPacket(pkt);
    DetectionResult detection;
    detection.finalVerdict = AttackType::Benign;
    session.setDetectionResult(0, detection);

    auto result = ReportGenerator::generate(session, testReportPath, "eth0");
    EXPECT_TRUE(result.success);
    EXPECT_TRUE(fs::exists(testReportPath));
    EXPECT_GT(result.generationTimeMs, -1);
}

TEST_F(ReportGeneratorTest, reportContainsPacketData) {
    CaptureSession session;
    PacketInfo pkt;
    pkt.protocol = "UDP";
    pkt.ipSource = "10.0.0.5";
    pkt.ipDestination = "8.8.8.8";
    pkt.portSource = "4567";
    pkt.portDestination = "53";
    pkt.application = "DNS";
    session.addPacket(pkt);
    DetectionResult detection;
    detection.finalVerdict = AttackType::DdosIcmp;
    session.setDetectionResult(0, detection);

    auto result = ReportGenerator::generate(session, testReportPath);
    ASSERT_TRUE(result.success);

    std::ifstream file(testReportPath);
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());

    EXPECT_NE(content.find("UDP"), std::string::npos);
    EXPECT_NE(content.find("10.0.0.5"), std::string::npos);
    EXPECT_NE(content.find("8.8.8.8"), std::string::npos);
    EXPECT_NE(content.find("53"), std::string::npos);
    EXPECT_NE(content.find("DNS"), std::string::npos);
    EXPECT_NE(content.find("DDoS ICMP"), std::string::npos);
}

TEST_F(ReportGeneratorTest, emptySessionGeneratesHeader) {
    CaptureSession session;
    auto result = ReportGenerator::generate(session, testReportPath);
    ASSERT_TRUE(result.success);

    std::ifstream file(testReportPath);
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());

    EXPECT_NE(content.find("NIDS Capture Report"), std::string::npos);
    EXPECT_NE(content.find("Total packets: 0"), std::string::npos);
}

TEST_F(ReportGeneratorTest, invalidPathFails) {
    CaptureSession session;
    auto result = ReportGenerator::generate(session, "/nonexistent/path/report.txt");
    EXPECT_FALSE(result.success);
}

// ── Detection details coverage ──────────────────────────────────────

TEST_F(ReportGeneratorTest, detectionSourceWritten_whenNotNone) {
    CaptureSession session;
    PacketInfo pkt;
    pkt.protocol = "TCP";
    pkt.ipSource = "10.0.0.5";
    pkt.ipDestination = "10.0.0.6";
    pkt.portSource = "5555";
    pkt.portDestination = "80";
    pkt.application = "HTTP";
    session.addPacket(pkt);

    DetectionResult detection;
    detection.finalVerdict = AttackType::SshBruteForce;
    detection.detectionSource = nids::core::DetectionSource::MlOnly;
    detection.combinedScore = 0.85f;
    detection.mlResult.confidence = 0.9f;
    detection.mlResult.classification = AttackType::SshBruteForce;
    session.setDetectionResult(0, detection);

    auto result = ReportGenerator::generate(session, testReportPath, "eth0");
    ASSERT_TRUE(result.success);

    std::ifstream file(testReportPath);
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());

    EXPECT_NE(content.find("Detection Source: ML Classifier"), std::string::npos);
    EXPECT_NE(content.find("Combined Score:"), std::string::npos);
    EXPECT_NE(content.find("ML Confidence:"), std::string::npos);
}

TEST_F(ReportGeneratorTest, threatIntelMatchesWritten) {
    CaptureSession session;
    PacketInfo pkt;
    pkt.protocol = "TCP";
    pkt.ipSource = "1.2.3.4";
    pkt.ipDestination = "5.6.7.8";
    pkt.portSource = "1234";
    pkt.portDestination = "443";
    pkt.application = "HTTPS";
    session.addPacket(pkt);

    DetectionResult detection;
    detection.finalVerdict = AttackType::Unknown;
    detection.detectionSource = nids::core::DetectionSource::ThreatIntel;
    detection.combinedScore = 0.7f;
    detection.mlResult.confidence = 0.3f;
    detection.mlResult.classification = AttackType::Benign;
    detection.threatIntelMatches.emplace_back("1.2.3.4", "feodo", true);
    detection.threatIntelMatches.emplace_back("5.6.7.8", "spamhaus", false);
    session.setDetectionResult(0, detection);

    auto result = ReportGenerator::generate(session, testReportPath);
    ASSERT_TRUE(result.success);

    std::ifstream file(testReportPath);
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());

    EXPECT_NE(content.find("Threat Intel Matches:"), std::string::npos);
    EXPECT_NE(content.find("1.2.3.4"), std::string::npos);
    EXPECT_NE(content.find("feodo"), std::string::npos);
    EXPECT_NE(content.find("(source)"), std::string::npos);
    EXPECT_NE(content.find("5.6.7.8"), std::string::npos);
    EXPECT_NE(content.find("spamhaus"), std::string::npos);
    EXPECT_NE(content.find("(destination)"), std::string::npos);
}

TEST_F(ReportGeneratorTest, ruleMatchesWritten) {
    CaptureSession session;
    PacketInfo pkt;
    pkt.protocol = "TCP";
    pkt.ipSource = "192.168.1.50";
    pkt.ipDestination = "10.0.0.1";
    pkt.portSource = "55555";
    pkt.portDestination = "22";
    pkt.application = "SSH";
    session.addPacket(pkt);

    DetectionResult detection;
    detection.finalVerdict = AttackType::SynFlood;
    detection.detectionSource = nids::core::DetectionSource::Ensemble;
    detection.combinedScore = 0.95f;
    detection.mlResult.confidence = 0.88f;
    detection.mlResult.classification = AttackType::SynFlood;
    detection.ruleMatches.emplace_back("syn_flood", "SYN flood detected", 0.85f);
    detection.ruleMatches.emplace_back("high_packet_rate", "Very high packet rate", 0.92f);
    session.setDetectionResult(0, detection);

    auto result = ReportGenerator::generate(session, testReportPath);
    ASSERT_TRUE(result.success);

    std::ifstream file(testReportPath);
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());

    EXPECT_NE(content.find("Heuristic Rules:"), std::string::npos);
    EXPECT_NE(content.find("syn_flood"), std::string::npos);
    EXPECT_NE(content.find("SYN flood detected"), std::string::npos);
    EXPECT_NE(content.find("high_packet_rate"), std::string::npos);
    EXPECT_NE(content.find("severity="), std::string::npos);
}

TEST_F(ReportGeneratorTest, multiplePackets_mixedDetectionSources) {
    CaptureSession session;

    // Benign packet (DetectionSource::None) — no details section
    PacketInfo pkt1;
    pkt1.protocol = "TCP";
    pkt1.ipSource = "192.168.1.1";
    pkt1.ipDestination = "10.0.0.1";
    pkt1.portSource = "12345";
    pkt1.portDestination = "80";
    pkt1.application = "HTTP";
    session.addPacket(pkt1);
    DetectionResult det1;
    det1.finalVerdict = AttackType::Benign;
    det1.detectionSource = nids::core::DetectionSource::None;
    session.setDetectionResult(0, det1);

    // Attack packet with all three layers
    PacketInfo pkt2;
    pkt2.protocol = "TCP";
    pkt2.ipSource = "1.2.3.4";
    pkt2.ipDestination = "5.6.7.8";
    pkt2.portSource = "4444";
    pkt2.portDestination = "443";
    pkt2.application = "HTTPS";
    session.addPacket(pkt2);
    DetectionResult det2;
    det2.finalVerdict = AttackType::DdosIcmp;
    det2.detectionSource = nids::core::DetectionSource::Ensemble;
    det2.combinedScore = 0.99f;
    det2.mlResult.confidence = 0.95f;
    det2.mlResult.classification = AttackType::DdosIcmp;
    det2.threatIntelMatches.emplace_back("1.2.3.4", "botnet", true);
    det2.ruleMatches.emplace_back("suspicious_port", "Port 4444 is suspicious", 0.6f);
    session.setDetectionResult(1, det2);

    auto result = ReportGenerator::generate(session, testReportPath, "wlan0");
    ASSERT_TRUE(result.success);

    std::ifstream file(testReportPath);
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());

    EXPECT_NE(content.find("Interface: wlan0"), std::string::npos);
    EXPECT_NE(content.find("Total packets: 2"), std::string::npos);
    EXPECT_NE(content.find("Packet #0"), std::string::npos);
    EXPECT_NE(content.find("Packet #1"), std::string::npos);
    // pkt2 should have ensemble details
    EXPECT_NE(content.find("Ensemble (ML + TI + Rules)"), std::string::npos);
    EXPECT_NE(content.find("botnet"), std::string::npos);
    EXPECT_NE(content.find("suspicious_port"), std::string::npos);
}

TEST_F(ReportGeneratorTest, networkCardOmitted_noInterfaceLine) {
    CaptureSession session;
    auto result = ReportGenerator::generate(session, testReportPath);
    ASSERT_TRUE(result.success);

    std::ifstream file(testReportPath);
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());

    EXPECT_EQ(content.find("Interface:"), std::string::npos);
}
