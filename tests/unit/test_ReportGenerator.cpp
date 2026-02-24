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
    session.setAnalysisResult(0, AttackType::Benign);

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
    session.setAnalysisResult(0, AttackType::DDoS);

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
    EXPECT_NE(content.find("DDoS"), std::string::npos);
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
