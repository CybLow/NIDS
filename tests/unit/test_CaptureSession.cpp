#include <gtest/gtest.h>
#include "core/model/CaptureSession.h"

using nids::core::CaptureSession;
using nids::core::PacketInfo;
using nids::core::AttackType;

TEST(CaptureSession, initiallyEmpty) {
    CaptureSession session;
    EXPECT_EQ(session.packetCount(), 0u);
    EXPECT_EQ(session.analysisResultCount(), 0u);
}

TEST(CaptureSession, addPacketIncreasesCount) {
    CaptureSession session;
    PacketInfo pkt;
    pkt.protocol = "TCP";
    pkt.ipSource = "192.168.1.1";
    session.addPacket(pkt);
    EXPECT_EQ(session.packetCount(), 1u);
}

TEST(CaptureSession, getPacketReturnsCorrectData) {
    CaptureSession session;
    PacketInfo pkt;
    pkt.protocol = "UDP";
    pkt.ipSource = "10.0.0.1";
    pkt.ipDestination = "10.0.0.2";
    pkt.portSource = "53";
    pkt.portDestination = "1234";
    session.addPacket(pkt);

    const auto& retrieved = session.getPacket(0);
    EXPECT_EQ(retrieved.protocol, "UDP");
    EXPECT_EQ(retrieved.ipSource, "10.0.0.1");
    EXPECT_EQ(retrieved.ipDestination, "10.0.0.2");
    EXPECT_EQ(retrieved.portSource, "53");
    EXPECT_EQ(retrieved.portDestination, "1234");
}

TEST(CaptureSession, getPacketOutOfRangeThrows) {
    CaptureSession session;
    EXPECT_THROW(session.getPacket(0), std::out_of_range);
}

TEST(CaptureSession, setAndGetAnalysisResult) {
    CaptureSession session;
    session.setAnalysisResult(0, AttackType::DdosIcmp);
    EXPECT_EQ(session.getAnalysisResult(0), AttackType::DdosIcmp);
}

TEST(CaptureSession, getAnalysisResultOutOfRangeReturnsUnknown) {
    CaptureSession session;
    EXPECT_EQ(session.getAnalysisResult(999), AttackType::Unknown);
}

TEST(CaptureSession, clearResetsEverything) {
    CaptureSession session;
    PacketInfo pkt;
    pkt.protocol = "TCP";
    session.addPacket(pkt);
    session.setAnalysisResult(0, AttackType::Benign);

    session.clear();
    EXPECT_EQ(session.packetCount(), 0u);
    EXPECT_EQ(session.analysisResultCount(), 0u);
}

TEST(CaptureSession, multiplePackets) {
    CaptureSession session;
    for (int i = 0; i < 100; ++i) {
        PacketInfo pkt;
        pkt.protocol = "TCP";
        pkt.portSource = std::to_string(i);
        session.addPacket(pkt);
    }
    EXPECT_EQ(session.packetCount(), 100u);
    EXPECT_EQ(session.getPacket(50).portSource, "50");
}
