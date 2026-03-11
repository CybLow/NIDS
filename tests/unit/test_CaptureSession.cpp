#include <gtest/gtest.h>
#include "core/model/CaptureSession.h"

using nids::core::CaptureSession;
using nids::core::PacketInfo;
using nids::core::AttackType;
using nids::core::DetectionResult;

/// Helper: create a DetectionResult with the given final verdict.
static DetectionResult makeResult(AttackType verdict) {
    DetectionResult result;
    result.finalVerdict = verdict;
    return result;
}

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
    EXPECT_THROW([[maybe_unused]] auto& pkt = session.getPacket(0), std::out_of_range);
}

TEST(CaptureSession, setAndGetDetectionResult) {
    CaptureSession session;
    session.setDetectionResult(0, makeResult(AttackType::DdosIcmp));
    EXPECT_EQ(session.getDetectionResult(0).finalVerdict, AttackType::DdosIcmp);
}

TEST(CaptureSession, getDetectionResultOutOfRangeReturnsUnknown) {
    CaptureSession session;
    EXPECT_EQ(session.getDetectionResult(999).finalVerdict, AttackType::Unknown);
}

TEST(CaptureSession, clearResetsEverything) {
    CaptureSession session;
    PacketInfo pkt;
    pkt.protocol = "TCP";
    session.addPacket(pkt);
    session.setDetectionResult(0, makeResult(AttackType::Benign));

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

// ── Sparse index auto-resize ─────────────────────────────────────────

TEST(CaptureSession, setDetectionResult_sparseIndex_autoResizes) {
    CaptureSession session;
    // Set result at index 10 without any prior results → should resize to 11
    session.setDetectionResult(10, makeResult(AttackType::DdosIcmp));
    EXPECT_EQ(session.analysisResultCount(), 11u);

    // Index 0-9 should return default (Unknown)
    EXPECT_EQ(session.getDetectionResult(0).finalVerdict, AttackType::Unknown);
    EXPECT_EQ(session.getDetectionResult(5).finalVerdict, AttackType::Unknown);

    // Index 10 should have our value
    EXPECT_EQ(session.getDetectionResult(10).finalVerdict, AttackType::DdosIcmp);
}

// ── Overwrite detection result ───────────────────────────────────────

TEST(CaptureSession, setDetectionResult_overwrite) {
    CaptureSession session;
    session.setDetectionResult(0, makeResult(AttackType::DdosIcmp));
    EXPECT_EQ(session.getDetectionResult(0).finalVerdict, AttackType::DdosIcmp);

    // Overwrite with a different verdict
    session.setDetectionResult(0, makeResult(AttackType::SynFlood));
    EXPECT_EQ(session.getDetectionResult(0).finalVerdict, AttackType::SynFlood);
}

// ── Multiple detection results ───────────────────────────────────────

TEST(CaptureSession, setDetectionResult_multipleResults) {
    CaptureSession session;
    session.setDetectionResult(0, makeResult(AttackType::Benign));
    session.setDetectionResult(1, makeResult(AttackType::SshBruteForce));
    session.setDetectionResult(2, makeResult(AttackType::PortScanning));

    EXPECT_EQ(session.analysisResultCount(), 3u);
    EXPECT_EQ(session.getDetectionResult(0).finalVerdict, AttackType::Benign);
    EXPECT_EQ(session.getDetectionResult(1).finalVerdict, AttackType::SshBruteForce);
    EXPECT_EQ(session.getDetectionResult(2).finalVerdict, AttackType::PortScanning);
}

// ── Clear resets detection results ───────────────────────────────────

TEST(CaptureSession, clear_alsoResetsDetectionResults) {
    CaptureSession session;
    session.setDetectionResult(5, makeResult(AttackType::DdosIcmp));
    EXPECT_EQ(session.analysisResultCount(), 6u);

    session.clear();
    EXPECT_EQ(session.analysisResultCount(), 0u);
    // After clear, getting any result returns default Unknown
    EXPECT_EQ(session.getDetectionResult(5).finalVerdict, AttackType::Unknown);
}

// ── Packets and results are independent ──────────────────────────────

TEST(CaptureSession, packetsAndResults_independent) {
    CaptureSession session;
    PacketInfo pkt;
    pkt.protocol = "TCP";
    session.addPacket(pkt);
    // 1 packet but no detection results yet
    EXPECT_EQ(session.packetCount(), 1u);
    EXPECT_EQ(session.analysisResultCount(), 0u);

    session.setDetectionResult(0, makeResult(AttackType::Benign));
    EXPECT_EQ(session.packetCount(), 1u);
    EXPECT_EQ(session.analysisResultCount(), 1u);
}
