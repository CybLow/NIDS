#include <gtest/gtest.h>
#include "infra/rules/HeuristicRuleEngine.h"

using nids::infra::HeuristicRuleEngine;
using nids::core::FlowMetadata;

class HeuristicRuleEngineTest : public ::testing::Test {
protected:
    HeuristicRuleEngine engine_;

    /// Create a baseline benign flow.
    static FlowMetadata makeBenignFlow() {
        FlowMetadata flow;
        flow.srcIp = "192.168.1.100";
        flow.dstIp = "10.0.0.1";
        flow.srcPort = 45000;
        flow.dstPort = 80;
        flow.protocol = "TCP";
        flow.totalFwdPackets = 10;
        flow.totalBwdPackets = 8;
        flow.flowDurationUs = 5'000'000; // 5 seconds
        flow.fwdPacketsPerSecond = 2.0f;
        flow.bwdPacketsPerSecond = 1.6f;
        flow.synFlagCount = 1;
        flow.ackFlagCount = 10;
        flow.rstFlagCount = 0;
        flow.finFlagCount = 1;
        flow.avgPacketSize = 512.0f;
        return flow;
    }
};

TEST_F(HeuristicRuleEngineTest, ruleCount_returnsExpected) {
    EXPECT_EQ(engine_.ruleCount(), 7u);
}

// ── Benign flow: no rules should fire ────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_benignFlow_noRulesFire) {
    auto flow = makeBenignFlow();
    auto results = engine_.evaluate(flow);
    EXPECT_TRUE(results.empty());
}

// ── Suspicious port ──────────────────────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_suspiciousPort_fires) {
    auto flow = makeBenignFlow();
    flow.dstPort = 4444; // Known suspicious port
    auto results = engine_.evaluate(flow);

    bool found = false;
    for (const auto& r : results) {
        if (r.ruleName.find("suspicious_port") != std::string::npos) {
            found = true;
            EXPECT_GT(r.severity, 0.0f);
        }
    }
    EXPECT_TRUE(found) << "Expected suspicious_port rule to fire for port 4444";
}

TEST_F(HeuristicRuleEngineTest, evaluate_normalPort_noSuspiciousPort) {
    auto flow = makeBenignFlow();
    flow.dstPort = 443; // Normal HTTPS port
    auto results = engine_.evaluate(flow);

    for (const auto& r : results) {
        EXPECT_TRUE(r.ruleName.find("suspicious_port") == std::string::npos)
            << "Unexpected suspicious_port rule for port 443";
    }
}

// ── SYN flood ────────────────────────────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_synFlood_fires) {
    auto flow = makeBenignFlow();
    flow.protocol = "TCP";
    flow.synFlagCount = 500;
    flow.ackFlagCount = 10; // ratio 50.0, well above 5.0 threshold
    flow.totalFwdPackets = 500;
    auto results = engine_.evaluate(flow);

    bool found = false;
    for (const auto& r : results) {
        if (r.ruleName.find("syn_flood") != std::string::npos) {
            found = true;
            EXPECT_GT(r.severity, 0.0f);
        }
    }
    EXPECT_TRUE(found) << "Expected syn_flood rule to fire";
}

TEST_F(HeuristicRuleEngineTest, evaluate_synFloodBelowThreshold_doesNotFire) {
    auto flow = makeBenignFlow();
    flow.protocol = "TCP";
    flow.synFlagCount = 3;
    flow.ackFlagCount = 10; // ratio 0.3, below 5.0 threshold
    auto results = engine_.evaluate(flow);

    for (const auto& r : results) {
        EXPECT_TRUE(r.ruleName.find("syn_flood") == std::string::npos)
            << "syn_flood should not fire below threshold";
    }
}

// ── ICMP flood ───────────────────────────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_icmpFlood_fires) {
    auto flow = makeBenignFlow();
    flow.protocol = "ICMP";
    flow.totalFwdPackets = 200;
    flow.fwdPacketsPerSecond = 200.0f; // well above 100 pkt/s threshold
    auto results = engine_.evaluate(flow);

    bool found = false;
    for (const auto& r : results) {
        if (r.ruleName.find("icmp_flood") != std::string::npos) {
            found = true;
        }
    }
    EXPECT_TRUE(found) << "Expected icmp_flood rule to fire";
}

// ── Brute force ──────────────────────────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_bruteForce_fires) {
    auto flow = makeBenignFlow();
    flow.protocol = "TCP";
    flow.dstPort = 22; // SSH
    flow.totalFwdPackets = 100;
    flow.fwdPacketsPerSecond = 50.0f; // well above 10 pkt/s threshold
    auto results = engine_.evaluate(flow);

    bool found = false;
    for (const auto& r : results) {
        if (r.ruleName.find("brute_force") != std::string::npos) {
            found = true;
        }
    }
    EXPECT_TRUE(found) << "Expected brute_force rule to fire for SSH port";
}

TEST_F(HeuristicRuleEngineTest, evaluate_bruteForce_nonAuthPort_doesNotFire) {
    auto flow = makeBenignFlow();
    flow.protocol = "TCP";
    flow.dstPort = 8080; // Not an auth port
    flow.totalFwdPackets = 100;
    flow.fwdPacketsPerSecond = 50.0f;
    auto results = engine_.evaluate(flow);

    for (const auto& r : results) {
        EXPECT_TRUE(r.ruleName.find("brute_force") == std::string::npos)
            << "brute_force should not fire for non-auth port";
    }
}

// ── High packet rate ─────────────────────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_highPacketRate_fires) {
    auto flow = makeBenignFlow();
    flow.totalFwdPackets = 5000;
    flow.totalBwdPackets = 5000;
    flow.fwdPacketsPerSecond = 15000.0f; // above 10000 threshold
    flow.bwdPacketsPerSecond = 15000.0f;
    auto results = engine_.evaluate(flow);

    bool found = false;
    for (const auto& r : results) {
        if (r.ruleName.find("high_packet_rate") != std::string::npos) {
            found = true;
        }
    }
    EXPECT_TRUE(found) << "Expected high_packet_rate rule to fire";
}

// ── Reset flood ──────────────────────────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_resetFlood_fires) {
    auto flow = makeBenignFlow();
    flow.protocol = "TCP";
    flow.rstFlagCount = 50;
    flow.totalFwdPackets = 60;
    flow.totalBwdPackets = 0;
    // RST ratio = 50/60 = 0.83, above 0.5 threshold; count 50 >= 30
    auto results = engine_.evaluate(flow);

    bool found = false;
    for (const auto& r : results) {
        if (r.ruleName.find("reset_flood") != std::string::npos) {
            found = true;
        }
    }
    EXPECT_TRUE(found) << "Expected reset_flood rule to fire";
}

// ── Port scan ────────────────────────────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluatePortScan_aboveThreshold_fires) {
    std::vector<std::uint16_t> ports;
    for (std::uint16_t i = 1; i <= 25; ++i) {
        ports.push_back(i);
    }

    auto results = engine_.evaluatePortScan("10.0.0.1", ports);
    EXPECT_FALSE(results.empty());

    bool found = false;
    for (const auto& r : results) {
        if (r.ruleName.find("port_scan") != std::string::npos) {
            found = true;
            EXPECT_GT(r.severity, 0.0f);
        }
    }
    EXPECT_TRUE(found) << "Expected port_scan rule to fire for 25 distinct ports";
}

TEST_F(HeuristicRuleEngineTest, evaluatePortScan_belowThreshold_doesNotFire) {
    std::vector<std::uint16_t> ports = {80, 443, 8080};

    auto results = engine_.evaluatePortScan("10.0.0.1", ports);
    EXPECT_TRUE(results.empty());
}
