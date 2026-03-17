#include "infra/rules/HeuristicRuleEngine.h"
#include <gtest/gtest.h>

using nids::core::FlowInfo;
using nids::infra::HeuristicRuleEngine;

class HeuristicRuleEngineTest : public ::testing::Test {
protected: // NOSONAR
  HeuristicRuleEngine engine_;

  /// Create a baseline benign flow.
  static FlowInfo makeBenignFlow() {
    FlowInfo flow;
    flow.srcIp = "192.168.1.100";
    flow.dstIp = "10.0.0.1";
    flow.srcPort = 45000;
    flow.dstPort = 80;
    flow.protocol = 6;
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
  for (const auto &r : results) {
    if (r.ruleName.find("suspicious_port") != std::string::npos) { // NOSONAR
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

  for (const auto &r : results) {
    EXPECT_TRUE(r.ruleName.find("suspicious_port") == std::string::npos)
        << "Unexpected suspicious_port rule for port 443";
  }
}

// ── SYN flood ────────────────────────────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_synFlood_fires) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.synFlagCount = 500;
  flow.ackFlagCount = 10; // ratio 50.0, well above 5.0 threshold
  flow.totalFwdPackets = 500;
  auto results = engine_.evaluate(flow);

  bool found = false;
  for (const auto &r : results) {
    if (r.ruleName.find("syn_flood") != std::string::npos) { // NOSONAR
      found = true;
      EXPECT_GT(r.severity, 0.0f);
    }
  }
  EXPECT_TRUE(found) << "Expected syn_flood rule to fire";
}

TEST_F(HeuristicRuleEngineTest, evaluate_synFloodBelowThreshold_doesNotFire) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.synFlagCount = 3;
  flow.ackFlagCount = 10; // ratio 0.3, below 5.0 threshold
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    EXPECT_TRUE(r.ruleName.find("syn_flood") == std::string::npos)
        << "syn_flood should not fire below threshold";
  }
}

// ── ICMP flood ───────────────────────────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_icmpFlood_fires) {
  auto flow = makeBenignFlow();
  flow.protocol = 1;
  flow.totalFwdPackets = 500;
  flow.totalBwdPackets = 500;
  flow.flowDurationUs =
      1'000'000; // 1 s → rate = 1000/1.0 = 1000 pkt/s, above 100 threshold
  auto results = engine_.evaluate(flow);

  bool found = false;
  for (const auto &r : results) {
    if (r.ruleName.find("icmp_flood") != std::string::npos) { // NOSONAR
      found = true;
    }
  }
  EXPECT_TRUE(found) << "Expected icmp_flood rule to fire";
}

// ── Brute force ──────────────────────────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_bruteForce_fires) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.dstPort = 22; // SSH
  flow.totalFwdPackets = 100;
  flow.fwdPacketsPerSecond = 50.0f; // well above 10 pkt/s threshold
  auto results = engine_.evaluate(flow);

  bool found = false;
  for (const auto &r : results) {
    if (r.ruleName.find("brute_force") != std::string::npos) { // NOSONAR
      found = true;
    }
  }
  EXPECT_TRUE(found) << "Expected brute_force rule to fire for SSH port";
}

TEST_F(HeuristicRuleEngineTest, evaluate_bruteForce_nonAuthPort_doesNotFire) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.dstPort = 8080; // Not an auth port
  flow.totalFwdPackets = 100;
  flow.fwdPacketsPerSecond = 50.0f;
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    EXPECT_TRUE(r.ruleName.find("brute_force") == std::string::npos)
        << "brute_force should not fire for non-auth port";
  }
}

// ── High packet rate ─────────────────────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_highPacketRate_fires) {
  auto flow = makeBenignFlow();
  flow.totalFwdPackets = 5000;
  flow.totalBwdPackets = 5000;
  flow.flowDurationUs =
      500'000; // 0.5 s → rate = 10000/0.5 = 20000 pkt/s, above 10000 threshold
  auto results = engine_.evaluate(flow);

  bool found = false;
  for (const auto &r : results) {
    if (r.ruleName.find("high_packet_rate") != std::string::npos) { // NOSONAR
      found = true;
    }
  }
  EXPECT_TRUE(found) << "Expected high_packet_rate rule to fire";
}

// ── Reset flood ──────────────────────────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_resetFlood_fires) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.rstFlagCount = 50;
  flow.totalFwdPackets = 60;
  flow.totalBwdPackets = 0;
  // RST ratio = 50/60 = 0.83, above 0.5 threshold; count 50 >= 30
  auto results = engine_.evaluate(flow);

  bool found = false;
  for (const auto &r : results) {
    if (r.ruleName.find("reset_flood") != std::string::npos) { // NOSONAR
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
  for (const auto &r : results) {
    if (r.ruleName.find("port_scan") != std::string::npos) { // NOSONAR
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

// ── Suspicious port: source port only ────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_suspiciousSrcPort_fires) {
  auto flow = makeBenignFlow();
  flow.srcPort = 31337; // Back Orifice (suspicious src port)
  flow.dstPort = 80;    // Normal dst port
  auto results = engine_.evaluate(flow);

  bool found = false;
  for (const auto &r : results) {
    if (r.ruleName.find("suspicious_port") != std::string::npos) { // NOSONAR
      found = true;
      EXPECT_NE(r.description.find("Source port"), std::string::npos);
    }
  }
  EXPECT_TRUE(found)
      << "Expected suspicious_port rule to fire for src port 31337";
}

// ── Suspicious port: both ports suspicious ───────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_bothPortsSuspicious_higherSeverity) {
  auto flow = makeBenignFlow();
  flow.srcPort = 4444;  // Metasploit
  flow.dstPort = 31337; // Back Orifice
  auto results = engine_.evaluate(flow);

  bool found = false;
  for (const auto &r : results) {
    if (r.ruleName.find("suspicious_port") != std::string::npos) { // NOSONAR
      found = true;
      EXPECT_EQ(r.severity, 0.8f); // Both suspicious → 0.8
      EXPECT_NE(r.description.find("Both"), std::string::npos);
    }
  }
  EXPECT_TRUE(found)
      << "Expected suspicious_port rule for both suspicious ports";
}

// ── SYN flood: zero ACK (denominator) ────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_synFlood_zeroAck_fires) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.synFlagCount = 100;
  flow.ackFlagCount = 0; // Zero ACK → ratio = synFlagCount itself
  flow.totalFwdPackets = 100;
  auto results = engine_.evaluate(flow);

  bool found = false;
  for (const auto &r : results) {
    if (r.ruleName.find("syn_flood") != std::string::npos) { // NOSONAR
      found = true;
    }
  }
  EXPECT_TRUE(found) << "Expected syn_flood to fire with zero ACK count";
}

// ── ICMP flood: below minimum packet threshold ──────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_icmpFlood_belowMinPkts_doesNotFire) {
  auto flow = makeBenignFlow();
  flow.protocol = 1;
  flow.totalFwdPackets = 5;
  flow.totalBwdPackets = 5;
  flow.flowDurationUs = 100'000; // rate 100/0.1=1000 but only 10 total < 20 min
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    EXPECT_TRUE(r.ruleName.find("icmp_flood") == std::string::npos)
        << "icmp_flood should not fire below minimum packet count";
  }
}

// ── ICMP flood: zero duration ────────────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_icmpFlood_zeroDuration_doesNotFire) {
  auto flow = makeBenignFlow();
  flow.protocol = 1;
  flow.totalFwdPackets = 500;
  flow.totalBwdPackets = 500;
  flow.flowDurationUs = 0; // Zero duration → return nullopt
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    EXPECT_TRUE(r.ruleName.find("icmp_flood") == std::string::npos)
        << "icmp_flood should not fire with zero duration";
  }
}

// ── Brute force: zero duration ───────────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_bruteForce_zeroDuration_doesNotFire) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.dstPort = 22;
  flow.totalFwdPackets = 100;
  flow.totalBwdPackets = 0;
  flow.flowDurationUs = 0; // Zero duration
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    EXPECT_TRUE(r.ruleName.find("brute_force") == std::string::npos)
        << "brute_force should not fire with zero duration";
  }
}

// ── Brute force: other auth ports ────────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_bruteForce_rdpPort_fires) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.dstPort = 3389; // RDP
  flow.totalFwdPackets = 100;
  flow.totalBwdPackets = 50;
  flow.flowDurationUs = 1'000'000; // 1s → rate = 150/1 = 150 > 10
  auto results = engine_.evaluate(flow);

  bool found = false;
  for (const auto &r : results) {
    if (r.ruleName.find("brute_force") != std::string::npos) { // NOSONAR
      found = true;
      EXPECT_NE(r.description.find("RDP"), std::string::npos);
    }
  }
  EXPECT_TRUE(found) << "Expected brute_force to fire for RDP port";
}

// ── High packet rate: zero duration ──────────────────────────────────

TEST_F(HeuristicRuleEngineTest,
       evaluate_highPacketRate_zeroDuration_doesNotFire) {
  auto flow = makeBenignFlow();
  flow.totalFwdPackets = 5000;
  flow.totalBwdPackets = 5000;
  flow.flowDurationUs = 0;
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    EXPECT_TRUE(r.ruleName.find("high_packet_rate") == std::string::npos)
        << "high_packet_rate should not fire with zero duration";
  }
}

// ── High packet rate: below minimum packets ──────────────────────────

TEST_F(HeuristicRuleEngineTest,
       evaluate_highPacketRate_belowMinPkts_doesNotFire) {
  auto flow = makeBenignFlow();
  flow.totalFwdPackets = 30;
  flow.totalBwdPackets = 30;
  flow.flowDurationUs = 1'000; // Tiny duration but only 60 packets < 100 min
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    EXPECT_TRUE(r.ruleName.find("high_packet_rate") == std::string::npos)
        << "high_packet_rate should not fire below minimum packet count";
  }
}

// ── Multiple rules firing simultaneously ─────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_multipleRulesFire) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.dstPort = 4444; // Suspicious port
  flow.synFlagCount = 200;
  flow.ackFlagCount = 0; // SYN flood
  flow.rstFlagCount = 100;
  flow.totalFwdPackets = 10000;
  flow.totalBwdPackets = 0;
  flow.flowDurationUs = 500'000; // 0.5s → rate = 10000/0.5 = 20000

  auto results = engine_.evaluate(flow);

  // Should fire: suspicious_port, syn_flood, reset_flood, high_packet_rate
  EXPECT_GE(results.size(), 3u);

  bool hasSuspPort = false;
  bool hasSynFlood = false;
  bool hasHighRate = false;
  for (const auto &r : results) {
    if (r.ruleName == "suspicious_port")
      hasSuspPort = true;
    if (r.ruleName == "syn_flood")
      hasSynFlood = true;
    if (r.ruleName == "high_packet_rate")
      hasHighRate = true;
  }
  EXPECT_TRUE(hasSuspPort);
  EXPECT_TRUE(hasSynFlood);
  EXPECT_TRUE(hasHighRate);
}

// ── Reset flood: below RST count threshold ───────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_resetFlood_belowMinRst_doesNotFire) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.rstFlagCount = 10; // Below 30 minimum
  flow.totalFwdPackets = 15;
  flow.totalBwdPackets = 0;
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    EXPECT_TRUE(r.ruleName.find("reset_flood") == std::string::npos)
        << "reset_flood should not fire below minimum RST count";
  }
}

// ── Reset flood: low RST ratio ───────────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_resetFlood_lowRatio_doesNotFire) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.rstFlagCount = 35; // Above 30 minimum
  flow.totalFwdPackets = 500;
  flow.totalBwdPackets = 500; // Total 1000 → ratio = 35/1000 = 0.035 < 0.5
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    EXPECT_TRUE(r.ruleName.find("reset_flood") == std::string::npos)
        << "reset_flood should not fire with low RST ratio";
  }
}

// ── ICMP flood: rate below threshold ─────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_icmpFlood_belowRate_doesNotFire) {
  auto flow = makeBenignFlow();
  flow.protocol = 1;
  flow.totalFwdPackets = 15;
  flow.totalBwdPackets = 15;       // 30 total >= 20 min
  flow.flowDurationUs = 1'000'000; // 1s → rate = 30/1 = 30, below 100 threshold
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    EXPECT_TRUE(r.ruleName.find("icmp_flood") == std::string::npos)
        << "icmp_flood should not fire when rate is below threshold";
  }
}

// ── Brute force: below minimum packet count ─────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_bruteForce_belowMinPkts_doesNotFire) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.dstPort = 22; // SSH (auth port)
  flow.totalFwdPackets = 5;
  flow.totalBwdPackets = 5;      // 10 total < 20 min
  flow.flowDurationUs = 100'000; // rate would be high but packet count too low
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    EXPECT_TRUE(r.ruleName.find("brute_force") == std::string::npos)
        << "brute_force should not fire below minimum packet count";
  }
}

// ── Brute force: rate below threshold ───────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_bruteForce_belowRate_doesNotFire) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.dstPort = 22; // SSH
  flow.totalFwdPackets = 15;
  flow.totalBwdPackets = 10; // 25 total >= 20 min
  flow.flowDurationUs =
      10'000'000; // 10s → rate = 25/10 = 2.5, below 10 threshold
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    EXPECT_TRUE(r.ruleName.find("brute_force") == std::string::npos)
        << "brute_force should not fire when rate is below threshold";
  }
}

// ── High packet rate: rate below threshold ──────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_highPacketRate_belowRate_doesNotFire) {
  auto flow = makeBenignFlow();
  flow.totalFwdPackets = 60;
  flow.totalBwdPackets = 60; // 120 total >= 100 min
  flow.flowDurationUs =
      5'000'000; // 5s → rate = 120/5 = 24, below 10000 threshold
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    EXPECT_TRUE(r.ruleName.find("high_packet_rate") == std::string::npos)
        << "high_packet_rate should not fire when rate is below threshold";
  }
}

// ── Reset flood: zero total packets (defensive) ─────────────────────

TEST_F(HeuristicRuleEngineTest,
       evaluate_resetFlood_zeroTotalPackets_doesNotFire) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.rstFlagCount = 30; // Meets minimum
  flow.totalFwdPackets = 0;
  flow.totalBwdPackets = 0; // 0 total → defensive guard
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    EXPECT_TRUE(r.ruleName.find("reset_flood") == std::string::npos)
        << "reset_flood should not fire with zero total packets";
  }
}

// ── Suspicious port: both src and dst suspicious ─────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_bothSuspiciousPorts_severityHigh) {
  auto flow = makeBenignFlow();
  flow.srcPort = 4444; // Metasploit reverse shell
  flow.dstPort = 5555; // Common backdoor
  auto results = engine_.evaluate(flow);

  bool found = false;
  for (const auto &r : results) {
    if (r.ruleName == "suspicious_port") {
      found = true;
      // Both ports suspicious → severity 0.8f
      EXPECT_FLOAT_EQ(r.severity, 0.8f);
      EXPECT_NE(r.description.find("Both"), std::string::npos);
    }
  }
  EXPECT_TRUE(found)
      << "suspicious_port rule should fire when both ports are suspicious";
}

// ── SYN flood: enough SYNs but ratio below threshold ─────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_synFlood_belowRatio_doesNotFire) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.synFlagCount = 60; // >= kSynFloodMinSyns (50)
  flow.ackFlagCount = 20; // ratio = 60/20 = 3.0 < kSynFloodRatio (5.0)
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    EXPECT_NE(r.ruleName, "syn_flood")
        << "syn_flood should not fire when SYN/ACK ratio is below threshold";
  }
}

// ── Port scan: severity capped at 1.0 ────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluatePortScan_manyPorts_severityCapped) {
  // kPortScanThreshold = 20, severity cap at kPortScanThreshold * 3 = 60
  std::vector<std::uint16_t> ports;
  for (std::uint16_t p = 1; p <= 100; ++p) {
    ports.push_back(p);
  }
  auto results = engine_.evaluatePortScan("10.0.0.1", ports);

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].ruleName, "port_scan");
  // 100 / 60 = 1.67 → clamped to 1.0
  EXPECT_FLOAT_EQ(results[0].severity, 1.0f);
}

// ── Non-TCP protocols don't trigger TCP-specific rules ───────────────

// ── Brute force: each auth port produces a different service name ──

TEST_F(HeuristicRuleEngineTest, evaluate_bruteForce_ftpPort_fires) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.dstPort = 21; // FTP
  flow.totalFwdPackets = 100;
  flow.totalBwdPackets = 50;
  flow.flowDurationUs = 1'000'000; // 1s → rate = 150 > 10
  auto results = engine_.evaluate(flow);

  bool found = false;
  for (const auto &r : results) {
    if (r.ruleName == "brute_force") {
      found = true;
      EXPECT_NE(r.description.find("FTP"), std::string::npos);
    }
  }
  EXPECT_TRUE(found) << "Expected brute_force to fire for FTP port";
}

TEST_F(HeuristicRuleEngineTest, evaluate_bruteForce_telnetPort_fires) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.dstPort = 23; // Telnet
  flow.totalFwdPackets = 100;
  flow.totalBwdPackets = 50;
  flow.flowDurationUs = 1'000'000;
  auto results = engine_.evaluate(flow);

  bool found = false;
  for (const auto &r : results) {
    if (r.ruleName == "brute_force") {
      found = true;
      EXPECT_NE(r.description.find("Telnet"), std::string::npos);
    }
  }
  EXPECT_TRUE(found) << "Expected brute_force to fire for Telnet port";
}

TEST_F(HeuristicRuleEngineTest, evaluate_bruteForce_vncPort_fires) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.dstPort = 5900; // VNC
  flow.totalFwdPackets = 100;
  flow.totalBwdPackets = 50;
  flow.flowDurationUs = 1'000'000;
  auto results = engine_.evaluate(flow);

  bool found = false;
  for (const auto &r : results) {
    if (r.ruleName == "brute_force") {
      found = true;
      EXPECT_NE(r.description.find("VNC"), std::string::npos);
    }
  }
  EXPECT_TRUE(found) << "Expected brute_force to fire for VNC port";
}

TEST_F(HeuristicRuleEngineTest, evaluate_bruteForce_sshPort_mentionsSSH) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.dstPort = 22; // SSH
  flow.totalFwdPackets = 100;
  flow.totalBwdPackets = 50;
  flow.flowDurationUs = 1'000'000;
  auto results = engine_.evaluate(flow);

  bool found = false;
  for (const auto &r : results) {
    if (r.ruleName == "brute_force") {
      found = true;
      EXPECT_NE(r.description.find("SSH"), std::string::npos);
    }
  }
  EXPECT_TRUE(found) << "Expected brute_force to fire for SSH port";
}

// ── Severity boundary tests ──────────────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_synFlood_severityCappedAtOne) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.synFlagCount = 10000;
  flow.ackFlagCount = 1; // ratio 10000.0
  flow.totalFwdPackets = 10000;
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    if (r.ruleName == "syn_flood") {
      EXPECT_LE(r.severity, 1.0f);
    }
  }
}

TEST_F(HeuristicRuleEngineTest, evaluate_icmpFlood_severityCappedAtOne) {
  auto flow = makeBenignFlow();
  flow.protocol = 1;
  flow.totalFwdPackets = 50000;
  flow.totalBwdPackets = 50000;
  flow.flowDurationUs = 1'000'000; // 1s → rate = 100000
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    if (r.ruleName == "icmp_flood") {
      EXPECT_LE(r.severity, 1.0f);
    }
  }
}

TEST_F(HeuristicRuleEngineTest, evaluate_bruteForce_severityCappedAtOne) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.dstPort = 22;
  flow.totalFwdPackets = 5000;
  flow.totalBwdPackets = 5000;
  flow.flowDurationUs = 1'000'000; // rate = 10000
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    if (r.ruleName == "brute_force") {
      EXPECT_LE(r.severity, 1.0f);
    }
  }
}

TEST_F(HeuristicRuleEngineTest, evaluate_highPacketRate_severityCappedAtOne) {
  auto flow = makeBenignFlow();
  flow.totalFwdPackets = 100000;
  flow.totalBwdPackets = 100000;
  flow.flowDurationUs = 1'000'000; // rate = 200000
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    if (r.ruleName == "high_packet_rate") {
      EXPECT_LE(r.severity, 1.0f);
    }
  }
}

TEST_F(HeuristicRuleEngineTest, evaluate_resetFlood_severityCappedAtOne) {
  auto flow = makeBenignFlow();
  flow.protocol = 6;
  flow.rstFlagCount = 100;
  flow.totalFwdPackets = 100;
  flow.totalBwdPackets = 0; // ratio = 100/100 = 1.0
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    if (r.ruleName == "reset_flood") {
      EXPECT_LE(r.severity, 1.0f);
      EXPECT_FLOAT_EQ(r.severity, 1.0f);
    }
  }
}

// ── All suspicious port values covered ───────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_allSuspiciousPorts_detected) {
  // Ensure each suspicious port triggers the rule.
  const std::vector<std::uint16_t> suspiciousPorts = {
      4444, 5555, 31337, 1337, 12345, 54321,
      6666, 6667, 6668,  6669, 8888,  9999};

  for (auto port : suspiciousPorts) {
    auto flow = makeBenignFlow();
    flow.dstPort = port;
    auto results = engine_.evaluate(flow);

    bool found = false;
    for (const auto &r : results) {
      if (r.ruleName == "suspicious_port") {
        found = true;
      }
    }
    EXPECT_TRUE(found) << "Expected suspicious_port rule for port " << port;
  }
}

// ── SYN flood: non-TCP protocol check ────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_synFlood_icmpProtocol_doesNotFire) {
  auto flow = makeBenignFlow();
  flow.protocol = 1; // ICMP, not TCP
  flow.synFlagCount = 500;
  flow.ackFlagCount = 0;
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    EXPECT_NE(r.ruleName, "syn_flood")
        << "syn_flood should not fire for ICMP protocol";
  }
}

// ── Port scan: exactly at threshold ──────────────────────────────────

TEST_F(HeuristicRuleEngineTest, evaluatePortScan_exactlyAtThreshold_fires) {
  std::vector<std::uint16_t> ports;
  for (std::uint16_t i = 1; i <= 20; ++i) {
    ports.push_back(i);
  }
  auto results = engine_.evaluatePortScan("10.0.0.1", ports);
  EXPECT_FALSE(results.empty());
  EXPECT_EQ(results[0].ruleName, "port_scan");
}

// ── Non-TCP protocols vs brute force / reset flood ───────────────────

TEST_F(HeuristicRuleEngineTest, evaluate_udpFlow_noTcpRules) {
  auto flow = makeBenignFlow();
  flow.protocol = 17;
  flow.synFlagCount = 1000; // Would trigger syn_flood if TCP
  flow.ackFlagCount = 0;
  flow.rstFlagCount = 100; // Would trigger reset_flood if TCP
  flow.dstPort = 22;       // Would trigger brute_force if TCP
  auto results = engine_.evaluate(flow);

  for (const auto &r : results) {
    EXPECT_TRUE(r.ruleName != "syn_flood")
        << "syn_flood should not fire for UDP";
    EXPECT_TRUE(r.ruleName != "brute_force")
        << "brute_force should not fire for UDP";
    EXPECT_TRUE(r.ruleName != "reset_flood")
        << "reset_flood should not fire for UDP";
  }
}
