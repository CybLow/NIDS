#include "infra/flow/NativeFlowExtractor.h"
#include "helpers/PcapTestHelpers.h"
#include "helpers/TestHelpers.h"

#include <filesystem>
#include <gtest/gtest.h>

using nids::core::kFlowFeatureCount;
using nids::infra::NativeFlowExtractor;
using nids::testing::buildIcmpPacket;
using nids::testing::buildTcpPacket;
using nids::testing::buildUdpPacket;
using nids::testing::writePcapFile;

namespace fs = std::filesystem;

// ═══════════════════════════════════════════════════════════════════════
// ── Live packet processing API (Phase 8.6) ──────────────────────────
// ═══════════════════════════════════════════════════════════════════════

TEST(NativeFlowExtractor, ProcessPacket_singleTcpPacket) {
  NativeFlowExtractor extractor;
  auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);

  std::vector<std::vector<float>> cbFeatures;
  std::vector<nids::core::FlowInfo> cbMeta;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&& f, nids::core::FlowInfo&& info) {
        cbFeatures.push_back(std::move(f));
        cbMeta.push_back(std::move(info));
      });

  extractor.processPacket(pkt.data(), pkt.size(), 1'000'000);

  EXPECT_EQ(cbFeatures.size(), 0u);

  extractor.finalizeAllFlows();
  EXPECT_EQ(cbFeatures.size(), 1u);
  EXPECT_EQ(cbFeatures[0].size(), static_cast<std::size_t>(kFlowFeatureCount));
  EXPECT_EQ(cbMeta[0].srcIp, "10.0.0.1");
  EXPECT_EQ(cbMeta[0].dstIp, "10.0.0.2");
  EXPECT_EQ(cbMeta[0].dstPort, 80);
  EXPECT_EQ(cbMeta[0].protocol, 6);
}

TEST(NativeFlowExtractor, ProcessPacket_tcpFinCompletesFlow) {
  NativeFlowExtractor extractor;
  auto syn = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto fin = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x11);

  int cbCount = 0;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&&, nids::core::FlowInfo&&) { ++cbCount; });

  extractor.processPacket(syn.data(), syn.size(), 1'000'000);
  EXPECT_EQ(cbCount, 0);

  extractor.processPacket(fin.data(), fin.size(), 2'000'000);
  EXPECT_EQ(cbCount, 1);
}

TEST(NativeFlowExtractor, ProcessPacket_tcpRstCompletesFlow) {
  NativeFlowExtractor extractor;
  auto syn = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto rst = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x04);

  int cbCount = 0;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&&, nids::core::FlowInfo&&) { ++cbCount; });

  extractor.processPacket(syn.data(), syn.size(), 1'000'000);
  extractor.processPacket(rst.data(), rst.size(), 2'000'000);
  EXPECT_EQ(cbCount, 1);
}

TEST(NativeFlowExtractor, ProcessPacket_bidirectionalFlow) {
  NativeFlowExtractor extractor;
  auto fwd = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto bwd = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x12);

  std::vector<nids::core::FlowInfo> cbMeta;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&&, nids::core::FlowInfo&& info) {
        cbMeta.push_back(std::move(info));
      });

  extractor.processPacket(fwd.data(), fwd.size(), 1'000'000);
  extractor.processPacket(bwd.data(), bwd.size(), 2'000'000);

  EXPECT_EQ(cbMeta.size(), 0u);

  extractor.finalizeAllFlows();
  ASSERT_EQ(cbMeta.size(), 1u);
  EXPECT_EQ(cbMeta[0].totalFwdPackets, 1u);
  EXPECT_EQ(cbMeta[0].totalBwdPackets, 1u);
}

TEST(NativeFlowExtractor, ProcessPacket_udpPacket) {
  NativeFlowExtractor extractor;
  auto pkt = buildUdpPacket("10.0.0.1", "10.0.0.2", 5000, 53);

  std::vector<nids::core::FlowInfo> cbMeta;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&&, nids::core::FlowInfo&& info) {
        cbMeta.push_back(std::move(info));
      });

  extractor.processPacket(pkt.data(), pkt.size(), 1'000'000);
  extractor.finalizeAllFlows();

  ASSERT_EQ(cbMeta.size(), 1u);
  EXPECT_EQ(cbMeta[0].protocol, 17);
  EXPECT_EQ(cbMeta[0].dstPort, 53);
}

TEST(NativeFlowExtractor, ProcessPacket_icmpPacket) {
  NativeFlowExtractor extractor;
  auto pkt = buildIcmpPacket("10.0.0.1", "10.0.0.2", 8, 0);

  std::vector<nids::core::FlowInfo> cbMeta;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&&, nids::core::FlowInfo&& info) {
        cbMeta.push_back(std::move(info));
      });

  extractor.processPacket(pkt.data(), pkt.size(), 1'000'000);
  extractor.finalizeAllFlows();

  ASSERT_EQ(cbMeta.size(), 1u);
  EXPECT_EQ(cbMeta[0].protocol, 1);
}

TEST(NativeFlowExtractor, ProcessPacket_nonIpv4Skipped) {
  NativeFlowExtractor extractor;

  std::vector<std::uint8_t> arpPkt(60, 0);
  arpPkt[12] = 0x08;
  arpPkt[13] = 0x06; // ARP

  int cbCount = 0;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&&, nids::core::FlowInfo&&) { ++cbCount; });

  extractor.processPacket(arpPkt.data(), arpPkt.size(), 1'000'000);
  extractor.finalizeAllFlows();

  EXPECT_EQ(cbCount, 0);
}

TEST(NativeFlowExtractor, ProcessPacket_maxFlowSplitting) {
  NativeFlowExtractor extractor;

  int cbCount = 0;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&&, nids::core::FlowInfo&&) { ++cbCount; });

  for (std::uint32_t i = 0; i < 250; ++i) {
    auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
    extractor.processPacket(pkt.data(), pkt.size(),
                            static_cast<std::int64_t>(i) * 1'000);
  }

  EXPECT_GE(cbCount, 1);

  extractor.finalizeAllFlows();
  EXPECT_GE(cbCount, 2);
}

TEST(NativeFlowExtractor, ProcessPacket_periodicSweep) {
  NativeFlowExtractor extractor;
  extractor.setFlowTimeout(10'000'000);

  int cbCount = 0;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&&, nids::core::FlowInfo&&) { ++cbCount; });

  auto pktA = buildUdpPacket("10.0.0.1", "10.0.0.2", 5000, 53);
  extractor.processPacket(pktA.data(), pktA.size(), 0);

  auto pktB = buildUdpPacket("10.0.0.3", "10.0.0.4", 6000, 80);
  extractor.processPacket(pktB.data(), pktB.size(), 31'000'000);

  EXPECT_GE(cbCount, 1);

  extractor.finalizeAllFlows();
  EXPECT_EQ(cbCount, 2);
}

TEST(NativeFlowExtractor, ProcessPacket_featureVectorMatchesBatchMode) {
  SKIP_IF_NO_PCAP();

  auto syn = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto ack = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  auto bwd = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x12);

  // Batch mode
  auto path = writePcapFile("nfe_live_vs_batch.pcap", {
                                                          {syn, 1, 0},
                                                          {ack, 1, 500'000},
                                                          {bwd, 2, 0},
                                                      });
  NativeFlowExtractor batchExtractor;
  auto batchFeatures = batchExtractor.extractFeatures(path);
  fs::remove(path);

  // Live mode
  NativeFlowExtractor liveExtractor;
  std::vector<std::vector<float>> liveFeatures;
  liveExtractor.setFlowCompletionCallback(
      [&](std::vector<float>&& f, nids::core::FlowInfo&&) {
        liveFeatures.push_back(std::move(f));
      });

  liveExtractor.processPacket(syn.data(), syn.size(), 1'000'000);
  liveExtractor.processPacket(ack.data(), ack.size(), 1'500'000);
  liveExtractor.processPacket(bwd.data(), bwd.size(), 2'000'000);
  liveExtractor.finalizeAllFlows();

  ASSERT_EQ(batchFeatures.size(), liveFeatures.size());
  ASSERT_EQ(batchFeatures.size(), 1u);

  ASSERT_EQ(batchFeatures[0].size(), liveFeatures[0].size());
  for (std::size_t i = 0; i < batchFeatures[0].size(); ++i) {
    EXPECT_FLOAT_EQ(batchFeatures[0][i], liveFeatures[0][i])
        << "Feature " << i << " differs between batch and live mode";
  }
}

// ── FinalizeAllFlows ────────────────────────────────────────────────

TEST(NativeFlowExtractor, FinalizeAllFlows_multipleActiveFlows) {
  NativeFlowExtractor extractor;

  int cbCount = 0;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&&, nids::core::FlowInfo&&) { ++cbCount; });

  auto pktA = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto pktB = buildUdpPacket("10.0.0.3", "10.0.0.4", 6000, 53);
  auto pktC = buildIcmpPacket("10.0.0.5", "10.0.0.6", 8, 0);

  extractor.processPacket(pktA.data(), pktA.size(), 1'000'000);
  extractor.processPacket(pktB.data(), pktB.size(), 2'000'000);
  extractor.processPacket(pktC.data(), pktC.size(), 3'000'000);

  EXPECT_EQ(cbCount, 0);

  extractor.finalizeAllFlows();
  EXPECT_EQ(cbCount, 3);
}

TEST(NativeFlowExtractor, FinalizeAllFlows_noCallbackSet_noCrash) {
  NativeFlowExtractor extractor;

  auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  extractor.processPacket(pkt.data(), pkt.size(), 1'000'000);

  extractor.finalizeAllFlows();
}

// ── Reset ───────────────────────────────────────────────────────────

TEST(NativeFlowExtractor, Reset_clearsAllState) {
  NativeFlowExtractor extractor;

  int cbCount = 0;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&&, nids::core::FlowInfo&&) { ++cbCount; });

  auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  extractor.processPacket(pkt.data(), pkt.size(), 1'000'000);

  extractor.reset();

  extractor.finalizeAllFlows();
  EXPECT_EQ(cbCount, 0);
}

TEST(NativeFlowExtractor, Reset_allowsNewSession) {
  NativeFlowExtractor extractor;

  std::vector<nids::core::FlowInfo> cbMeta;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&&, nids::core::FlowInfo&& info) {
        cbMeta.push_back(std::move(info));
      });

  auto pkt1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  extractor.processPacket(pkt1.data(), pkt1.size(), 1'000'000);
  extractor.finalizeAllFlows();
  ASSERT_EQ(cbMeta.size(), 1u);
  EXPECT_EQ(cbMeta[0].srcIp, "10.0.0.1");

  cbMeta.clear();
  extractor.reset();

  auto pkt2 = buildUdpPacket("192.168.1.1", "192.168.1.2", 8080, 443);
  extractor.processPacket(pkt2.data(), pkt2.size(), 5'000'000);
  extractor.finalizeAllFlows();

  ASSERT_EQ(cbMeta.size(), 1u);
  EXPECT_EQ(cbMeta[0].srcIp, "192.168.1.1");
  EXPECT_EQ(cbMeta[0].dstPort, 443);
  EXPECT_EQ(cbMeta[0].protocol, 17);
}

// ── Time-window flow splitting ───────────────────────────────────────

TEST(NativeFlowExtractor, ProcessPacket_durationSplit_completesLongFlow) {
  NativeFlowExtractor extractor;
  extractor.setMaxFlowDuration(10'000'000); // 10 seconds

  int cbCount = 0;
  std::vector<nids::core::FlowInfo> cbMeta;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&&, nids::core::FlowInfo&& info) {
        ++cbCount;
        cbMeta.push_back(std::move(info));
      });

  constexpr std::int64_t kBase = 1'000'000'000;
  for (int i = 0; i < 25; ++i) {
    auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
    extractor.processPacket(pkt.data(), pkt.size(),
                            kBase + static_cast<std::int64_t>(i) * 1'000'000);
  }

  EXPECT_GE(cbCount, 2);

  extractor.finalizeAllFlows();
  EXPECT_GE(cbCount, 3);

  for (const auto& m : cbMeta) {
    EXPECT_EQ(m.srcIp, "10.0.0.1");
    EXPECT_EQ(m.dstIp, "10.0.0.2");
    EXPECT_EQ(m.dstPort, 80);
  }
}

TEST(NativeFlowExtractor, ProcessPacket_durationSplit_disabledWhenZero) {
  NativeFlowExtractor extractor;
  extractor.setMaxFlowDuration(0);

  int cbCount = 0;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&&, nids::core::FlowInfo&&) { ++cbCount; });

  constexpr std::int64_t kBase = 1'000'000'000;
  for (int i = 0; i < 20; ++i) {
    auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
    extractor.processPacket(pkt.data(), pkt.size(),
                            kBase + static_cast<std::int64_t>(i) * 1'500'000);
  }

  EXPECT_EQ(cbCount, 0);

  extractor.finalizeAllFlows();
  EXPECT_EQ(cbCount, 1);
}

TEST(NativeFlowExtractor, ProcessPacket_durationSplit_restartsFreshStats) {
  NativeFlowExtractor extractor;
  extractor.setMaxFlowDuration(5'000'000); // 5 seconds

  std::vector<nids::core::FlowInfo> cbMeta;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&&, nids::core::FlowInfo&& info) {
        cbMeta.push_back(std::move(info));
      });

  constexpr std::int64_t kBase = 1'000'000'000;
  auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  extractor.processPacket(pkt.data(), pkt.size(), kBase);
  extractor.processPacket(pkt.data(), pkt.size(), kBase + 2'000'000);
  extractor.processPacket(pkt.data(), pkt.size(), kBase + 4'000'000);
  extractor.processPacket(pkt.data(), pkt.size(), kBase + 6'000'000); // triggers split
  extractor.processPacket(pkt.data(), pkt.size(), kBase + 8'000'000);

  ASSERT_EQ(cbMeta.size(), 1u);
  EXPECT_EQ(cbMeta[0].totalFwdPackets + cbMeta[0].totalBwdPackets, 4u);

  extractor.finalizeAllFlows();
  ASSERT_EQ(cbMeta.size(), 2u);
  EXPECT_EQ(cbMeta[1].totalFwdPackets + cbMeta[1].totalBwdPackets, 1u);
}

TEST(NativeFlowExtractor, ProcessPacket_durationSplit_diagnosticsCounted) {
  NativeFlowExtractor extractor;
  extractor.setMaxFlowDuration(5'000'000);

  extractor.setFlowCompletionCallback(
      [](std::vector<float>&&, nids::core::FlowInfo&&) {});

  constexpr std::int64_t kBase = 1'000'000'000;
  for (int i = 0; i < 10; ++i) {
    auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
    extractor.processPacket(pkt.data(), pkt.size(),
                            kBase + static_cast<std::int64_t>(i) * 1'600'000);
  }

  const auto& diag = extractor.diagCounters();
  EXPECT_EQ(diag.packetsReceived, 10u);
  EXPECT_EQ(diag.packetsParsed, 10u);
  EXPECT_EQ(diag.packetsSkipped, 0u);
  EXPECT_GE(diag.flowsCompletedDuration, 2u);
  EXPECT_EQ(diag.flowsCompletedFinRst, 0u);
  EXPECT_EQ(diag.flowsCompletedMaxPkts, 0u);
}
