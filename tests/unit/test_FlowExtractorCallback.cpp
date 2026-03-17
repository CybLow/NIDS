#include "infra/flow/NativeFlowExtractor.h"
#include "helpers/PcapTestHelpers.h"
#include "helpers/TestHelpers.h"

#include <filesystem>
#include <gtest/gtest.h>

using nids::core::kFlowFeatureCount;
using nids::infra::NativeFlowExtractor;
using nids::testing::buildTcpPacket;
using nids::testing::buildUdpPacket;
using nids::testing::PcapPacketEntry;
using nids::testing::writePcapFile;

namespace fs = std::filesystem;

// ── Flow completion callback ────────────────────────────────────────

TEST(NativeFlowExtractor, FlowCompletionCallback_firedOnTcpFin) {
  SKIP_IF_NO_PCAP();

  auto syn = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto fin = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x11); // FIN+ACK

  auto path = writePcapFile("nfe_cb_fin.pcap", {
                                                    {syn, 0, 0},
                                                    {fin, 0, 100'000},
                                                });

  NativeFlowExtractor extractor;
  std::vector<std::vector<float>> callbackFeatures;
  std::vector<nids::core::FlowInfo> callbackMetadata;

  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&& features, nids::core::FlowInfo&& info) {
        callbackFeatures.push_back(std::move(features));
        callbackMetadata.push_back(std::move(info));
      });

  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 1u);
  EXPECT_EQ(callbackFeatures.size(), 1u);
  EXPECT_EQ(callbackFeatures[0].size(),
            static_cast<std::size_t>(kFlowFeatureCount));
  EXPECT_EQ(callbackMetadata[0].srcIp, "10.0.0.1");
  EXPECT_EQ(callbackMetadata[0].dstIp, "10.0.0.2");
  EXPECT_EQ(callbackMetadata[0].dstPort, 80);
}

TEST(NativeFlowExtractor, FlowCompletionCallback_firedOnMaxPackets) {
  SKIP_IF_NO_PCAP();

  std::vector<PcapPacketEntry> packets;
  for (std::uint32_t i = 0; i < 250; ++i) {
    auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
    packets.emplace_back(pkt, i / 1000, (i % 1000) * 1000);
  }

  auto path = writePcapFile("nfe_cb_maxpkt.pcap", packets);

  NativeFlowExtractor extractor;
  int callbackCount = 0;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&&, nids::core::FlowInfo&&) { ++callbackCount; });

  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_GE(features.size(), 2u);
  EXPECT_EQ(callbackCount, static_cast<int>(features.size()));
}

TEST(NativeFlowExtractor, FlowCompletionCallback_firedOnEndOfCapture) {
  SKIP_IF_NO_PCAP();

  auto pkt = buildUdpPacket("10.0.0.1", "10.0.0.2", 5000, 53);
  auto path = writePcapFile("nfe_cb_eoc.pcap", {{pkt, 0, 0}});

  NativeFlowExtractor extractor;
  int callbackCount = 0;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&&, nids::core::FlowInfo&&) { ++callbackCount; });

  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 1u);
  EXPECT_EQ(callbackCount, 1);
}

TEST(NativeFlowExtractor, FlowCompletionCallback_firedOnSweep) {
  SKIP_IF_NO_PCAP();

  auto pktA = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  auto pktB = buildUdpPacket("10.0.0.3", "10.0.0.4", 6000, 53);
  auto pktC = buildTcpPacket("10.0.0.5", "10.0.0.6", 7000, 443, 0x02);

  auto path = writePcapFile("nfe_cb_sweep.pcap", {
                                                      {pktA, 0, 0},
                                                      {pktB, 0, 100'000},
                                                      {pktC, 700, 0},
                                                  });

  NativeFlowExtractor extractor;
  int callbackCount = 0;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&&, nids::core::FlowInfo&&) { ++callbackCount; });

  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 3u);
  EXPECT_EQ(callbackCount, 3);
}

TEST(NativeFlowExtractor, FlowCompletionCallback_notFiredWhenNull) {
  SKIP_IF_NO_PCAP();

  auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x11); // FIN
  auto path = writePcapFile("nfe_cb_null.pcap", {{pkt, 0, 0}});

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 1u);
}

TEST(NativeFlowExtractor, FlowCompletionCallback_disabledAfterClear) {
  SKIP_IF_NO_PCAP();

  auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x11); // FIN
  auto path = writePcapFile("nfe_cb_clear.pcap", {{pkt, 0, 0}});

  NativeFlowExtractor extractor;
  int callbackCount = 0;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float>&&, nids::core::FlowInfo&&) { ++callbackCount; });

  extractor.setFlowCompletionCallback(nullptr);

  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 1u);
  EXPECT_EQ(callbackCount, 0);
}
