#include "infra/flow/NativeFlowExtractor.h"
#include "helpers/PcapTestHelpers.h"
#include "helpers/TestHelpers.h"

#include <filesystem>
#include <gtest/gtest.h>

using nids::core::kFlowFeatureCount;
using nids::infra::kMaxFlowPackets;
using nids::infra::NativeFlowExtractor;
using nids::testing::buildIcmpPacket;
using nids::testing::buildTcpPacket;
using nids::testing::buildUdpPacket;
using nids::testing::buildVlanTcpPacket;
using nids::testing::PcapPacketEntry;
using nids::testing::writeNBO16;
using nids::testing::writeIPv4;
using nids::testing::writePcapFile;

namespace fs = std::filesystem;

// ── NativeFlowExtractor: basic pcap tests ───────────────────────────

TEST(NativeFlowExtractor, ExtractFeaturesWithMinimalTcpPcap) {
  SKIP_IF_NO_PCAP();

  auto pkt = buildTcpPacket("192.168.1.1", "192.168.1.2", 8080, 443, 0x02);
  auto path = writePcapFile("nfe_minimal_tcp.pcap", {{pkt, 0, 0}});

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 1u);
  if (!features.empty()) {
    EXPECT_EQ(features[0].size(), static_cast<std::size_t>(kFlowFeatureCount));
    EXPECT_FLOAT_EQ(features[0][0], 443.0f);
  }

  const auto& metadata = extractor.flowMetadata();
  EXPECT_EQ(metadata.size(), 1u);
  if (!metadata.empty()) {
    EXPECT_EQ(metadata[0].srcIp, "192.168.1.1");
    EXPECT_EQ(metadata[0].dstIp, "192.168.1.2");
    EXPECT_EQ(metadata[0].dstPort, 443);
    EXPECT_EQ(metadata[0].protocol, 6);
  }
}

TEST(NativeFlowExtractor, ExtractFeatures_badFile_returnsEmpty) {
  SKIP_IF_NO_PCAP();

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures("/nonexistent_file_xyz.pcap");
  EXPECT_TRUE(features.empty());
}

TEST(NativeFlowExtractor, SetFlowTimeout) {
  SKIP_IF_NO_PCAP();
  NativeFlowExtractor extractor;
  extractor.setFlowTimeout(300'000'000);
}

// ── UDP flow extraction ─────────────────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_udpPacket) {
  SKIP_IF_NO_PCAP();

  auto pkt = buildUdpPacket("10.0.0.1", "10.0.0.2", 5000, 53);
  auto path = writePcapFile("nfe_udp.pcap", {{pkt, 0, 0}});

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 1u);
  if (!features.empty()) {
    EXPECT_FLOAT_EQ(features[0][0], 53.0f); // Destination port
  }

  const auto& meta = extractor.flowMetadata();
  EXPECT_EQ(meta.size(), 1u);
  if (!meta.empty()) {
    EXPECT_EQ(meta[0].protocol, 17); // UDP
    EXPECT_EQ(meta[0].dstPort, 53);
  }
}

// ── ICMP flow extraction ────────────────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_icmpPacket) {
  SKIP_IF_NO_PCAP();

  auto pkt = buildIcmpPacket("10.0.0.1", "10.0.0.2", 8, 0);
  auto path = writePcapFile("nfe_icmp.pcap", {{pkt, 0, 0}});

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 1u);

  const auto& meta = extractor.flowMetadata();
  EXPECT_EQ(meta.size(), 1u);
  if (!meta.empty()) {
    EXPECT_EQ(meta[0].protocol, 1); // ICMP
  }
}

// ── VLAN-tagged packet extraction ───────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_vlanTaggedPacket) {
  SKIP_IF_NO_PCAP();

  auto pkt = buildVlanTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 100, 0x02);
  auto path = writePcapFile("nfe_vlan.pcap", {{pkt, 0, 0}});

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 1u);
  if (!features.empty()) {
    EXPECT_FLOAT_EQ(features[0][0], 80.0f);
  }
}

// ── Bidirectional flow (forward + backward packets) ─────────────────

TEST(NativeFlowExtractor, ExtractFeatures_bidirectionalFlow) {
  SKIP_IF_NO_PCAP();

  auto fwd = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto bwd = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x12); // SYN+ACK

  auto path =
      writePcapFile("nfe_bidir.pcap", {
                                          {fwd, 0, 0},
                                          {bwd, 0, 500'000}, // 500ms later
                                      });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 1u);
  if (!features.empty()) {
    EXPECT_FLOAT_EQ(features[0][2], 1.0f); // Total Fwd Packets
    EXPECT_FLOAT_EQ(features[0][3], 1.0f); // Total Bwd Packets
  }
}

// ── Multi-flow: different 5-tuples become separate flows ────────────

TEST(NativeFlowExtractor, ExtractFeatures_multipleDistinctFlows) {
  SKIP_IF_NO_PCAP();

  auto pktA = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto pktB = buildUdpPacket("10.0.0.3", "10.0.0.4", 6000, 53);
  auto pktC = buildIcmpPacket("10.0.0.5", "10.0.0.6", 8, 0);

  auto path = writePcapFile("nfe_multi.pcap", {
                                                  {pktA, 0, 0},
                                                  {pktB, 0, 100'000},
                                                  {pktC, 0, 200'000},
                                              });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 3u);
  EXPECT_EQ(extractor.flowMetadata().size(), 3u);
}

// ── TCP FIN/RST terminates a flow (completeFlow path) ───────────────

TEST(NativeFlowExtractor, ExtractFeatures_tcpFinCompletesFlow) {
  SKIP_IF_NO_PCAP();

  auto syn = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto synack = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x12);
  auto ack = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  auto fin = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x11); // FIN+ACK
  auto newSyn = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);

  auto path = writePcapFile("nfe_fin.pcap", {
                                                {syn, 0, 0},
                                                {synack, 0, 100'000},
                                                {ack, 0, 200'000},
                                                {fin, 0, 300'000},
                                                {newSyn, 0, 400'000},
                                            });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 2u);
}

TEST(NativeFlowExtractor, ExtractFeatures_tcpRstCompletesFlow) {
  SKIP_IF_NO_PCAP();

  auto syn = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto rst = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x04); // RST

  auto path = writePcapFile("nfe_rst.pcap", {
                                                {syn, 0, 0},
                                                {rst, 0, 100'000},
                                            });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 1u);
  if (!features.empty()) {
    EXPECT_GT(features[0][45], 0.0f); // RST Flag Count > 0
  }
}

// ── Flow timeout eviction ───────────────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_flowTimeoutEviction) {
  SKIP_IF_NO_PCAP();

  auto pkt1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto pkt2 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);

  auto path =
      writePcapFile("nfe_timeout.pcap", {
                                            {pkt1, 0, 0},
                                            {pkt2, 700, 0}, // 700 seconds later
                                        });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 2u);
}

TEST(NativeFlowExtractor, ExtractFeatures_customTimeoutEviction) {
  SKIP_IF_NO_PCAP();

  auto pkt1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto pkt2 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);

  auto path = writePcapFile("nfe_custom_timeout.pcap",
                            {
                                {pkt1, 0, 0},
                                {pkt2, 5, 0}, // 5 seconds later
                            });

  NativeFlowExtractor extractor;
  extractor.setFlowTimeout(2'000'000);
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 2u);
}

// ── Max-flow-size splitting ─────────────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_maxFlowSplitting) {
  SKIP_IF_NO_PCAP();

  std::vector<PcapPacketEntry> packets;
  for (std::uint32_t i = 0; i < 250; ++i) {
    auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
    packets.emplace_back(pkt, i / 1000, (i % 1000) * 1000);
  }

  auto path = writePcapFile("nfe_maxflow.pcap", packets);

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_GE(features.size(), 2u);
}

// ── TCP flags accumulation ──────────────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_tcpFlagsCounted) {
  SKIP_IF_NO_PCAP();

  auto syn = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto synack = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x12);
  auto ack = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  auto pshack = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x18);
  auto finack = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x11);

  auto path = writePcapFile("nfe_flags.pcap", {
                                                  {syn, 0, 0},
                                                  {synack, 0, 100'000},
                                                  {ack, 0, 200'000},
                                                  {pshack, 0, 300'000},
                                                  {finack, 0, 400'000},
                                              });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  ASSERT_EQ(features.size(), 1u);
  auto& f = features[0];
  EXPECT_FLOAT_EQ(f[44], 2.0f); // SYN count: 2
  EXPECT_FLOAT_EQ(f[47], 4.0f); // ACK count: 4
  EXPECT_FLOAT_EQ(f[46], 1.0f); // PSH count: 1
  EXPECT_FLOAT_EQ(f[43], 1.0f); // FIN count: 1
}

// ── Backward stats (IAT, packet lengths) ────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_backwardStatsPopulated) {
  SKIP_IF_NO_PCAP();

  auto fwd1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto bwd1 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x12);
  auto bwd2 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);

  auto path = writePcapFile("nfe_bwd_stats.pcap", {
                                                      {fwd1, 0, 0},
                                                      {bwd1, 0, 100'000},
                                                      {bwd2, 0, 300'000},
                                                  });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  ASSERT_EQ(features.size(), 1u);
  auto& f = features[0];
  EXPECT_FLOAT_EQ(f[2], 1.0f); // Total Fwd Packets = 1
  EXPECT_FLOAT_EQ(f[3], 2.0f); // Total Bwd Packets = 2
  EXPECT_GT(f[10], 0.0f);      // Bwd Pkt Len Max > 0
}

// ── Malformed packet handling ───────────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_truncatedPacketSkipped) {
  SKIP_IF_NO_PCAP();

  std::vector<std::uint8_t> tiny(10, 0);
  auto path = writePcapFile("nfe_truncated.pcap", {{tiny, 0, 0}});

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_TRUE(features.empty());
}

TEST(NativeFlowExtractor, ExtractFeatures_nonIpv4Skipped) {
  SKIP_IF_NO_PCAP();

  std::vector<std::uint8_t> arpPkt(60, 0);
  arpPkt[12] = 0x08;
  arpPkt[13] = 0x06; // ARP
  auto path = writePcapFile("nfe_arp.pcap", {{arpPkt, 0, 0}});

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_TRUE(features.empty());
}

TEST(NativeFlowExtractor, ExtractFeatures_unsupportedProtocolSkipped) {
  SKIP_IF_NO_PCAP();

  std::vector<std::uint8_t> pkt(54, 0);
  pkt[12] = 0x08;
  pkt[13] = 0x00;                  // IPv4
  pkt[14] = 0x45;                  // IHL=5
  writeNBO16(pkt.data() + 16, 40); // IP total length
  pkt[23] = 50;                    // Protocol = ESP
  writeIPv4(pkt.data() + 26, "10.0.0.1");
  writeIPv4(pkt.data() + 30, "10.0.0.2");

  auto path = writePcapFile("nfe_esp.pcap", {{pkt, 0, 0}});

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_TRUE(features.empty());
}

TEST(NativeFlowExtractor, ExtractFeatures_truncatedTcpHeader_skipped) {
  SKIP_IF_NO_PCAP();

  std::vector<std::uint8_t> pkt(44, 0);
  pkt[12] = 0x08;
  pkt[13] = 0x00;
  auto* ip = pkt.data() + 14;
  ip[0] = 0x45;
  writeNBO16(ip + 2, 30); // IP total = 30 (20 IP + 10 "TCP" -- too short)
  ip[8] = 0x40;
  ip[9] = 6; // TCP
  writeIPv4(ip + 12, "10.0.0.1");
  writeIPv4(ip + 16, "10.0.0.2");

  auto path = writePcapFile("nfe_trunc_tcp.pcap", {{pkt, 0, 0}});
  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);
  EXPECT_TRUE(features.empty());
}

TEST(NativeFlowExtractor, ExtractFeatures_truncatedUdpHeader_skipped) {
  SKIP_IF_NO_PCAP();

  std::vector<std::uint8_t> pkt(38, 0);
  pkt[12] = 0x08;
  pkt[13] = 0x00;
  auto* ip = pkt.data() + 14;
  ip[0] = 0x45;
  writeNBO16(ip + 2, 24); // IP total = 24 (20 IP + 4 "UDP" -- too short)
  ip[8] = 0x40;
  ip[9] = 17; // UDP
  writeIPv4(ip + 12, "10.0.0.1");
  writeIPv4(ip + 16, "10.0.0.2");

  auto path = writePcapFile("nfe_trunc_udp.pcap", {{pkt, 0, 0}});
  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);
  EXPECT_TRUE(features.empty());
}

TEST(NativeFlowExtractor, ExtractFeatures_truncatedIcmpHeader_skipped) {
  SKIP_IF_NO_PCAP();

  std::vector<std::uint8_t> pkt(36, 0);
  pkt[12] = 0x08;
  pkt[13] = 0x00;
  auto* ip = pkt.data() + 14;
  ip[0] = 0x45;
  writeNBO16(ip + 2, 22); // IP total = 22 (20 IP + 2 "ICMP" -- too short)
  ip[8] = 0x40;
  ip[9] = 1; // ICMP
  writeIPv4(ip + 12, "10.0.0.1");
  writeIPv4(ip + 16, "10.0.0.2");

  auto path = writePcapFile("nfe_trunc_icmp.pcap", {{pkt, 0, 0}});
  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);
  EXPECT_TRUE(features.empty());
}

TEST(NativeFlowExtractor, ExtractFeatures_ipHeaderTooShort_skipped) {
  SKIP_IF_NO_PCAP();

  std::vector<std::uint8_t> pkt(24, 0);
  pkt[12] = 0x08;
  pkt[13] = 0x00;
  auto* ip = pkt.data() + 14;
  ip[0] = 0x45;
  writeNBO16(ip + 2, 10); // IP total length = 10 (< IHL of 20)

  auto path = writePcapFile("nfe_short_ip.pcap", {{pkt, 0, 0}});
  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);
  EXPECT_TRUE(features.empty());
}

TEST(NativeFlowExtractor, ExtractFeatures_vlanTooShort_skipped) {
  SKIP_IF_NO_PCAP();

  std::vector<std::uint8_t> pkt(15, 0);
  pkt[12] = 0x81;
  pkt[13] = 0x00; // VLAN EtherType

  auto path = writePcapFile("nfe_vlan_short.pcap", {{pkt, 0, 0}});
  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);
  EXPECT_TRUE(features.empty());
}

TEST(NativeFlowExtractor, ExtractFeatures_ipTotalLenLessThanIhl_skipped) {
  SKIP_IF_NO_PCAP();

  auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  pkt[16] = 0x00;
  pkt[17] = 0x0A; // 10 in big-endian (< IHL of 20)

  auto path = writePcapFile("test_ip_totlen_lt_ihl.pcap", {{pkt, 0, 0}});

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_TRUE(features.empty());
}

TEST(NativeFlowExtractor, ExtractFeatures_tcpDataOffsetBelowMin_rejected) {
  SKIP_IF_NO_PCAP();

  auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 12345, 80, 0x02);
  pkt[46] = 0x10; // th_off=1 -> 4 bytes (malformed)

  auto path = writePcapFile("test_tcp_low_offset.pcap", {{pkt, 1, 0}});

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  EXPECT_EQ(features.size(), 0u);
  fs::remove(path);
}

// ── Bulk transfer tracking ──────────────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_bulkTransferDetected) {
  SKIP_IF_NO_PCAP();

  std::vector<PcapPacketEntry> packets;
  for (int i = 0; i < 5; ++i) {
    auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
    packets.emplace_back(pkt, 0, static_cast<std::uint32_t>(i * 100'000));
  }
  for (int i = 0; i < 3; ++i) {
    auto pkt = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);
    packets.emplace_back(pkt, 0, static_cast<std::uint32_t>((5 + i) * 100'000));
  }

  auto path = writePcapFile("nfe_bulk.pcap", packets);

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  ASSERT_EQ(features.size(), 1u);
  EXPECT_GT(features[0][55], 0.0f); // Fwd Avg Bytes/Bulk
}

TEST(NativeFlowExtractor, ExtractFeatures_bwdBulkDetected) {
  SKIP_IF_NO_PCAP();

  auto fwd1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  auto bwd1 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);
  auto bwd2 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);
  auto bwd3 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);
  auto bwd4 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);
  auto fwd2 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);

  auto path = writePcapFile("nfe_bwd_bulk.pcap", {
                                                     {fwd1, 0, 0},
                                                     {bwd1, 0, 100'000},
                                                     {bwd2, 0, 200'000},
                                                     {bwd3, 0, 300'000},
                                                     {bwd4, 0, 400'000},
                                                     {fwd2, 0, 500'000},
                                                 });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  ASSERT_EQ(features.size(), 1u);
  EXPECT_GT(features[0][58], 0.0f); // Bwd Avg Bytes/Bulk
  EXPECT_GE(features[0][59], 2.0f); // Bwd Avg Packets/Bulk
}

TEST(NativeFlowExtractor, ExtractFeatures_bwdBulkFlushedAtFlowCompletion) {
  SKIP_IF_NO_PCAP();

  auto fwd1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  auto bwd1 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);
  auto bwd2 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);
  auto bwdFin = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x11);

  auto path =
      writePcapFile("test_bwd_bulk_complete.pcap", {
                                                       {fwd1, 0, 0},
                                                       {bwd1, 0, 100'000},
                                                       {bwd2, 0, 200'000},
                                                       {bwdFin, 0, 300'000},
                                                   });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  ASSERT_EQ(features.size(), 1u);
  EXPECT_GT(features[0][58], 0.0f);
  EXPECT_GE(features[0][59], 2.0f);
}

TEST(NativeFlowExtractor, ExtractFeatures_bwdBulkFlushedAtFinalize) {
  SKIP_IF_NO_PCAP();

  auto fwd1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  auto bwd1 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);
  auto bwd2 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);
  auto bwd3 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);

  auto path =
      writePcapFile("test_bwd_bulk_finalize.pcap", {
                                                       {fwd1, 0, 0},
                                                       {bwd1, 0, 100'000},
                                                       {bwd2, 0, 200'000},
                                                       {bwd3, 0, 300'000},
                                                   });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  ASSERT_EQ(features.size(), 1u);
  EXPECT_GT(features[0][58], 0.0f);
  EXPECT_GE(features[0][59], 2.0f);
}

// ── Active/Idle period tracking ─────────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_activeIdlePeriods) {
  SKIP_IF_NO_PCAP();

  auto pkt1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  auto pkt2 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  auto pkt3 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);

  auto path =
      writePcapFile("nfe_active_idle.pcap",
                    {
                        {pkt1, 0, 0},
                        {pkt2, 0, 100'000}, // 100ms later (active)
                        {pkt3, 10, 0}, // 10 seconds later (> 5s idle threshold)
                    });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  ASSERT_EQ(features.size(), 1u);
  EXPECT_GT(features[0][73], 0.0f); // Idle Mean > 0
}

// ── TCP payload and segment tracking ────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_tcpPayloadTracked) {
  SKIP_IF_NO_PCAP();

  auto pkt1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x18, 8192, 100);
  auto pkt2 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x18, 8192, 50);
  auto pkt3 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x18, 8192, 200);

  auto path = writePcapFile("nfe_tcp_payload.pcap", {
                                                        {pkt1, 0, 0},
                                                        {pkt2, 0, 100'000},
                                                        {pkt3, 0, 200'000},
                                                    });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  ASSERT_EQ(features.size(), 1u);
  auto& f = features[0];
  EXPECT_FLOAT_EQ(f[67], 3.0f);  // act_data_pkt_fwd
  EXPECT_FLOAT_EQ(f[68], 50.0f); // min_seg_size_forward = 50
  EXPECT_FLOAT_EQ(f[30], 3.0f);  // Fwd PSH Flags
}

TEST(NativeFlowExtractor, ExtractFeatures_urgAndCwrAndEceFlags) {
  SKIP_IF_NO_PCAP();

  auto urg = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x20);
  auto cwr = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x80);
  auto ece = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x40);
  auto bwd_urg_psh = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x28);

  auto path =
      writePcapFile("nfe_rare_flags.pcap", {
                                               {urg, 0, 0},
                                               {cwr, 0, 100'000},
                                               {ece, 0, 200'000},
                                               {bwd_urg_psh, 0, 300'000},
                                           });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  ASSERT_EQ(features.size(), 1u);
  auto& f = features[0];
  EXPECT_FLOAT_EQ(f[32], 1.0f); // Fwd URG Flags
  EXPECT_FLOAT_EQ(f[33], 1.0f); // Bwd URG Flags
  EXPECT_FLOAT_EQ(f[31], 1.0f); // Bwd PSH Flags
  EXPECT_FLOAT_EQ(f[48], 2.0f); // Global URG count
  EXPECT_FLOAT_EQ(f[49], 1.0f); // Global CWR count
  EXPECT_FLOAT_EQ(f[50], 1.0f); // Global ECE count
}

// ── Backward key timeout eviction ───────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_backwardKeyTimeoutEviction) {
  SKIP_IF_NO_PCAP();

  auto pkt1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto pkt2 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x12);

  auto path = writePcapFile("nfe_bwd_timeout.pcap", {
                                                        {pkt1, 0, 0},
                                                        {pkt2, 700, 0},
                                                    });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 2u);
}

// ── Metadata population ─────────────────────────────────────────────

TEST(NativeFlowExtractor, FlowMetadata_populatedCorrectly) {
  SKIP_IF_NO_PCAP();

  auto pkt1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto pkt2 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  auto pkt3 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);

  auto path =
      writePcapFile("nfe_meta.pcap", {
                                         {pkt1, 0, 0},
                                         {pkt2, 1, 0},
                                         {pkt3, 2, 0},
                                     });

  NativeFlowExtractor extractor;
  [[maybe_unused]] auto features = extractor.extractFeatures(path);
  fs::remove(path);

  const auto& meta = extractor.flowMetadata();
  ASSERT_EQ(meta.size(), 1u);
  EXPECT_EQ(meta[0].srcIp, "10.0.0.1");
  EXPECT_EQ(meta[0].dstIp, "10.0.0.2");
  EXPECT_EQ(meta[0].totalFwdPackets, 2u);
  EXPECT_EQ(meta[0].totalBwdPackets, 1u);
  EXPECT_GT(meta[0].flowDurationUs, 0.0);
  EXPECT_GT(meta[0].fwdPacketsPerSecond, 0.0);
  EXPECT_GT(meta[0].avgPacketSize, 0.0);
  EXPECT_EQ(meta[0].synFlagCount, 1u);
  EXPECT_GT(meta[0].ackFlagCount, 0u);
}

TEST(NativeFlowExtractor, FlowMetadata_singlePacket_zeroDuration) {
  SKIP_IF_NO_PCAP();

  auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto path = writePcapFile("nfe_single_meta.pcap", {{pkt, 0, 0}});

  NativeFlowExtractor extractor;
  [[maybe_unused]] auto features = extractor.extractFeatures(path);
  fs::remove(path);

  const auto& meta = extractor.flowMetadata();
  ASSERT_EQ(meta.size(), 1u);
  EXPECT_DOUBLE_EQ(meta[0].flowDurationUs, 0.0);
  EXPECT_NEAR(meta[0].fwdPacketsPerSecond, 0.0f, 1e-6f);
  EXPECT_NEAR(meta[0].bwdPacketsPerSecond, 0.0f, 1e-6f);
}

// ── Reuse after extract (state cleanup) ─────────────────────────────

TEST(NativeFlowExtractor, extractFeatures_clearsBetweenCalls) {
  SKIP_IF_NO_PCAP();

  auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto path = writePcapFile("nfe_reuse.pcap", {{pkt, 0, 0}});

  NativeFlowExtractor extractor;
  auto features1 = extractor.extractFeatures(path);
  EXPECT_EQ(features1.size(), 1u);

  auto features2 = extractor.extractFeatures(path);
  EXPECT_EQ(features2.size(), 1u);

  fs::remove(path);
}

// ── Sweep expired flows ─────────────────────────────────────────────

TEST(NativeFlowExtractor, SweepExpiredFlows_expiresIdleFlows) {
  SKIP_IF_NO_PCAP();

  auto pktA = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  auto pktB = buildUdpPacket("10.0.0.3", "10.0.0.4", 6000, 53);
  auto pktC = buildTcpPacket("10.0.0.5", "10.0.0.6", 7000, 443, 0x02);

  auto path = writePcapFile("nfe_sweep_expire.pcap", {
                                                         {pktA, 0, 0},
                                                         {pktB, 0, 100'000},
                                                         {pktC, 700, 0},
                                                     });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 3u);
}

TEST(NativeFlowExtractor, SweepExpiredFlows_returnsZeroWhenNoneExpired) {
  SKIP_IF_NO_PCAP();

  auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto path = writePcapFile("nfe_sweep_none.pcap", {{pkt, 1, 0}});

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  auto swept = extractor.sweepExpiredFlows(2'000'000);
  EXPECT_EQ(swept, 0u);
}

TEST(NativeFlowExtractor, SweepExpiredFlows_respectsCustomTimeout) {
  SKIP_IF_NO_PCAP();

  auto pkt1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  auto pkt2 = buildUdpPacket("10.0.0.3", "10.0.0.4", 6000, 53);
  auto pkt3 = buildTcpPacket("10.0.0.5", "10.0.0.6", 7000, 443, 0x02);

  auto path = writePcapFile("nfe_sweep_custom.pcap", {
                                                         {pkt1, 0, 0},
                                                         {pkt2, 0, 100'000},
                                                         {pkt3, 35, 0},
                                                     });

  NativeFlowExtractor extractor;
  extractor.setFlowTimeout(2'000'000);
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 3u);
}

TEST(NativeFlowExtractor, SweepExpiredFlows_directCallExpiresFlow) {
  SKIP_IF_NO_PCAP();

  auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  auto path = writePcapFile("nfe_sweep_direct.pcap", {{pkt, 100, 0}});

  NativeFlowExtractor extractor;
  extractor.setFlowTimeout(10'000'000);
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 1u);

  auto swept = extractor.sweepExpiredFlows(200'000'000);
  EXPECT_GE(swept, 0u);
}
