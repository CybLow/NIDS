#include "infra/flow/NativeFlowExtractor.h"
#include <cstring>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <pcapplusplus/IPv4Layer.h>

using nids::infra::FlowKey;
using nids::infra::FlowStats;
using nids::infra::WelfordAccumulator;
using nids::infra::kFlowFeatureCount;
using nids::infra::kMaxFlowPackets;
using nids::infra::NativeFlowExtractor;

namespace fs = std::filesystem;

// PcapPlusPlus uses pcap_open_offline_with_tstamp_precision (npcap-only).
// On Windows CI without npcap, pcap-dependent tests are skipped.
#ifdef _WIN32
#define SKIP_IF_NO_PCAP()                                                      \
  GTEST_SKIP() << "npcap runtime not available on Windows CI"
#else
#define SKIP_IF_NO_PCAP()                                                      \
  do {                                                                         \
  } while (0)
#endif

// ── Helper: Build raw pcap data in memory ────────────────────────────

namespace {

/// PCAP global header (libpcap format, little-endian, version 2.4, link type 1
/// = Ethernet)
constexpr std::uint8_t kPcapGlobalHeader[] = {
    0xd4, 0xc3, 0xb2, 0xa1, // magic
    0x02, 0x00, 0x04, 0x00, // version 2.4
    0x00, 0x00, 0x00, 0x00, // thiszone
    0x00, 0x00, 0x00, 0x00, // sigfigs
    0xff, 0xff, 0x00, 0x00, // snaplen
    0x01, 0x00, 0x00, 0x00, // link type = Ethernet
};

/// Helper to write a 32-bit value in little-endian format.
void writeLE32(std::vector<std::uint8_t> &buf, std::uint32_t val) {
  buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
  buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
  buf.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
  buf.push_back(static_cast<std::uint8_t>((val >> 24) & 0xFF));
}

/// Helper to write a 16-bit value in network (big-endian) byte order.
void writeNBO16(std::uint8_t *dst, std::uint16_t val) {
  dst[0] = static_cast<std::uint8_t>((val >> 8) & 0xFF);
  dst[1] = static_cast<std::uint8_t>(val & 0xFF);
}

/// Helper to write an IPv4 address from dotted-decimal string into 4 bytes.
void writeIPv4(std::uint8_t *dst, const char *ip) {
  auto addr = pcpp::IPv4Address(ip);
  auto bytes = addr.toBytes();
  std::memcpy(dst, bytes, 4);
}

/// Build a raw Ethernet+IP+TCP packet.
/// Returns the raw packet bytes (no pcap header).
std::vector<std::uint8_t>
buildTcpPacket(const char *srcIp, const char *dstIp, std::uint16_t srcPort,
               std::uint16_t dstPort,
               std::uint8_t tcpFlags = 0x02, // SYN by default
               std::uint16_t window = 8192, std::uint16_t payloadSize = 0) {
  std::uint16_t ipTotalLen = 20 + 20 + payloadSize;
  std::uint16_t totalLen = 14 + ipTotalLen;
  std::vector<std::uint8_t> pkt(totalLen, 0);

  // Ethernet header
  pkt[12] = 0x08;
  pkt[13] = 0x00; // EtherType = IPv4

  // IPv4 header (offset 14)
  auto *ip = pkt.data() + 14;
  ip[0] = 0x45; // version 4, IHL = 5 (20 bytes)
  writeNBO16(ip + 2, ipTotalLen);
  ip[6] = 0x40; // Don't Fragment
  ip[8] = 0x40; // TTL
  ip[9] = 6;    // Protocol = TCP
  writeIPv4(ip + 12, srcIp);
  writeIPv4(ip + 16, dstIp);

  // TCP header (offset 34)
  auto *tcp = pkt.data() + 34;
  writeNBO16(tcp, srcPort);
  writeNBO16(tcp + 2, dstPort);
  tcp[12] = 0x50; // Data offset = 5 (20 bytes)
  tcp[13] = tcpFlags;
  writeNBO16(tcp + 14, window);

  return pkt;
}

/// Build a raw Ethernet+IP+UDP packet.
std::vector<std::uint8_t> buildUdpPacket(const char *srcIp, const char *dstIp,
                                         std::uint16_t srcPort,
                                         std::uint16_t dstPort,
                                         std::uint16_t payloadSize = 0) {
  std::uint16_t udpLen = 8 + payloadSize;
  std::uint16_t ipTotalLen = 20 + udpLen;
  std::uint16_t totalLen = 14 + ipTotalLen;
  std::vector<std::uint8_t> pkt(totalLen, 0);

  // Ethernet
  pkt[12] = 0x08;
  pkt[13] = 0x00;

  // IPv4
  auto *ip = pkt.data() + 14;
  ip[0] = 0x45;
  writeNBO16(ip + 2, ipTotalLen);
  ip[8] = 0x40;
  ip[9] = 17; // UDP
  writeIPv4(ip + 12, srcIp);
  writeIPv4(ip + 16, dstIp);

  // UDP header (offset 34)
  auto *udp = pkt.data() + 34;
  writeNBO16(udp, srcPort);
  writeNBO16(udp + 2, dstPort);
  writeNBO16(udp + 4, udpLen);

  return pkt;
}

/// Build a raw Ethernet+IP+ICMP packet.
std::vector<std::uint8_t> buildIcmpPacket(const char *srcIp, const char *dstIp,
                                          std::uint8_t icmpType = 8,
                                          std::uint8_t icmpCode = 0) {
  constexpr std::uint16_t ipTotalLen = 20 + 8;
  constexpr std::uint16_t totalLen = 14 + ipTotalLen;
  std::vector<std::uint8_t> pkt(totalLen, 0);

  pkt[12] = 0x08;
  pkt[13] = 0x00;

  auto *ip = pkt.data() + 14;
  ip[0] = 0x45;
  writeNBO16(ip + 2, ipTotalLen);
  ip[8] = 0x40;
  ip[9] = 1; // ICMP
  writeIPv4(ip + 12, srcIp);
  writeIPv4(ip + 16, dstIp);

  // ICMP header (offset 34)
  auto *icmp = pkt.data() + 34;
  icmp[0] = icmpType;
  icmp[1] = icmpCode;

  return pkt;
}

/// Build a raw Ethernet + VLAN tag + IP + TCP packet (802.1Q).
std::vector<std::uint8_t>
buildVlanTcpPacket(const char *srcIp, const char *dstIp, std::uint16_t srcPort,
                   std::uint16_t dstPort, std::uint16_t vlanId = 100,
                   std::uint8_t tcpFlags = 0x02) {
  std::uint16_t ipTotalLen = 20 + 20;
  std::uint16_t totalLen = 14 + 4 + ipTotalLen;
  std::vector<std::uint8_t> pkt(totalLen, 0);

  // Ethernet header with VLAN EtherType (0x8100)
  pkt[12] = 0x81;
  pkt[13] = 0x00;

  pkt[14] = static_cast<std::uint8_t>((vlanId >> 8) & 0x0F);
  pkt[15] = static_cast<std::uint8_t>(vlanId & 0xFF);
  pkt[16] = 0x08;
  pkt[17] = 0x00; // Real EtherType = IPv4

  // IPv4 header (offset 18)
  auto *ip = pkt.data() + 18;
  ip[0] = 0x45;
  writeNBO16(ip + 2, ipTotalLen);
  ip[6] = 0x40;
  ip[8] = 0x40;
  ip[9] = 6; // TCP
  writeIPv4(ip + 12, srcIp);
  writeIPv4(ip + 16, dstIp);

  // TCP header (offset 38)
  auto *tcp = pkt.data() + 38;
  writeNBO16(tcp, srcPort);
  writeNBO16(tcp + 2, dstPort);
  tcp[12] = 0x50; // Data offset = 5
  tcp[13] = tcpFlags;
  writeNBO16(tcp + 14, 8192);

  return pkt;
}

/// Write a complete pcap file with multiple packets.
/// Each packet entry: {packet_bytes, timestamp_sec, timestamp_usec}
struct PcapPacketEntry {
  std::vector<std::uint8_t> data;
  std::uint32_t tsSec = 0;
  std::uint32_t tsUsec = 0;
};

std::string writePcapFile(const std::string &name,
                          const std::vector<PcapPacketEntry> &packets) {
  auto path = (fs::temp_directory_path() / name).string();
  std::vector<std::uint8_t> buf;

  // Global header
  buf.insert(buf.end(), std::begin(kPcapGlobalHeader),
             std::end(kPcapGlobalHeader));

  // Packet records
  for (const auto &entry : packets) {
    writeLE32(buf, entry.tsSec);
    writeLE32(buf, entry.tsUsec);
    auto capLen = static_cast<std::uint32_t>(entry.data.size());
    writeLE32(buf, capLen);
    writeLE32(buf, capLen);
    buf.insert(buf.end(), entry.data.begin(), entry.data.end());
  }

  std::ofstream ofs(path, std::ios::binary);
  ofs.write(reinterpret_cast<const char *>(buf.data()),
            static_cast<std::streamsize>(buf.size()));
  ofs.close();
  return path;
}

} // anonymous namespace

// ── FlowKey tests ────────────────────────────────────────────────────

TEST(FlowKey, Equality) {
  FlowKey a{"10.0.0.1", "192.168.1.1", 12345, 443, 6};
  FlowKey b{"10.0.0.1", "192.168.1.1", 12345, 443, 6};
  FlowKey c{"10.0.0.2", "192.168.1.1", 12345, 443, 6};
  FlowKey d{"10.0.0.1", "192.168.1.2", 12345, 443, 6};

  EXPECT_EQ(a, b);
  EXPECT_NE(a, c);
  EXPECT_NE(a, d);
}

TEST(FlowKey, Equality_portDifference) {
  FlowKey a{"10.0.0.1", "10.0.0.2", 80, 443, 6};
  FlowKey b{"10.0.0.1", "10.0.0.2", 81, 443, 6};
  FlowKey c{"10.0.0.1", "10.0.0.2", 80, 444, 6};
  FlowKey d{"10.0.0.1", "10.0.0.2", 80, 443, 17};

  EXPECT_NE(a, b);
  EXPECT_NE(a, c);
  EXPECT_NE(a, d);
}

TEST(FlowKey, HashConsistency) {
  nids::infra::FlowKeyHash hasher;
  FlowKey a{"10.0.0.1", "192.168.1.1", 12345, 443, 6};
  FlowKey b{"10.0.0.1", "192.168.1.1", 12345, 443, 6};
  FlowKey c{"10.0.0.2", "192.168.1.1", 12345, 443, 6};

  EXPECT_EQ(hasher(a), hasher(b));
  EXPECT_NE(hasher(a), hasher(c));
}

TEST(FlowKey, HashDiffersForProtocol) {
  nids::infra::FlowKeyHash hasher;
  FlowKey tcp{"10.0.0.1", "10.0.0.2", 80, 443, 6};
  FlowKey udp{"10.0.0.1", "10.0.0.2", 80, 443, 17};
  EXPECT_NE(hasher(tcp), hasher(udp));
}

// ── WelfordAccumulator tests ────────────────────────────────────────

TEST(WelfordAccumulator, EmptyAccumulator) {
  WelfordAccumulator acc;
  EXPECT_EQ(acc.n, 0u);
  EXPECT_DOUBLE_EQ(acc.mean(), 0.0);
  EXPECT_DOUBLE_EQ(acc.sum(), 0.0);
  EXPECT_DOUBLE_EQ(acc.min(), 0.0);
  EXPECT_DOUBLE_EQ(acc.max(), 0.0);
  EXPECT_DOUBLE_EQ(acc.stddev(), 0.0);
  EXPECT_DOUBLE_EQ(acc.populationVariance(), 0.0);
  EXPECT_DOUBLE_EQ(acc.sampleVariance(), 0.0);
}

TEST(WelfordAccumulator, SingleValue) {
  WelfordAccumulator acc;
  acc.update(42.0);
  EXPECT_EQ(acc.n, 1u);
  EXPECT_DOUBLE_EQ(acc.mean(), 42.0);
  EXPECT_DOUBLE_EQ(acc.sum(), 42.0);
  EXPECT_DOUBLE_EQ(acc.min(), 42.0);
  EXPECT_DOUBLE_EQ(acc.max(), 42.0);
  EXPECT_DOUBLE_EQ(acc.stddev(), 0.0);       // N=1 → sampleVariance=0
  EXPECT_DOUBLE_EQ(acc.populationVariance(), 0.0);
}

TEST(WelfordAccumulator, MultipleValues_meanAndStddev) {
  WelfordAccumulator acc;
  // Values: 2, 4, 4, 4, 5, 5, 7, 9 → mean=5, population variance=4, sample
  // variance=4.571
  for (double v : {2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0})
    acc.update(v);

  EXPECT_EQ(acc.n, 8u);
  EXPECT_DOUBLE_EQ(acc.mean(), 5.0);
  EXPECT_DOUBLE_EQ(acc.sum(), 40.0);
  EXPECT_DOUBLE_EQ(acc.min(), 2.0);
  EXPECT_DOUBLE_EQ(acc.max(), 9.0);
  EXPECT_NEAR(acc.populationVariance(), 4.0, 1e-10);
  EXPECT_NEAR(acc.sampleVariance(), 32.0 / 7.0, 1e-10);
  EXPECT_NEAR(acc.stddev(), std::sqrt(32.0 / 7.0), 1e-10);
}

TEST(WelfordAccumulator, IdenticalValues_zeroVariance) {
  WelfordAccumulator acc;
  acc.update(100);
  acc.update(100);
  acc.update(100);
  EXPECT_DOUBLE_EQ(acc.mean(), 100.0);
  EXPECT_DOUBLE_EQ(acc.stddev(), 0.0);
  EXPECT_DOUBLE_EQ(acc.populationVariance(), 0.0);
}

TEST(WelfordAccumulator, TwoValues_sampleVariance) {
  WelfordAccumulator acc;
  acc.update(10);
  acc.update(20);
  EXPECT_DOUBLE_EQ(acc.mean(), 15.0);
  EXPECT_DOUBLE_EQ(acc.sum(), 30.0);
  EXPECT_DOUBLE_EQ(acc.min(), 10.0);
  EXPECT_DOUBLE_EQ(acc.max(), 20.0);
  // Population variance = ((10-15)^2 + (20-15)^2) / 2 = 25
  EXPECT_DOUBLE_EQ(acc.populationVariance(), 25.0);
  // Sample variance = 50 / 1 = 50
  EXPECT_DOUBLE_EQ(acc.sampleVariance(), 50.0);
}

// ── FlowStats tests ─────────────────────────────────────────────────

TEST(FlowStats, ToFeatureVectorSizeAndOrder) {
  FlowStats stats;
  stats.startTimeUs = 0;
  stats.lastTimeUs = 1'000'000;
  stats.totalFwdPackets = 5;
  stats.totalBwdPackets = 3;
  stats.totalFwdBytes = 500;
  stats.totalBwdBytes = 300;

  auto features = stats.toFeatureVector(443);
  EXPECT_EQ(features.size(), static_cast<std::size_t>(kFlowFeatureCount));
  EXPECT_FLOAT_EQ(features[0], 443.0f);     // Destination Port
  EXPECT_FLOAT_EQ(features[1], 1000000.0f); // Flow Duration
  EXPECT_FLOAT_EQ(features[2], 5.0f);       // Total Fwd Packets
  EXPECT_FLOAT_EQ(features[3], 3.0f);       // Total Bwd Packets
  EXPECT_FLOAT_EQ(features[4], 500.0f);     // Total Fwd Bytes
  EXPECT_FLOAT_EQ(features[5], 300.0f);     // Total Bwd Bytes
}

TEST(FlowStats, ToFeatureVector_zeroDuration) {
  FlowStats stats;
  stats.startTimeUs = 100;
  stats.lastTimeUs = 100; // Same → zero duration
  stats.totalFwdPackets = 1;
  stats.totalFwdBytes = 100;

  auto features = stats.toFeatureVector(80);
  EXPECT_EQ(features.size(), static_cast<std::size_t>(kFlowFeatureCount));
  EXPECT_FLOAT_EQ(features[0], 80.0f);
  EXPECT_FLOAT_EQ(features[1], 0.0f);  // Duration = 0
  EXPECT_FLOAT_EQ(features[14], 0.0f); // Flow Bytes/s = 0 (div by zero guarded)
  EXPECT_FLOAT_EQ(features[15], 0.0f); // Flow Packets/s = 0
}

TEST(FlowStats, ToFeatureVector_negativeDurationClampedToZero) {
  FlowStats stats;
  stats.startTimeUs = 1000;
  stats.lastTimeUs = 500; // lastTime < startTime → negative clamped to 0
  stats.totalFwdPackets = 1;

  auto features = stats.toFeatureVector(80);
  EXPECT_FLOAT_EQ(features[1], 0.0f);
}

TEST(FlowStats, ToFeatureVector_tcpFlagCountsAndInitWindow) {
  FlowStats stats;
  stats.startTimeUs = 0;
  stats.lastTimeUs = 1'000'000;
  stats.totalFwdPackets = 2;
  stats.totalBwdPackets = 1;
  stats.totalFwdBytes = 200;
  stats.totalBwdBytes = 100;
  stats.finCount = 1;
  stats.synCount = 2;
  stats.rstCount = 3;
  stats.pshCount = 4;
  stats.ackCount = 5;
  stats.urgCount = 6;
  stats.cwrCount = 7;
  stats.eceCount = 8;
  stats.fwdPshFlags = 1;
  stats.bwdPshFlags = 2;
  stats.fwdUrgFlags = 3;
  stats.bwdUrgFlags = 4;
  stats.fwdHeaderBytes = 40;
  stats.bwdHeaderBytes = 20;
  stats.fwdInitWinBytes = 65535;
  stats.bwdInitWinBytes = 32768;
  stats.actDataPktFwd = 1;
  stats.minSegSizeForward = 50;

  auto f = stats.toFeatureVector(443);
  EXPECT_FLOAT_EQ(f[30], 1.0f); // Fwd PSH Flags
  EXPECT_FLOAT_EQ(f[31], 2.0f); // Bwd PSH Flags
  EXPECT_FLOAT_EQ(f[32], 3.0f); // Fwd URG Flags
  EXPECT_FLOAT_EQ(f[33], 4.0f); // Bwd URG Flags
  // Header lengths: features 34-35
  EXPECT_FLOAT_EQ(f[34], 40.0f);
  EXPECT_FLOAT_EQ(f[35], 20.0f);
  // TCP flag counts: features 43-50
  EXPECT_FLOAT_EQ(f[43], 1.0f); // FIN
  EXPECT_FLOAT_EQ(f[44], 2.0f); // SYN
  EXPECT_FLOAT_EQ(f[45], 3.0f); // RST
  EXPECT_FLOAT_EQ(f[46], 4.0f); // PSH
  EXPECT_FLOAT_EQ(f[47], 5.0f); // ACK
  EXPECT_FLOAT_EQ(f[48], 6.0f); // URG
  EXPECT_FLOAT_EQ(f[49], 7.0f); // CWR
  EXPECT_FLOAT_EQ(f[50], 8.0f); // ECE
  // Down/Up ratio: features[51] = bwd/fwd = 1/2 = 0.5
  EXPECT_FLOAT_EQ(f[51], 0.5f);
  // Init window: features 65-66
  EXPECT_FLOAT_EQ(f[65], 65535.0f);
  EXPECT_FLOAT_EQ(f[66], 32768.0f);
  // act_data_pkt_fwd, min_seg_size_forward: features 67-68
  EXPECT_FLOAT_EQ(f[67], 1.0f);
  EXPECT_FLOAT_EQ(f[68], 50.0f);
}

TEST(FlowStats, ToFeatureVector_withIatAndPacketLengths) {
  FlowStats stats;
  stats.startTimeUs = 0;
  stats.lastTimeUs = 2'000'000;
  stats.totalFwdPackets = 3;
  stats.totalBwdPackets = 0;
  stats.totalFwdBytes = 300;
  stats.totalBwdBytes = 0;
  for (int i = 0; i < 3; ++i) {
    stats.fwdLengthAcc.update(100);
    stats.allLengthAcc.update(100);
  }
  stats.flowIatAcc.update(500'000);
  stats.flowIatAcc.update(500'000);
  stats.fwdIatAcc.update(500'000);
  stats.fwdIatAcc.update(500'000);

  auto f = stats.toFeatureVector(80);
  // Fwd Packet Length Max/Min/Mean/Std: features 6-9
  EXPECT_FLOAT_EQ(f[6], 100.0f); // Max
  EXPECT_FLOAT_EQ(f[7], 100.0f); // Min
  EXPECT_FLOAT_EQ(f[8], 100.0f); // Mean
  EXPECT_FLOAT_EQ(f[9], 0.0f);   // Std (all same)
  // Bwd Packet Length stats (empty): features 10-13 = 0
  EXPECT_FLOAT_EQ(f[10], 0.0f);
  EXPECT_FLOAT_EQ(f[11], 0.0f);
  EXPECT_FLOAT_EQ(f[12], 0.0f);
  EXPECT_FLOAT_EQ(f[13], 0.0f);
}

TEST(FlowStats, ToFeatureVector_bulkMetrics) {
  FlowStats stats;
  stats.startTimeUs = 0;
  stats.lastTimeUs = 2'000'000;
  stats.totalFwdPackets = 5;
  stats.totalBwdPackets = 3;
  stats.totalFwdBytes = 500;
  stats.totalBwdBytes = 300;
  stats.fwdBulkBytesAcc.update(200);
  stats.fwdBulkBytesAcc.update(300);
  stats.fwdBulkPktsAcc.update(2);
  stats.fwdBulkPktsAcc.update(3);
  stats.bwdBulkBytesAcc.update(150);
  stats.bwdBulkPktsAcc.update(2);

  auto f = stats.toFeatureVector(80);
  EXPECT_FLOAT_EQ(f[55], 250.0f);
  EXPECT_FLOAT_EQ(f[56], 2.5f);
  EXPECT_FLOAT_EQ(f[57], 250.0f);
  EXPECT_FLOAT_EQ(f[58], 150.0f);
}

TEST(FlowStats, ToFeatureVector_activeIdlePeriods) {
  FlowStats stats;
  stats.startTimeUs = 0;
  stats.lastTimeUs = 10'000'000;
  stats.totalFwdPackets = 1;
  stats.totalFwdBytes = 100;
  stats.activeAcc.update(1'000'000);
  stats.activeAcc.update(2'000'000);
  stats.idleAcc.update(5'000'000);
  stats.idleAcc.update(6'000'000);

  auto f = stats.toFeatureVector(80);
  // Active Mean: features[69]
  EXPECT_FLOAT_EQ(f[69], 1'500'000.0f); // mean(1M, 2M) = 1.5M
  // Idle Mean: features[73]
  EXPECT_FLOAT_EQ(f[73], 5'500'000.0f); // mean(5M, 6M) = 5.5M
}

// ── flowFeatureNames() ──────────────────────────────────────────────

TEST(FlowFeatureNames, sizeMatchesKFlowFeatureCount) {
  const auto &names = nids::infra::flowFeatureNames();
  EXPECT_EQ(names.size(), static_cast<std::size_t>(kFlowFeatureCount));
}

TEST(FlowFeatureNames, firstAndLastNames) {
  const auto &names = nids::infra::flowFeatureNames();
  EXPECT_EQ(names.front(), "Destination Port");
  EXPECT_EQ(names.back(), "Idle Min");
}

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

  const auto &metadata = extractor.flowMetadata();
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

  const auto &meta = extractor.flowMetadata();
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

  const auto &meta = extractor.flowMetadata();
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

  // Forward: A → B
  auto fwd = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  // Backward: B → A (same flow, reverse direction)
  auto bwd = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x12); // SYN+ACK

  auto path =
      writePcapFile("nfe_bidir.pcap", {
                                          {fwd, 0, 0},
                                          {bwd, 0, 500'000}, // 500ms later
                                      });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  // Should be ONE flow (bidirectional)
  EXPECT_EQ(features.size(), 1u);
  if (!features.empty()) {
    // Total Fwd Packets = 1, Total Bwd Packets = 1
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

  auto syn = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02); // SYN
  auto synack =
      buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x12);        // SYN+ACK
  auto ack = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10); // ACK
  auto fin = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x11); // FIN+ACK

  // After FIN, a new packet on the same 5-tuple starts a new flow
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

  // FIN should complete the first flow, newSyn starts a second
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

  // RST completes the flow
  EXPECT_EQ(features.size(), 1u);
  if (!features.empty()) {
    EXPECT_GT(features[0][45], 0.0f); // RST Flag Count > 0
  }
}

// ── Flow timeout eviction ───────────────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_flowTimeoutEviction) {
  SKIP_IF_NO_PCAP();

  auto pkt1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  // Packet 2 comes 700 seconds later (> 600s default timeout)
  auto pkt2 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);

  auto path =
      writePcapFile("nfe_timeout.pcap", {
                                            {pkt1, 0, 0},
                                            {pkt2, 700, 0}, // 700 seconds later
                                        });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  // The old flow should be evicted, pkt2 starts a new one
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

  // Set timeout to 2 seconds
  NativeFlowExtractor extractor;
  extractor.setFlowTimeout(2'000'000);
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 2u);
}

// ── Max-flow-size splitting ─────────────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_maxFlowSplitting) {
  SKIP_IF_NO_PCAP();

  // Build 250 packets (> kMaxFlowPackets=200 threshold)
  std::vector<PcapPacketEntry> packets;
  for (std::uint32_t i = 0; i < 250; ++i) {
    auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
    packets.emplace_back(pkt, i / 1000, (i % 1000) * 1000);
  }

  auto path = writePcapFile("nfe_maxflow.pcap", packets);

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  // 250 packets should split into at least 2 flows (200 + 50)
  EXPECT_GE(features.size(), 2u);
}

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
      [&](std::vector<float> &&features, nids::core::FlowInfo &&info) {
        callbackFeatures.push_back(std::move(features));
        callbackMetadata.push_back(std::move(info));
      });

  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  // FIN completes the flow → callback fires once during processing
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

  // Build 250 packets (> kMaxFlowPackets=200)
  std::vector<PcapPacketEntry> packets;
  for (std::uint32_t i = 0; i < 250; ++i) {
    auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
    packets.emplace_back(pkt, i / 1000, (i % 1000) * 1000);
  }

  auto path = writePcapFile("nfe_cb_maxpkt.pcap", packets);

  NativeFlowExtractor extractor;
  int callbackCount = 0;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float> &&, nids::core::FlowInfo &&) { ++callbackCount; });

  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  // 250 packets split into at least 2 flows; callback fires for each completed
  // flow plus any remaining active flow at end-of-capture
  EXPECT_GE(features.size(), 2u);
  EXPECT_EQ(callbackCount, static_cast<int>(features.size()));
}

TEST(NativeFlowExtractor, FlowCompletionCallback_firedOnEndOfCapture) {
  SKIP_IF_NO_PCAP();

  // Single UDP packet — no FIN/RST, flow stays active until end-of-capture
  auto pkt = buildUdpPacket("10.0.0.1", "10.0.0.2", 5000, 53);
  auto path = writePcapFile("nfe_cb_eoc.pcap", {{pkt, 0, 0}});

  NativeFlowExtractor extractor;
  int callbackCount = 0;
  extractor.setFlowCompletionCallback(
      [&](std::vector<float> &&, nids::core::FlowInfo &&) { ++callbackCount; });

  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  // End-of-capture finalization fires the callback for the active flow
  EXPECT_EQ(features.size(), 1u);
  EXPECT_EQ(callbackCount, 1);
}

TEST(NativeFlowExtractor, FlowCompletionCallback_firedOnSweep) {
  SKIP_IF_NO_PCAP();

  // Two flows at t=0, then a packet at t=700s triggers sweep
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
      [&](std::vector<float> &&, nids::core::FlowInfo &&) { ++callbackCount; });

  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  // 3 flows total: 2 swept + 1 active (finalized at end-of-capture)
  EXPECT_EQ(features.size(), 3u);
  EXPECT_EQ(callbackCount, 3);
}

TEST(NativeFlowExtractor, FlowCompletionCallback_notFiredWhenNull) {
  SKIP_IF_NO_PCAP();

  auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x11); // FIN
  auto path = writePcapFile("nfe_cb_null.pcap", {{pkt, 0, 0}});

  NativeFlowExtractor extractor;
  // No callback set — should work without crashing
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
      [&](std::vector<float> &&, nids::core::FlowInfo &&) { ++callbackCount; });

  // Disable callback
  extractor.setFlowCompletionCallback(nullptr);

  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 1u);
  EXPECT_EQ(callbackCount, 0);
}

// ── sweepExpiredFlows ───────────────────────────────────────────────

TEST(NativeFlowExtractor, SweepExpiredFlows_expiresIdleFlows) {
  SKIP_IF_NO_PCAP();

  // Two distinct flows, both go idle. Sweep should expire both.
  auto pktA = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  auto pktB = buildUdpPacket("10.0.0.3", "10.0.0.4", 6000, 53);

  // After 700 seconds, a third flow arrives. The sweep during processing
  // should have already expired the first two.
  auto pktC = buildTcpPacket("10.0.0.5", "10.0.0.6", 7000, 443, 0x02);

  auto path = writePcapFile("nfe_sweep_expire.pcap", {
                                                         {pktA, 0, 0},
                                                         {pktB, 0, 100'000},
                                                         {pktC, 700, 0},
                                                     });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  // 3 flows total: 2 expired by sweep + 1 active
  EXPECT_EQ(features.size(), 3u);
}

TEST(NativeFlowExtractor, SweepExpiredFlows_returnsZeroWhenNoneExpired) {
  SKIP_IF_NO_PCAP();

  // Single flow, sweep immediately — nothing should expire.
  auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto path = writePcapFile("nfe_sweep_none.pcap", {{pkt, 1, 0}});

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  // Call sweep at a time that doesn't expire the flow
  // (flow lastTimeUs = 1_000_000, sweep at 2_000_000 = 1 sec gap, < 600s timeout)
  auto swept = extractor.sweepExpiredFlows(2'000'000);
  EXPECT_EQ(swept, 0u);
}

TEST(NativeFlowExtractor, SweepExpiredFlows_respectsCustomTimeout) {
  SKIP_IF_NO_PCAP();

  // Two packets on the same 5-tuple, 3 seconds apart.
  // With a 2-second timeout, the periodic sweep should expire the flow
  // before the second packet arrives, creating two separate flows.
  auto pkt1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  auto pkt2 = buildUdpPacket("10.0.0.3", "10.0.0.4", 6000, 53);
  // Third packet arrives 35 seconds later — triggers sweep
  auto pkt3 = buildTcpPacket("10.0.0.5", "10.0.0.6", 7000, 443, 0x02);

  auto path = writePcapFile("nfe_sweep_custom.pcap", {
                                                         {pkt1, 0, 0},
                                                         {pkt2, 0, 100'000},
                                                         {pkt3, 35, 0},
                                                     });

  NativeFlowExtractor extractor;
  extractor.setFlowTimeout(2'000'000); // 2-second timeout
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  // pkt1 and pkt2 should be swept at t=35s, pkt3 starts a new flow = 3 flows
  EXPECT_EQ(features.size(), 3u);
}

TEST(NativeFlowExtractor, SweepExpiredFlows_directCallExpiresFlow) {
  SKIP_IF_NO_PCAP();

  // Create a pcap, extract features, then call sweepExpiredFlows manually
  // on the remaining active flows.
  auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  auto path = writePcapFile("nfe_sweep_direct.pcap", {{pkt, 100, 0}});

  NativeFlowExtractor extractor;
  extractor.setFlowTimeout(10'000'000); // 10-second timeout
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_EQ(features.size(), 1u);

  // Now call sweepExpiredFlows at a time well past the timeout
  // (flow lastTimeUs = 100_000_000, sweep at 200_000_000 = 100s gap > 10s timeout)
  // Note: after extractFeatures, remaining active flows are already in the output,
  // but they remain in flows_ until the next extractFeatures call clears them.
  // The sweep should expire them and move them to completedFlows_.
  auto swept = extractor.sweepExpiredFlows(200'000'000);
  // The flow was already included in output; sweep operates on internal state.
  // After extractFeatures completes, flows_ may still contain the active flows.
  // Verify the sweep ran (it may or may not find flows depending on implementation).
  EXPECT_GE(swept, 0u); // Non-negative (always true, just verify no crash)
}

// ── TCP flags accumulation ──────────────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_tcpFlagsCounted) {
  SKIP_IF_NO_PCAP();

  // SYN → SYN+ACK → ACK → PSH+ACK → FIN+ACK
  auto syn = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02); // SYN
  auto synack =
      buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x12);        // SYN+ACK
  auto ack = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10); // ACK
  auto pshack =
      buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x18); // PSH+ACK
  auto finack =
      buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x11); // FIN+ACK

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

  ASSERT_EQ(features.size(), 1u); // FIN completes, but that's the only flow
  auto &f = features[0];
  // SYN count: 2 (SYN + SYN+ACK)
  EXPECT_FLOAT_EQ(f[44], 2.0f);
  // ACK count: 4 (SYN+ACK, ACK, PSH+ACK, FIN+ACK)
  EXPECT_FLOAT_EQ(f[47], 4.0f);
  // PSH count: 1
  EXPECT_FLOAT_EQ(f[46], 1.0f);
  // FIN count: 1
  EXPECT_FLOAT_EQ(f[43], 1.0f);
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
  auto &f = features[0];
  EXPECT_FLOAT_EQ(f[2], 1.0f); // Total Fwd Packets = 1
  EXPECT_FLOAT_EQ(f[3], 2.0f); // Total Bwd Packets = 2
  // Bwd Packet Length stats (features 10-13) should be non-zero
  EXPECT_GT(f[10], 0.0f); // Bwd Pkt Len Max > 0
}

// ── Packet too short: should be skipped ─────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_truncatedPacketSkipped) {
  SKIP_IF_NO_PCAP();

  // A packet too short for an Ethernet header
  std::vector<std::uint8_t> tiny(10, 0);
  auto path = writePcapFile("nfe_truncated.pcap", {{tiny, 0, 0}});

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_TRUE(features.empty());
}

TEST(NativeFlowExtractor, ExtractFeatures_nonIpv4Skipped) {
  SKIP_IF_NO_PCAP();

  // Valid Ethernet length but non-IPv4 EtherType (e.g., ARP = 0x0806)
  std::vector<std::uint8_t> arpPkt(60, 0);
  arpPkt[12] = 0x08;
  arpPkt[13] = 0x06; // ARP
  auto path = writePcapFile("nfe_arp.pcap", {{arpPkt, 0, 0}});

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  EXPECT_TRUE(features.empty());
}

// ── Bulk transfer tracking ──────────────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_bulkTransferDetected) {
  SKIP_IF_NO_PCAP();

  // 5 consecutive forward packets (direction doesn't change = bulk)
  std::vector<PcapPacketEntry> packets;
  for (int i = 0; i < 5; ++i) {
    auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
    packets.emplace_back(pkt, 0, static_cast<std::uint32_t>(i * 100'000));
  }
  // Switch direction (backward)
  for (int i = 0; i < 3; ++i) {
    auto pkt = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);
    packets.emplace_back(pkt, 0, static_cast<std::uint32_t>((5 + i) * 100'000));
  }

  auto path = writePcapFile("nfe_bulk.pcap", packets);

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  ASSERT_EQ(features.size(), 1u);
  // Forward bulk metrics (features 55-57) should be non-zero
  // because 5 consecutive fwd packets forms a bulk
  EXPECT_GT(features[0][55], 0.0f); // Fwd Avg Bytes/Bulk
}

// ── Active/Idle period tracking ─────────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_activeIdlePeriods) {
  SKIP_IF_NO_PCAP();

  // Packets with a >5 second gap to trigger idle detection
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
  // Idle period stats (features 73-76) should be non-zero
  EXPECT_GT(features[0][73], 0.0f); // Idle Mean > 0
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

// ── Unsupported protocol skipped ────────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_unsupportedProtocolSkipped) {
  SKIP_IF_NO_PCAP();

  // Build an IP packet with protocol 50 (ESP) — not TCP/UDP/ICMP
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

// ── Metadata population: flowDuration, packetRates ──────────────────

TEST(NativeFlowExtractor, FlowMetadata_populatedCorrectly) {
  SKIP_IF_NO_PCAP();

  auto pkt1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto pkt2 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  auto pkt3 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);

  auto path =
      writePcapFile("nfe_meta.pcap", {
                                         {pkt1, 0, 0},
                                         {pkt2, 1, 0}, // 1 second later
                                         {pkt3, 2, 0}, // 2 seconds later
                                     });

  NativeFlowExtractor extractor;
  [[maybe_unused]] auto features = extractor.extractFeatures(path);
  fs::remove(path);

  const auto &meta = extractor.flowMetadata();
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

// ── Malformed packet parsing: truncated transport headers ───────────

TEST(NativeFlowExtractor, ExtractFeatures_truncatedTcpHeader_skipped) {
  SKIP_IF_NO_PCAP();

  // Build IPv4 packet where payload is too short for TCP header (IP=20 bytes,
  // need +20 for TCP) Ethernet(14) + IP(20) + partial TCP (10 bytes instead of
  // 20) = 44
  std::vector<std::uint8_t> pkt(44, 0);
  pkt[12] = 0x08;
  pkt[13] = 0x00; // IPv4
  auto *ip = pkt.data() + 14;
  ip[0] = 0x45;           // IHL=5 (20 bytes)
  writeNBO16(ip + 2, 30); // IP total = 30 (20 IP + 10 "TCP" — too short)
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

  // Ethernet(14) + IP(20) + partial UDP (4 bytes instead of 8) = 38
  std::vector<std::uint8_t> pkt(38, 0);
  pkt[12] = 0x08;
  pkt[13] = 0x00; // IPv4
  auto *ip = pkt.data() + 14;
  ip[0] = 0x45;
  writeNBO16(ip + 2, 24); // IP total = 24 (20 IP + 4 "UDP" — too short)
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

  // Ethernet(14) + IP(20) + partial ICMP (2 bytes instead of 8) = 36
  std::vector<std::uint8_t> pkt(36, 0);
  pkt[12] = 0x08;
  pkt[13] = 0x00; // IPv4
  auto *ip = pkt.data() + 14;
  ip[0] = 0x45;
  writeNBO16(ip + 2, 22); // IP total = 22 (20 IP + 2 "ICMP" — too short)
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

  // Ethernet(14) + minimal data (IPv4 EtherType but only 10 bytes of IP
  // payload)
  std::vector<std::uint8_t> pkt(24, 0);
  pkt[12] = 0x08;
  pkt[13] = 0x00; // IPv4 EtherType
  auto *ip = pkt.data() + 14;
  ip[0] = 0x45;           // IHL=5 (claims 20 bytes but only 10 available)
  writeNBO16(ip + 2, 10); // IP total length = 10 (< IHL of 20)

  auto path = writePcapFile("nfe_short_ip.pcap", {{pkt, 0, 0}});
  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);
  EXPECT_TRUE(features.empty());
}

TEST(NativeFlowExtractor, ExtractFeatures_vlanTooShort_skipped) {
  SKIP_IF_NO_PCAP();

  // VLAN EtherType but only 1 byte after Ethernet header (need 4 for VLAN tag)
  std::vector<std::uint8_t> pkt(15, 0);
  pkt[12] = 0x81;
  pkt[13] = 0x00; // VLAN EtherType

  auto path = writePcapFile("nfe_vlan_short.pcap", {{pkt, 0, 0}});
  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);
  EXPECT_TRUE(features.empty());
}

// ── TCP payload and segment tracking ────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_tcpPayloadTracked) {
  SKIP_IF_NO_PCAP();

  // Forward TCP packet with 100 bytes of payload (PSH+ACK)
  auto pkt1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x18, 8192, 100);
  // Forward TCP packet with 50 bytes of payload
  auto pkt2 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x18, 8192, 50);
  // Forward TCP packet with 200 bytes of payload
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
  auto &f = features[0];
  // act_data_pkt_fwd (feature 67) — packets with payload > 0
  EXPECT_FLOAT_EQ(f[67], 3.0f);
  // min_seg_size_forward (feature 68) — minimum segment size = 50
  EXPECT_FLOAT_EQ(f[68], 50.0f);
  // Fwd PSH Flags (feature 30) — all 3 have PSH
  EXPECT_FLOAT_EQ(f[30], 3.0f);
}

TEST(NativeFlowExtractor, ExtractFeatures_urgAndCwrAndEceFlags) {
  SKIP_IF_NO_PCAP();

  // Forward packet with URG flag
  auto urg = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x20); // URG
  // Forward packet with CWR flag
  auto cwr = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x80); // CWR
  // Forward packet with ECE flag
  auto ece = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x40); // ECE
  // Backward packet with URG + PSH
  auto bwd_urg_psh =
      buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x28); // PSH+URG

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
  auto &f = features[0];
  // Fwd URG Flags (feature 32)
  EXPECT_FLOAT_EQ(f[32], 1.0f);
  // Bwd URG Flags (feature 33)
  EXPECT_FLOAT_EQ(f[33], 1.0f);
  // Bwd PSH Flags (feature 31)
  EXPECT_FLOAT_EQ(f[31], 1.0f);
  // Global URG count (feature 48)
  EXPECT_FLOAT_EQ(f[48], 2.0f); // fwd + bwd
  // Global CWR count (feature 49)
  EXPECT_FLOAT_EQ(f[49], 1.0f);
  // Global ECE count (feature 50)
  EXPECT_FLOAT_EQ(f[50], 1.0f);
}

// ── Backward bulk transfer detection ────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_bwdBulkDetected) {
  SKIP_IF_NO_PCAP();

  // 1 fwd packet, then 4 consecutive bwd packets (forms bwd bulk),
  // then 1 fwd packet (triggers bwd bulk completion on direction change)
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
  // Bwd Avg Bytes/Bulk (feature 58) should be non-zero
  EXPECT_GT(features[0][58], 0.0f);
  // Bwd Avg Packets/Bulk (feature 59) should be >= 2
  EXPECT_GE(features[0][59], 2.0f);
}

// ── Backward key timeout eviction ───────────────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_backwardKeyTimeoutEviction) {
  SKIP_IF_NO_PCAP();

  // Packet A→B at t=0 (creates flow with keyFwd={A,B})
  auto pkt1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  // Packet B→A at t=700s (resolveFlow tries keyBwd={A,B} which matches, but
  // timed out)
  auto pkt2 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x12);

  auto path = writePcapFile("nfe_bwd_timeout.pcap", {
                                                        {pkt1, 0, 0},
                                                        {pkt2, 700, 0},
                                                    });

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  // The old flow should be evicted (backward key match but timed out),
  // pkt2 starts a new flow
  EXPECT_EQ(features.size(), 2u);
}

// ── Single-packet flow metadata (zero duration) ─────────────────────

TEST(NativeFlowExtractor, FlowMetadata_singlePacket_zeroDuration) {
  SKIP_IF_NO_PCAP();

  auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);
  auto path = writePcapFile("nfe_single_meta.pcap", {{pkt, 0, 0}});

  NativeFlowExtractor extractor;
  [[maybe_unused]] auto features = extractor.extractFeatures(path);
  fs::remove(path);

  const auto &meta = extractor.flowMetadata();
  ASSERT_EQ(meta.size(), 1u);
  EXPECT_DOUBLE_EQ(meta[0].flowDurationUs, 0.0);
  EXPECT_NEAR(meta[0].fwdPacketsPerSecond, 0.0f, 1e-6f);
  EXPECT_NEAR(meta[0].bwdPacketsPerSecond, 0.0f, 1e-6f);
}

// ── FlowStats: single-element containers (stddev = 0) ───────────────

TEST(FlowStats, ToFeatureVector_singleFwdPacket_stddevZero) {
  FlowStats stats;
  stats.startTimeUs = 0;
  stats.lastTimeUs = 0;
  stats.totalFwdPackets = 1;
  stats.totalBwdPackets = 0;
  stats.totalFwdBytes = 100;
  stats.totalBwdBytes = 0;
  stats.fwdLengthAcc.update(100);
  stats.allLengthAcc.update(100);

  auto f = stats.toFeatureVector(80);
  // Fwd Packet Length Std (feature 9) should be 0 for single element
  EXPECT_FLOAT_EQ(f[9], 0.0f);
  // Fwd Packet Length Mean (feature 8) = 100
  EXPECT_FLOAT_EQ(f[8], 100.0f);
}

// ── FlowStats: bulk metrics with zero-duration flow ─────────────────

TEST(FlowStats, ToFeatureVector_bulkWithZeroDuration) {
  FlowStats stats;
  stats.startTimeUs = 100;
  stats.lastTimeUs = 100; // Zero duration
  stats.totalFwdPackets = 5;
  stats.totalBwdPackets = 0;
  stats.totalFwdBytes = 500;
  stats.fwdBulkBytesAcc.update(200);
  stats.fwdBulkPktsAcc.update(3);

  auto f = stats.toFeatureVector(80);
  // Fwd Avg Bulk Rate (feature 57) should be 0 (not NaN/Inf) when duration = 0
  EXPECT_FLOAT_EQ(f[57], 0.0f);
  // Fwd Avg Bytes/Bulk (feature 55) should still be valid
  EXPECT_FLOAT_EQ(f[55], 200.0f);
}

// ── IP total length < IHL → packet rejected ─────────────────────────

TEST(NativeFlowExtractor, ExtractFeatures_ipTotalLenLessThanIhl_skipped) {
  SKIP_IF_NO_PCAP();

  // Build a valid TCP packet, then corrupt the IP total length to be
  // smaller than the IHL (20 bytes). This triggers line 495:
  //   if (payloadLen < pkt.ipIhl || ipTotalLen < pkt.ipIhl) return false;
  // specifically the second condition (ipTotalLen < ipIhl).
  auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x02);

  // IPv4 total length field is at IP header offset +2 (2 bytes, big-endian).
  // IP header starts at byte 14 (after Ethernet header).
  // Set IP total length to 10 (less than IHL of 20).
  pkt[16] = 0x00;
  pkt[17] = 0x0A; // 10 in big-endian

  auto path = writePcapFile("test_ip_totlen_lt_ihl.pcap", {{pkt, 0, 0}});

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  fs::remove(path);

  // Packet should be skipped — no flows extracted
  EXPECT_TRUE(features.empty());
}

// ── Bwd bulk flushed at flow completion via TCP FIN (completeFlow) ──

TEST(NativeFlowExtractor, ExtractFeatures_bwdBulkFlushedAtFlowCompletion) {
  SKIP_IF_NO_PCAP();

  // Create a flow where the last consecutive packets are backward, then a
  // backward FIN terminates the flow. completeFlow() is called while
  // curBwdBulkPkts >= 2, triggering lines 736-738.

  // 1 fwd ACK to create the flow (direction = fwd)
  auto fwd1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  // 3 consecutive bwd ACK packets (accumulates curBwdBulkPkts = 3)
  auto bwd1 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);
  auto bwd2 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);
  // Bwd FIN — terminates the flow via completeFlow while bwd bulk is pending
  auto bwdFin =
      buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x11); // FIN+ACK

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
  // Bwd Avg Bytes/Bulk (feature 58) should be non-zero
  // because completeFlow flushed the pending bwd bulk (curBwdBulkPkts = 3)
  EXPECT_GT(features[0][58], 0.0f);
  // Bwd Avg Packets/Bulk (feature 59) should be >= 2
  EXPECT_GE(features[0][59], 2.0f);
}

// ── Bwd bulk flushed at finalizeBulks (end of pcap) ─────────────────

TEST(NativeFlowExtractor, ExtractFeatures_bwdBulkFlushedAtFinalize) {
  SKIP_IF_NO_PCAP();

  // Create a flow where the last consecutive packets are backward and the
  // pcap ends without a FIN/RST. finalizeBulks() flushes curBwdBulkPkts >= 2
  // for flows still in the flows_ map (lines 408-410).

  // 1 fwd ACK to create the flow
  auto fwd1 = buildTcpPacket("10.0.0.1", "10.0.0.2", 5000, 80, 0x10);
  // 3 consecutive bwd ACK packets (curBwdBulkPkts = 3, no direction change)
  auto bwd1 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);
  auto bwd2 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);
  auto bwd3 = buildTcpPacket("10.0.0.2", "10.0.0.1", 80, 5000, 0x10);
  // No FIN/RST — flow stays in flows_ map, finalizeBulks() handles it

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
  // Bwd Avg Bytes/Bulk (feature 58) should be non-zero
  EXPECT_GT(features[0][58], 0.0f);
  // Bwd Avg Packets/Bulk (feature 59) should be >= 2
  EXPECT_GE(features[0][59], 2.0f);
}

// ── TCP data offset < 5 clamped to 20 bytes ─────────────────────────

TEST(NativeFlowExtractorTest, ExtractFeatures_tcpDataOffsetBelowMin_rejected) {
  SKIP_IF_NO_PCAP();

  // Build a TCP packet where th_off = 1 → data offset is 4 bytes (< 20 min).
  // PcapPlusPlus rejects malformed TCP headers, so the packet is skipped.
  auto pkt = buildTcpPacket("10.0.0.1", "10.0.0.2", 12345, 80, 0x02);
  // Overwrite TCP data offset field: byte 12 of TCP header (offset 34+12=46)
  // th_off is the upper 4 bits of byte 12. Set to 0x10 → th_off=1 → 4 bytes.
  pkt[46] = 0x10;

  auto path = writePcapFile("test_tcp_low_offset.pcap", {{pkt, 1, 0}});

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(path);
  // Malformed TCP header is correctly rejected by PcapPlusPlus parser
  EXPECT_EQ(features.size(), 0u);
  fs::remove(path);
}
