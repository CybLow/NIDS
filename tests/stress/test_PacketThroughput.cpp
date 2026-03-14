/**
 * Stress test: Packet capture throughput benchmark.
 *
 * Measures how many packets/sec the NativeFlowExtractor can parse and
 * extract features from, using synthetically generated pcap files of
 * increasing size.  No real NIC or root privileges required.
 */

#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include "infra/flow/NativeFlowExtractor.h"
#include "stress/StressTestHelpers.h"

#include <filesystem>
#include <string>

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

namespace fs = std::filesystem;
using nids::infra::NativeFlowExtractor;
using nids::test::generatePcap;
using nids::test::ScopedTimer;

class PacketThroughputTest : public ::testing::Test {
protected: // NOSONAR
  std::string pcapPath_;

  void SetUp() override {
    const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
    std::string filename =
        std::string("nids_stress_tp_") + info->name() + ".pcap";
    pcapPath_ = (fs::temp_directory_path() / filename).string();
  }

  void TearDown() override { fs::remove(pcapPath_); }
};

TEST_F(PacketThroughputTest, parse10kPackets_singleFlow) {
  SKIP_IF_NO_PCAP();

  constexpr std::uint32_t kPackets = 10'000;
  constexpr std::uint32_t kFlows = 1;

  generatePcap(pcapPath_, kPackets, kFlows);

  NativeFlowExtractor extractor;
  double elapsedMs = 0.0;
  std::vector<std::vector<float>> features;
  {
    ScopedTimer timer(elapsedMs);
    features = extractor.extractFeatures(pcapPath_);
  }

  double pps = static_cast<double>(kPackets) / (elapsedMs / 1000.0);
  spdlog::info(
      "10k packets / 1 flow: {:.1f} ms, {:.0f} pps, {} flow(s) extracted",
      elapsedMs, pps, features.size());

  EXPECT_FALSE(features.empty());
  // With kMaxFlowPackets=200, 10k packets / 1 flow -> ~50 sub-flows
  EXPECT_GE(features.size(), 1u);

  // Performance gate: must process >50k packets/sec
  EXPECT_GT(pps, 50'000.0) << "Throughput below minimum threshold";
}

TEST_F(PacketThroughputTest, parse50kPackets_100flows) {
  SKIP_IF_NO_PCAP();

  constexpr std::uint32_t kPackets = 50'000;
  constexpr std::uint32_t kFlows = 100;

  generatePcap(pcapPath_, kPackets, kFlows);

  NativeFlowExtractor extractor;
  double elapsedMs = 0.0;
  std::vector<std::vector<float>> features;
  {
    ScopedTimer timer(elapsedMs);
    features = extractor.extractFeatures(pcapPath_);
  }

  double pps = static_cast<double>(kPackets) / (elapsedMs / 1000.0);
  spdlog::info("50k packets / 100 flows: {:.1f} ms, {:.0f} pps, {} flow(s)",
               elapsedMs, pps, features.size());

  EXPECT_GE(features.size(), kFlows);
  EXPECT_GT(pps, 30'000.0) << "Throughput below minimum threshold";
}

TEST_F(PacketThroughputTest, parse100kPackets_1000flows) {
  SKIP_IF_NO_PCAP();

  constexpr std::uint32_t kPackets = 100'000;
  constexpr std::uint32_t kFlows = 1'000;

  generatePcap(pcapPath_, kPackets, kFlows);

  NativeFlowExtractor extractor;
  double elapsedMs = 0.0;
  std::vector<std::vector<float>> features;
  {
    ScopedTimer timer(elapsedMs);
    features = extractor.extractFeatures(pcapPath_);
  }

  double pps = static_cast<double>(kPackets) / (elapsedMs / 1000.0);
  spdlog::info("100k packets / 1000 flows: {:.1f} ms, {:.0f} pps, {} flow(s)",
               elapsedMs, pps, features.size());

  EXPECT_GE(features.size(), kFlows);
  EXPECT_GT(pps, 20'000.0) << "Throughput below minimum threshold";
}

TEST_F(PacketThroughputTest, parse100kPackets_withPayload) {
  SKIP_IF_NO_PCAP();

  constexpr std::uint32_t kPackets = 100'000;
  constexpr std::uint32_t kFlows = 500;
  constexpr std::uint32_t kPayload = 256; // 256-byte payload per packet

  generatePcap(pcapPath_, kPackets, kFlows, kPayload);

  NativeFlowExtractor extractor;
  double elapsedMs = 0.0;
  std::vector<std::vector<float>> features;
  {
    ScopedTimer timer(elapsedMs);
    features = extractor.extractFeatures(pcapPath_);
  }

  double pps = static_cast<double>(kPackets) / (elapsedMs / 1000.0);
  double mbps = static_cast<double>(kPackets) * (54.0 + kPayload) /
                (elapsedMs / 1000.0) / 1'000'000.0;
  spdlog::info("100k packets / 500 flows / 256B payload: {:.1f} ms, {:.0f} "
               "pps, {:.1f} MB/s",
               elapsedMs, pps, mbps);

  EXPECT_GE(features.size(), kFlows);
}

TEST_F(PacketThroughputTest, featureVectorDimensionConsistency) {
  SKIP_IF_NO_PCAP();

  constexpr std::uint32_t kPackets = 5'000;
  constexpr std::uint32_t kFlows = 50;

  generatePcap(pcapPath_, kPackets, kFlows);

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(pcapPath_);

  // Every feature vector must have exactly kFlowFeatureCount dimensions
  for (std::size_t i = 0; i < features.size(); ++i) {
    EXPECT_EQ(features[i].size(),
              static_cast<std::size_t>(nids::infra::kFlowFeatureCount))
        << "Flow " << i << " has wrong feature dimension";
  }

  // Metadata must match feature count
  const auto &meta = extractor.flowMetadata();
  EXPECT_EQ(meta.size(), features.size());
}
