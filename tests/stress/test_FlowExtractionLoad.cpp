/**
 * Stress test: Flow extraction under heavy load.
 *
 * Tests NativeFlowExtractor with thousands of concurrent flows, verifying
 * correct flow splitting (kMaxFlowPackets), memory efficiency, and
 * feature vector correctness at scale.
 */

#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include "infra/flow/NativeFlowExtractor.h"
#include "stress/StressTestHelpers.h"

#include <filesystem>
#include <numeric>
#include <string>

// Skip tests requiring pcap runtime (not available on Windows CI)
#ifdef _WIN32
#define SKIP_IF_NO_PCAP() GTEST_SKIP() << "npcap runtime not available"
#else
#define SKIP_IF_NO_PCAP() do {} while(0)
#endif


namespace fs = std::filesystem;
using nids::infra::kFlowFeatureCount;
using nids::infra::kMaxFlowPackets;
using nids::infra::NativeFlowExtractor;
using nids::test::generatePcap;
using nids::test::ScopedTimer;

class FlowExtractionLoadTest : public ::testing::Test {
protected: // NOSONAR
  std::string pcapPath_;

  void SetUp() override {
    const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
    std::string filename =
        std::string("nids_stress_fe_") + info->name() + ".pcap";
    pcapPath_ = (fs::temp_directory_path() / filename).string();
  }

  void TearDown() override { fs::remove(pcapPath_); }
};

TEST_F(FlowExtractionLoadTest, manyFlows_5000distinct) {
  SKIP_IF_NO_PCAP();
  constexpr std::uint32_t kPackets = 50'000;
  constexpr std::uint32_t kFlows = 5'000;
  // 10 packets per flow on average, below kMaxFlowPackets

  generatePcap(pcapPath_, kPackets, kFlows);

  NativeFlowExtractor extractor;
  double elapsedMs = 0.0;
  std::vector<std::vector<float>> features;
  {
    ScopedTimer timer(elapsedMs);
    features = extractor.extractFeatures(pcapPath_);
  }

  spdlog::info("5000 flows / 50k packets: {:.1f} ms, {} flows extracted",
               elapsedMs, features.size());

  // Each flow gets 10 packets (well under kMaxFlowPackets=200), so no splitting
  EXPECT_EQ(features.size(), kFlows);

  // Verify all features have correct dimension
  for (const auto &fv : features) {
    EXPECT_EQ(fv.size(), static_cast<std::size_t>(kFlowFeatureCount));
  }
}

TEST_F(FlowExtractionLoadTest, flowSplitting_megaFlow) {
  SKIP_IF_NO_PCAP();
  // One mega-flow with many packets -> should split at kMaxFlowPackets boundary
  constexpr std::uint32_t kPackets = 1'000;
  constexpr std::uint32_t kFlows = 1; // All packets in one flow

  generatePcap(pcapPath_, kPackets, kFlows);

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(pcapPath_);

  // With kMaxFlowPackets=200 and 1000 packets, expect ~5 sub-flows
  std::size_t expectedMin = kPackets / kMaxFlowPackets;
  spdlog::info(
      "Mega-flow (1 flow, 1000 pkts): {} sub-flows extracted (expected >= {})",
      features.size(), expectedMin);

  EXPECT_GE(features.size(), expectedMin);

  // Each sub-flow should have correct dimensions
  for (const auto &fv : features) {
    EXPECT_EQ(fv.size(), static_cast<std::size_t>(kFlowFeatureCount));
  }
}

TEST_F(FlowExtractionLoadTest, flowTimeout_oldFlowsEvicted) {
  SKIP_IF_NO_PCAP();
  // Generate packets with large inter-arrival time that exceeds flow timeout
  constexpr std::uint32_t kPackets = 100;
  constexpr std::uint32_t kFlows = 1;
  constexpr std::int64_t kIatUs = 100'000'000; // 100 seconds between packets

  generatePcap(pcapPath_, kPackets, kFlows, 0, kIatUs);

  NativeFlowExtractor extractor;
  extractor.setFlowTimeout(
      50'000'000); // 50 seconds -> each packet creates new flow

  auto features = extractor.extractFeatures(pcapPath_);

  spdlog::info(
      "Flow timeout test: {} packets -> {} flows (timeout=50s, IAT=100s)",
      kPackets, features.size());

  // Each packet should start a new flow since IAT > timeout
  // (first packet is always the same flow, subsequent ones split)
  EXPECT_GT(features.size(), 1u);
}

TEST_F(FlowExtractionLoadTest, largeScale_10kFlows_100kPackets) {
  SKIP_IF_NO_PCAP();
  constexpr std::uint32_t kPackets = 100'000;
  constexpr std::uint32_t kFlows = 10'000;

  generatePcap(pcapPath_, kPackets, kFlows);

  NativeFlowExtractor extractor;
  double elapsedMs = 0.0;
  std::vector<std::vector<float>> features;
  {
    ScopedTimer timer(elapsedMs);
    features = extractor.extractFeatures(pcapPath_);
  }

  spdlog::info(
      "10k flows / 100k packets: {:.1f} ms, {} flows, {:.0f} flows/sec",
      elapsedMs, features.size(),
      static_cast<double>(features.size()) / (elapsedMs / 1000.0));

  // 10 packets per flow -> no splitting
  EXPECT_EQ(features.size(), kFlows);

  // Metadata must match
  const auto &meta = extractor.flowMetadata();
  EXPECT_EQ(meta.size(), features.size());

  // Spot-check some metadata fields
  for (std::size_t i = 0; i < std::min<std::size_t>(10, meta.size()); ++i) {
    EXPECT_FALSE(meta[i].srcIp.empty());
    EXPECT_FALSE(meta[i].dstIp.empty());
    EXPECT_EQ(meta[i].protocol, 6); // TCP
  }
}

TEST_F(FlowExtractionLoadTest, featureValues_noNanNoInf) {
  SKIP_IF_NO_PCAP();
  constexpr std::uint32_t kPackets = 20'000;
  constexpr std::uint32_t kFlows = 200;

  generatePcap(pcapPath_, kPackets, kFlows);

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(pcapPath_);

  std::size_t nanCount = 0;
  std::size_t infCount = 0;
  for (const auto &fv : features) {
    for (float val : fv) {
      if (std::isnan(val))
        ++nanCount;
      if (std::isinf(val))
        ++infCount;
    }
  }

  EXPECT_EQ(nanCount, 0u) << "Found NaN values in feature vectors";
  EXPECT_EQ(infCount, 0u) << "Found Inf values in feature vectors";
}

TEST_F(FlowExtractionLoadTest, repeatedExtraction_noStateLeakage) {
  SKIP_IF_NO_PCAP();
  constexpr std::uint32_t kPackets = 1'000;
  constexpr std::uint32_t kFlows = 10;

  generatePcap(pcapPath_, kPackets, kFlows);

  NativeFlowExtractor extractor;

  // Run extraction multiple times — state should reset each time
  auto features1 = extractor.extractFeatures(pcapPath_);
  auto features2 = extractor.extractFeatures(pcapPath_);
  auto features3 = extractor.extractFeatures(pcapPath_);

  EXPECT_EQ(features1.size(), features2.size());
  EXPECT_EQ(features2.size(), features3.size());

  // Feature vectors should be identical across runs
  for (std::size_t i = 0; i < features1.size(); ++i) {
    EXPECT_EQ(features1[i], features2[i])
        << "Feature vector mismatch at flow " << i << " between run 1 and 2";
  }
}
