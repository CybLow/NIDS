/**
 * Stress test: Memory usage under sustained load.
 *
 * Tracks RSS (Resident Set Size) growth during sustained packet processing
 * to detect memory leaks. Uses /proc/self/status on Linux.
 */

#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include "app/HybridDetectionService.h"
#include "infra/flow/NativeFlowExtractor.h"
#include "stress/StressTestHelpers.h"

#include <filesystem>
#include <format>
#include <string>

namespace fs = std::filesystem;
using nids::app::HybridDetectionService;
using nids::infra::kFlowFeatureCount;
using nids::infra::NativeFlowExtractor;
using nids::test::currentRssKb;
using nids::test::generatePcap;
using nids::test::ScopedTimer;
using nids::test::StubAnalyzer;
using nids::test::StubRuleEngine;
using nids::test::StubThreatIntel;

class MemoryStressTest : public ::testing::Test {
protected: // NOSONAR
  std::string pcapPath_;

  void SetUp() override {
    const auto *info = ::testing::UnitTest::GetInstance()->current_test_info();
    std::string filename =
        std::string("nids_stress_mem_") + info->name() + ".pcap";
    pcapPath_ = (fs::temp_directory_path() / filename).string();
  }

  void TearDown() override { fs::remove(pcapPath_); }
};

TEST_F(MemoryStressTest, repeatedExtraction_noMemoryLeak) {
  constexpr std::uint32_t kPackets = 10'000;
  constexpr std::uint32_t kFlows = 100;
  constexpr int kIterations = 20;

  generatePcap(pcapPath_, kPackets, kFlows);

  // Warm up — first extraction allocates internal buffers
  {
    NativeFlowExtractor warmup;
    auto features = warmup.extractFeatures(pcapPath_);
    ASSERT_FALSE(features.empty());
  }

  std::size_t rssBaseline = currentRssKb();
  if (rssBaseline == 0) {
    spdlog::warn("Cannot read /proc/self/status — skipping memory measurement");
  }

  std::vector<std::size_t> rssHistory;
  rssHistory.reserve(static_cast<std::size_t>(kIterations));

  for (int i = 0; i < kIterations; ++i) {
    NativeFlowExtractor extractor;
    auto features = extractor.extractFeatures(pcapPath_);
    EXPECT_FALSE(features.empty());

    std::size_t rssNow = currentRssKb();
    rssHistory.push_back(rssNow);
  }

  if (rssBaseline > 0) {
    std::size_t rssEnd = rssHistory.back();
    auto growth = static_cast<std::int64_t>(rssEnd) -
                  static_cast<std::int64_t>(rssBaseline);
    double growthMb = static_cast<double>(growth) / 1024.0;

    spdlog::info("Memory: baseline={} KB, final={} KB, growth={:.1f} MB across "
                 "{} iterations",
                 rssBaseline, rssEnd, growthMb, kIterations);

    // Allow up to 50MB growth for 20 iterations of 10k packets
    // (RSS can grow due to allocator fragmentation, but should be bounded)
    EXPECT_LT(growthMb, 50.0)
        << "Possible memory leak: RSS grew by " << growthMb << " MB";
  }
}

TEST_F(MemoryStressTest, largeFlowTable_memoryBounded) {
  // Generate pcap with many distinct flows — stresses the hash map
  constexpr std::uint32_t kPackets = 50'000;
  constexpr std::uint32_t kFlows = 10'000;

  generatePcap(pcapPath_, kPackets, kFlows);

  std::size_t rssBefore = currentRssKb();

  NativeFlowExtractor extractor;
  auto features = extractor.extractFeatures(pcapPath_);

  std::size_t rssAfter = currentRssKb();

  spdlog::info("Large flow table (10k flows): {} features extracted",
               features.size());

  if (rssBefore > 0 && rssAfter > 0) {
    auto growth = static_cast<std::int64_t>(rssAfter) -
                  static_cast<std::int64_t>(rssBefore);
    double growthMb = static_cast<double>(growth) / 1024.0;

    spdlog::info("  Memory: before={} KB, after={} KB, growth={:.1f} MB",
                 rssBefore, rssAfter, growthMb);

    // 10k flows with stats should fit comfortably in <200 MB
    EXPECT_LT(growthMb, 200.0)
        << "Excessive memory for 10k flows: " << growthMb << " MB";
  }

  EXPECT_GE(features.size(), kFlows);
}

TEST_F(MemoryStressTest, sustainedEvaluation_memoryStable) {
  // Run HybridDetectionService evaluations in a loop and track memory
  StubThreatIntel ti;
  StubRuleEngine rules;
  HybridDetectionService service(&ti, &rules);

  constexpr int kIterations = 50'000;
  constexpr int kCheckInterval = 10'000;

  std::size_t rssBaseline = currentRssKb();
  std::vector<std::pair<int, std::size_t>> checkpoints;

  for (int i = 0; i < kIterations; ++i) {
    nids::core::PredictionResult pred;
    pred.classification = (i % 3 == 0) ? nids::core::AttackType::DdosIcmp
                                       : nids::core::AttackType::Benign;
    pred.confidence = 0.85f;

    nids::core::FlowMetadata meta;
    meta.srcIp = std::format("10.0.0.{}", i % 256);
    meta.dstIp = "10.1.0.1";
    meta.srcPort = static_cast<std::uint16_t>(40000 + (i % 1000));
    meta.dstPort = 80;
    meta.protocol = "TCP";
    meta.totalFwdPackets = 100;
    meta.totalBwdPackets = 80;
    meta.fwdPacketsPerSecond = 500.0;

    auto result = service.evaluate(pred, meta.srcIp, meta.dstIp, meta);
    static_cast<void>(result);

    if ((i + 1) % kCheckInterval == 0) {
      std::size_t rssNow = currentRssKb();
      checkpoints.emplace_back(i + 1, rssNow);
    }
  }

  if (rssBaseline > 0 && !checkpoints.empty()) {
    spdlog::info("Sustained evaluation memory checkpoints (baseline={} KB):",
                 rssBaseline);
    for (const auto &[iter, rss] : checkpoints) {
      auto growthKb = static_cast<std::int64_t>(rss) -
                      static_cast<std::int64_t>(rssBaseline);
      spdlog::info("  iter={}: RSS={} KB (delta={:+d} KB)", iter, rss,
                   growthKb);
    }

    // Memory should not grow continuously — check last vs first checkpoint
    auto firstRss = static_cast<std::int64_t>(checkpoints.front().second);
    auto lastRss = static_cast<std::int64_t>(checkpoints.back().second);
    double growthMb = static_cast<double>(lastRss - firstRss) / 1024.0;

    EXPECT_LT(growthMb, 10.0)
        << "Memory grew " << growthMb
        << " MB during sustained evaluation — possible leak";
  }
}

TEST_F(MemoryStressTest, predictorMemory_noAccumulation) {
  // Ensure StubAnalyzer (and by extension OnnxAnalyzer pattern) doesn't leak
  StubAnalyzer analyzer;
  ASSERT_TRUE(analyzer.loadModel("dummy"));

  constexpr int kIterations = 100'000;
  std::vector<float> features(static_cast<std::size_t>(kFlowFeatureCount),
                              0.5f);

  std::size_t rssBefore = currentRssKb();

  for (int i = 0; i < kIterations; ++i) {
    features[0] = static_cast<float>(i % 65536); // Vary dst port
    auto result = analyzer.predictWithConfidence(features);
    static_cast<void>(result);
  }

  std::size_t rssAfter = currentRssKb();

  if (rssBefore > 0 && rssAfter > 0) {
    double growthMb =
        static_cast<double>(static_cast<std::int64_t>(rssAfter) -
                            static_cast<std::int64_t>(rssBefore)) /
        1024.0;

    spdlog::info("100k predictions: memory growth={:.1f} MB", growthMb);

    EXPECT_LT(growthMb, 5.0)
        << "Predictor memory grew " << growthMb << " MB over 100k calls";
  }
}
