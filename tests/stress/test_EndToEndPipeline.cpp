#include "StressTestHelpers.h"

#include "app/HybridDetectionService.h"
#include "app/LiveDetectionPipeline.h"
#include "core/model/CaptureSession.h"
#include "infra/output/ConsoleAlertSink.h"

#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <string>

using namespace nids;
using namespace nids::test;

/// Full pipeline: packet → flow extraction → ML inference → hybrid detection
/// → output sinks. Measures end-to-end throughput.
class EndToEndPipelineStress : public ::testing::Test {
protected:
    void SetUp() override {
        // Generate a test pcap.
        pcapPath_ = std::filesystem::temp_directory_path() / "nids_e2e_stress.pcap";
        generatePcap(pcapPath_, kPacketCount, kFlowCount);
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove(pcapPath_, ec);
    }

    static constexpr std::size_t kPacketCount = 50000;
    static constexpr std::size_t kFlowCount = 500;
    std::filesystem::path pcapPath_;
};

TEST_F(EndToEndPipelineStress, fullPipeline_50kPackets_completesUnder10s) {
    // Setup components.
    infra::NativeFlowExtractor extractor;
    StubAnalyzer analyzer;
    StubNormalizer normalizer;
    core::CaptureSession session;

    app::LiveDetectionPipeline pipeline(extractor, analyzer, normalizer, session);

    app::HybridDetectionService hybridService(nullptr, nullptr);
    pipeline.setHybridDetection(&hybridService);

    // Count output events.
    std::atomic<std::size_t> outputCount{0};
    infra::ConsoleAlertSink alertSink;

    pipeline.start();

    // Feed packets from the generated pcap through the pipeline.
    double elapsedMs = 0;
    {
        ScopedTimer timer(elapsedMs);

        auto features = extractor.extractFeatures(pcapPath_.string());
        const auto& metadata = extractor.flowMetadata();

        for (std::size_t i = 0; i < features.size(); ++i) {
            auto prediction = analyzer.predictWithConfidence(features[i]);
            auto result = hybridService.evaluate(
                prediction, metadata[i].srcIp, metadata[i].dstIp, metadata[i]);
            outputCount.fetch_add(1);
        }
    }

    pipeline.stop();

    // Performance gates.
    EXPECT_LT(elapsedMs, 10000.0) << "Full pipeline should complete within 10s";
    EXPECT_GT(outputCount.load(), 0u) << "Should produce detection results";

    const double flowsPerSec = static_cast<double>(outputCount.load()) /
                                (elapsedMs / 1000.0);
    // Expect at least 50 flows/sec through the full pipeline.
    EXPECT_GT(flowsPerSec, 50.0)
        << "Pipeline throughput: " << flowsPerSec << " flows/sec";
}

TEST_F(EndToEndPipelineStress, fullPipeline_memoryBounded) {
    auto rssBefore = currentRssKb();

    infra::NativeFlowExtractor extractor;
    StubAnalyzer analyzer;
    StubNormalizer normalizer;
    core::CaptureSession session;

    app::LiveDetectionPipeline pipeline(extractor, analyzer, normalizer, session);
    app::HybridDetectionService hybridService(nullptr, nullptr);
    pipeline.setHybridDetection(&hybridService);
    pipeline.start();

    auto features = extractor.extractFeatures(pcapPath_.string());
    const auto& metadata = extractor.flowMetadata();

    for (std::size_t i = 0; i < features.size(); ++i) {
        auto prediction = analyzer.predictWithConfidence(features[i]);
        [[maybe_unused]] auto result = hybridService.evaluate(
            prediction, metadata[i].srcIp, metadata[i].dstIp, metadata[i]);
    }

    pipeline.stop();

    auto rssAfter = currentRssKb();
    auto growthMb = static_cast<double>(rssAfter - rssBefore) / 1024.0;

    // Memory growth should be bounded (< 100 MB for 50k packets).
    EXPECT_LT(growthMb, 100.0)
        << "Memory growth: " << growthMb << " MB";
}

TEST_F(EndToEndPipelineStress, hybridDetection_throughput) {
    infra::NativeFlowExtractor extractor;
    StubAnalyzer analyzer;
    StubNormalizer normalizer;

    auto features = extractor.extractFeatures(pcapPath_.string());
    const auto& metadata = extractor.flowMetadata();

    app::HybridDetectionService hybridService(nullptr, nullptr);

    double elapsedMs = 0;
    std::size_t evaluated = 0;
    {
        ScopedTimer timer(elapsedMs);
        for (std::size_t i = 0; i < features.size(); ++i) {
            auto prediction = analyzer.predictWithConfidence(features[i]);
            [[maybe_unused]] auto result = hybridService.evaluate(
                prediction, metadata[i].srcIp, metadata[i].dstIp, metadata[i]);
            ++evaluated;
        }
    }

    const double evalsPerSec = static_cast<double>(evaluated) /
                                (elapsedMs / 1000.0);
    // Hybrid detection should process >10k evaluations/sec.
    EXPECT_GT(evalsPerSec, 10000.0)
        << "Hybrid detection throughput: " << evalsPerSec << " evals/sec";
}
