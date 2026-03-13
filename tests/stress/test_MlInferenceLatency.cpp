/**
 * Stress test: ML inference latency benchmark.
 *
 * Measures predict() call latency and throughput using a stub analyzer
 * (no ONNX Runtime dependency). When ONNX Runtime and a model file are
 * available, also benchmarks the real OnnxAnalyzer.
 */

#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include "stress/StressTestHelpers.h"
#include "infra/flow/NativeFlowExtractor.h"
#include "core/model/AttackType.h"
#include "core/model/PredictionResult.h"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <random>
#include <vector>

#ifdef NIDS_HAS_ONNX
#include "infra/analysis/OnnxAnalyzer.h"
#include "infra/analysis/AnalyzerFactory.h"
#endif  // NIDS_HAS_ONNX

using nids::infra::kFlowFeatureCount;
using nids::core::AttackType;
using nids::test::ScopedTimer;
using nids::test::StubAnalyzer;

namespace {

/// Generate `count` random feature vectors of kFlowFeatureCount dimensions.
std::vector<std::vector<float>> generateFeatures(std::size_t count, unsigned seed = 42) {
    std::mt19937 rng(seed);
    std::uniform_real_distribution<float> dist(-3.0f, 3.0f);

    std::vector<std::vector<float>> features(count);
    for (auto& fv : features) {
        fv.resize(static_cast<std::size_t>(kFlowFeatureCount));
        std::ranges::generate(fv, [&]() { return dist(rng); });
        // Set first feature (dst port) to realistic value
        fv[0] = static_cast<float>(rng() % 65536);
    }
    return features;
}

} // anonymous namespace

class MlInferenceLatencyTest : public ::testing::Test {
protected:
    StubAnalyzer analyzer_;
};

TEST_F(MlInferenceLatencyTest, predict_10kFlows_throughput) {
    constexpr std::size_t kFlows = 10'000;
    auto features = generateFeatures(kFlows);

    double elapsedMs = 0.0;
    std::size_t attackCount = 0;
    {
        ScopedTimer timer(elapsedMs);
        for (const auto& fv : features) {
            auto type = analyzer_.predict(fv);
            if (type != AttackType::Benign && type != AttackType::Unknown) {
                ++attackCount;
            }
        }
    }

    double flowsPerSec = static_cast<double>(kFlows) / (elapsedMs / 1000.0);
    double avgLatencyUs = elapsedMs * 1000.0 / static_cast<double>(kFlows);
    spdlog::info("predict() 10k flows: {:.1f} ms total, {:.1f} us/flow, {:.0f} flows/sec, "
                 "{} attacks detected",
                 elapsedMs, avgLatencyUs, flowsPerSec, attackCount);

    // Stub should be extremely fast
    EXPECT_GT(flowsPerSec, 100'000.0) << "Stub predict() throughput too low";
}

TEST_F(MlInferenceLatencyTest, predictWithConfidence_10kFlows_throughput) {
    constexpr std::size_t kFlows = 10'000;
    auto features = generateFeatures(kFlows);

    double elapsedMs = 0.0;
    std::vector<float> confidences;
    confidences.reserve(kFlows);
    {
        ScopedTimer timer(elapsedMs);
        for (const auto& fv : features) {
            auto result = analyzer_.predictWithConfidence(fv);
            confidences.push_back(result.confidence);
        }
    }

    double flowsPerSec = static_cast<double>(kFlows) / (elapsedMs / 1000.0);
    float avgConf = std::accumulate(confidences.begin(), confidences.end(), 0.0f)
                    / static_cast<float>(confidences.size());
    spdlog::info("predictWithConfidence() 10k flows: {:.1f} ms, {:.0f} flows/sec, "
                 "avg confidence={:.3f}",
                 elapsedMs, flowsPerSec, avgConf);

    EXPECT_GT(flowsPerSec, 50'000.0);
}

TEST_F(MlInferenceLatencyTest, predict_100kFlows_sustained) {
    constexpr std::size_t kFlows = 100'000;
    auto features = generateFeatures(kFlows);

    double elapsedMs = 0.0;
    {
        ScopedTimer timer(elapsedMs);
        for (const auto& fv : features) {
            auto result = analyzer_.predictWithConfidence(fv);
            // Force the compiler not to optimize away
            if (result.confidence < 0.0f) {
                FAIL() << "Negative confidence should never happen";
            }
        }
    }

    double flowsPerSec = static_cast<double>(kFlows) / (elapsedMs / 1000.0);
    spdlog::info("Sustained 100k predictions: {:.1f} ms, {:.0f} flows/sec",
                 elapsedMs, flowsPerSec);

    EXPECT_GT(flowsPerSec, 50'000.0);
}

TEST_F(MlInferenceLatencyTest, predict_latencyDistribution) {
    constexpr std::size_t kFlows = 10'000;
    auto features = generateFeatures(kFlows);

    std::vector<double> latenciesUs;
    latenciesUs.reserve(kFlows);

    for (const auto& fv : features) {
        auto start = std::chrono::steady_clock::now();
        auto result = analyzer_.predictWithConfidence(fv);
        auto end = std::chrono::steady_clock::now();

        // Suppress unused variable
        static_cast<void>(result);

        double us = std::chrono::duration<double, std::micro>(end - start).count();
        latenciesUs.push_back(us);
    }

    std::ranges::sort(latenciesUs);

    double p50 = latenciesUs[kFlows / 2];
    double p95 = latenciesUs[kFlows * 95 / 100];
    double p99 = latenciesUs[kFlows * 99 / 100];
    double maxLat = latenciesUs.back();

    spdlog::info("Latency distribution (us): p50={:.1f}, p95={:.1f}, p99={:.1f}, max={:.1f}",
                 p50, p95, p99, maxLat);

    // p99 should be under 1ms for stub analyzer
    EXPECT_LT(p99, 1000.0) << "p99 latency exceeds 1ms";
}

TEST_F(MlInferenceLatencyTest, predict_deterministic_sameInput) {
    constexpr std::size_t kIterations = 1'000;
    auto features = generateFeatures(1);

    // Same input should always produce same output
    auto firstResult = analyzer_.predictWithConfidence(features[0]);
    for (std::size_t i = 0; i < kIterations; ++i) {
        auto result = analyzer_.predictWithConfidence(features[0]);
        EXPECT_EQ(result.classification, firstResult.classification);
        EXPECT_FLOAT_EQ(result.confidence, firstResult.confidence);
    }
}

#ifdef NIDS_HAS_ONNX

class OnnxInferenceStressTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Skip if model file doesn't exist
        if (!std::filesystem::exists("models/model.onnx")) {
            GTEST_SKIP() << "ONNX model not available (models/model.onnx)";
        }
        analyzer_ = nids::infra::AnalyzerFactory::create();
        ASSERT_TRUE(analyzer_->loadModel("models/model.onnx"));
    }

    std::unique_ptr<nids::core::IPacketAnalyzer> analyzer_;
};

TEST_F(OnnxInferenceStressTest, predict_1kFlows_realModel) {
    constexpr std::size_t kFlows = 1'000;
    auto features = generateFeatures(kFlows);

    double elapsedMs = 0.0;
    {
        ScopedTimer timer(elapsedMs);
        for (const auto& fv : features) {
            auto result = analyzer_->predictWithConfidence(fv);
            static_cast<void>(result);
        }
    }

    double flowsPerSec = static_cast<double>(kFlows) / (elapsedMs / 1000.0);
    double avgLatencyMs = elapsedMs / static_cast<double>(kFlows);
    spdlog::info("ONNX predict() 1k flows: {:.1f} ms total, {:.2f} ms/flow, {:.0f} flows/sec",
                 elapsedMs, avgLatencyMs, flowsPerSec);

    // Real ONNX inference should handle at least 100 flows/sec
    EXPECT_GT(flowsPerSec, 100.0) << "ONNX inference too slow";
}

#endif  // NIDS_HAS_ONNX
