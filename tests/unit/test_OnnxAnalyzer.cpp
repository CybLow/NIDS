/**
 * ONNX Analyzer unit + integration tests.
 *
 * Unit tests exercise error handling without a model file.
 * Integration tests (guarded by model-file existence) validate that the
 * real ONNX model loads, produces correct output shapes, returns valid
 * attack types, and gives deterministic/consistent results.
 */

#include <gtest/gtest.h>
#include "infra/analysis/OnnxAnalyzer.h"
#include "infra/analysis/AnalyzerFactory.h"
#include "infra/flow/NativeFlowExtractor.h"  // kFlowFeatureCount
#include "core/model/AttackType.h"
#include "core/model/PredictionResult.h"

#include <algorithm>
#include <filesystem>
#include <numeric>
#include <random>
#include <vector>

using nids::infra::OnnxAnalyzer;
using nids::infra::AnalyzerBackend;
using nids::infra::createAnalyzer;
using nids::infra::kFlowFeatureCount;
using nids::core::AttackType;
using nids::core::PredictionResult;
using nids::core::kAttackTypeCount;

namespace fs = std::filesystem;

// ── Helper: locate the model file ───────────────────────────────────

namespace {

/// Search common paths relative to the test working directory.
/// CTest may run from build/Debug, build/ci-gcc, or project root.
std::string findModelPath() {
    for (const auto& candidate : {
        "models/model.onnx",
        "../models/model.onnx",
        "../../models/model.onnx",
        "../../../models/model.onnx",
    }) {
        if (fs::exists(candidate)) {
            return candidate;
        }
    }
    return {};
}

} // anonymous namespace

// =====================================================================
//  Unit tests (no model file required)
// =====================================================================

TEST(OnnxAnalyzer, construct_doesNotThrow) {
    EXPECT_NO_THROW(OnnxAnalyzer analyzer);
}

TEST(OnnxAnalyzer, predictWithoutLoad_returnsUnknown) {
    OnnxAnalyzer analyzer;
    std::vector<float> features(kFlowFeatureCount, 0.0f);
    EXPECT_EQ(analyzer.predict(features), AttackType::Unknown);
}

TEST(OnnxAnalyzer, predictWithConfidenceWithoutLoad_returnsUnknown) {
    OnnxAnalyzer analyzer;
    std::vector<float> features(kFlowFeatureCount, 0.0f);
    auto result = analyzer.predictWithConfidence(features);
    EXPECT_TRUE(result.isUnknown());
    EXPECT_FLOAT_EQ(result.confidence, 0.0f);
}

TEST(OnnxAnalyzer, loadModel_invalidPath_returnsFalse) {
    OnnxAnalyzer analyzer;
    EXPECT_FALSE(analyzer.loadModel("/nonexistent/path/model.onnx"));
}

TEST(OnnxAnalyzer, loadModel_emptyPath_returnsFalse) {
    OnnxAnalyzer analyzer;
    EXPECT_FALSE(analyzer.loadModel(""));
}

TEST(OnnxAnalyzer, loadModel_directoryPath_returnsFalse) {
    OnnxAnalyzer analyzer;
    EXPECT_FALSE(analyzer.loadModel("/tmp"));
}

TEST(OnnxAnalyzer, predictAfterFailedLoad_returnsUnknown) {
    OnnxAnalyzer analyzer;
    [[maybe_unused]] auto loaded = analyzer.loadModel("/nonexistent/model.onnx");
    std::vector<float> features(kFlowFeatureCount, 1.0f);
    EXPECT_EQ(analyzer.predict(features), AttackType::Unknown);
}

TEST(OnnxAnalyzer, predictWithEmptyFeatures_returnsUnknown) {
    OnnxAnalyzer analyzer;
    std::vector<float> empty;
    EXPECT_EQ(analyzer.predict(empty), AttackType::Unknown);
}

// ── AnalyzerFactory tests ────────────────────────────────────────────

TEST(AnalyzerFactory, createOnnxBackend_returnsNonNull) {
    auto analyzer = createAnalyzer(AnalyzerBackend::Onnx);
    EXPECT_NE(analyzer, nullptr);
}

TEST(AnalyzerFactory, createOnnxBackend_implementsInterface) {
    auto analyzer = createAnalyzer(AnalyzerBackend::Onnx);
    EXPECT_FALSE(analyzer->loadModel("/nonexistent.onnx"));
    EXPECT_EQ(analyzer->predict({}), AttackType::Unknown);
}

TEST(AnalyzerFactory, defaultBackend_isOnnx) {
    auto analyzer = createAnalyzer();
    EXPECT_NE(analyzer, nullptr);
}

// =====================================================================
//  Integration tests (require models/model.onnx)
// =====================================================================

class OnnxModelTest : public ::testing::Test {
protected:
    void SetUp() override {
        modelPath_ = findModelPath();
        if (modelPath_.empty()) {
            GTEST_SKIP() << "Model file not found — skipping model integration test";
        }
    }

    std::string modelPath_;
};

TEST_F(OnnxModelTest, loadModel_validPath_succeeds) {
    OnnxAnalyzer analyzer;
    EXPECT_TRUE(analyzer.loadModel(modelPath_));
}

TEST_F(OnnxModelTest, loadModel_canReloadSameModel) {
    OnnxAnalyzer analyzer;
    ASSERT_TRUE(analyzer.loadModel(modelPath_));
    // Reloading the same model should succeed (replaces session)
    EXPECT_TRUE(analyzer.loadModel(modelPath_));
}

// ── Output shape and probability distribution ────────────────────────

TEST_F(OnnxModelTest, predict_allZeros_returnsValidType) {
    OnnxAnalyzer analyzer;
    ASSERT_TRUE(analyzer.loadModel(modelPath_));

    std::vector<float> features(kFlowFeatureCount, 0.0f);
    auto result = analyzer.predict(features);

    // Must be a valid AttackType, not Unknown (model should classify)
    EXPECT_NE(result, AttackType::Unknown);
    EXPECT_LT(static_cast<int>(result), kAttackTypeCount);
}

TEST_F(OnnxModelTest, predictWithConfidence_outputProbabilitiesSumToOne) {
    OnnxAnalyzer analyzer;
    ASSERT_TRUE(analyzer.loadModel(modelPath_));

    std::vector<float> features(kFlowFeatureCount, 0.0f);
    auto result = analyzer.predictWithConfidence(features);

    // Softmax output must sum to ~1.0
    float sum = 0.0f;
    for (int i = 0; i < kAttackTypeCount; ++i) {
        sum += result.probabilities[static_cast<std::size_t>(i)];
        // Each probability must be in [0, 1]
        EXPECT_GE(result.probabilities[static_cast<std::size_t>(i)], 0.0f);
        EXPECT_LE(result.probabilities[static_cast<std::size_t>(i)], 1.0f);
    }
    EXPECT_NEAR(sum, 1.0f, 1e-4f);
}

TEST_F(OnnxModelTest, predictWithConfidence_confidenceMatchesTopProbability) {
    OnnxAnalyzer analyzer;
    ASSERT_TRUE(analyzer.loadModel(modelPath_));

    std::vector<float> features(kFlowFeatureCount, 0.0f);
    auto result = analyzer.predictWithConfidence(features);

    // Confidence should equal the max probability in the distribution
    float maxProb = *std::ranges::max_element(result.probabilities);
    EXPECT_FLOAT_EQ(result.confidence, maxProb);

    // Classification must match the argmax of probabilities
    auto expectedIdx = static_cast<int>(std::distance(
        result.probabilities.begin(),
        std::ranges::max_element(result.probabilities)));
    EXPECT_EQ(static_cast<int>(result.classification), expectedIdx);
}

TEST_F(OnnxModelTest, predictWithConfidence_confidenceInValidRange) {
    OnnxAnalyzer analyzer;
    ASSERT_TRUE(analyzer.loadModel(modelPath_));

    std::vector<float> features(kFlowFeatureCount, 0.0f);
    auto result = analyzer.predictWithConfidence(features);

    EXPECT_GE(result.confidence, 0.0f);
    EXPECT_LE(result.confidence, 1.0f);
    // With 16 classes, max uniform probability is 1/16 ≈ 0.0625
    // A trained model should do better than random
    EXPECT_GT(result.confidence, 1.0f / static_cast<float>(kAttackTypeCount));
}

// ── Determinism ──────────────────────────────────────────────────────

TEST_F(OnnxModelTest, predict_deterministicWithSameInput) {
    OnnxAnalyzer analyzer;
    ASSERT_TRUE(analyzer.loadModel(modelPath_));

    std::vector<float> features(kFlowFeatureCount, 0.5f);
    auto result1 = analyzer.predict(features);
    auto result2 = analyzer.predict(features);
    EXPECT_EQ(result1, result2);
}

TEST_F(OnnxModelTest, predictWithConfidence_deterministicProbabilities) {
    OnnxAnalyzer analyzer;
    ASSERT_TRUE(analyzer.loadModel(modelPath_));

    std::vector<float> features(kFlowFeatureCount, 0.5f);
    auto r1 = analyzer.predictWithConfidence(features);
    auto r2 = analyzer.predictWithConfidence(features);

    EXPECT_EQ(r1.classification, r2.classification);
    EXPECT_FLOAT_EQ(r1.confidence, r2.confidence);
    for (int i = 0; i < kAttackTypeCount; ++i) {
        EXPECT_FLOAT_EQ(
            r1.probabilities[static_cast<std::size_t>(i)],
            r2.probabilities[static_cast<std::size_t>(i)]);
    }
}

// ── Different input distributions ────────────────────────────────────

TEST_F(OnnxModelTest, predict_differentInputs_canProduceDifferentOutputs) {
    OnnxAnalyzer analyzer;
    ASSERT_TRUE(analyzer.loadModel(modelPath_));

    // All-zeros vs large values should yield different probability distributions
    std::vector<float> zeros(kFlowFeatureCount, 0.0f);
    std::vector<float> large(kFlowFeatureCount, 10.0f);
    // Simulate a high-rate flow with port-scan-like features
    large[0] = 22.0f;     // dst port (SSH)
    large[36] = 50000.0f; // fwd packets/s (very high)
    large[37] = 50000.0f; // bwd packets/s

    auto r1 = analyzer.predictWithConfidence(zeros);
    auto r2 = analyzer.predictWithConfidence(large);

    // Probabilities should differ (model is responsive to input)
    bool probsDiffer = false;
    for (int i = 0; i < kAttackTypeCount; ++i) {
        if (std::abs(r1.probabilities[static_cast<std::size_t>(i)]
                   - r2.probabilities[static_cast<std::size_t>(i)]) > 1e-6f) {
            probsDiffer = true;
            break;
        }
    }
    EXPECT_TRUE(probsDiffer) << "Model produced identical outputs for very different inputs";
}

TEST_F(OnnxModelTest, predict_randomInputs_allReturnValidTypes) {
    OnnxAnalyzer analyzer;
    ASSERT_TRUE(analyzer.loadModel(modelPath_));

    std::mt19937 rng(42);
    std::uniform_real_distribution<float> dist(-5.0f, 5.0f);

    constexpr int kTrials = 50;
    for (int trial = 0; trial < kTrials; ++trial) {
        std::vector<float> features(kFlowFeatureCount);
        std::ranges::generate(features,
                              [&]() { return dist(rng); });

        auto result = analyzer.predictWithConfidence(features);

        EXPECT_NE(result.classification, AttackType::Unknown)
            << "Trial " << trial << " returned Unknown";
        EXPECT_GE(result.confidence, 0.0f);
        EXPECT_LE(result.confidence, 1.0f);
    }
}

// ── Feature count boundary ───────────────────────────────────────────

TEST_F(OnnxModelTest, predict_wrongFeatureCount_handlesGracefully) {
    OnnxAnalyzer analyzer;
    ASSERT_TRUE(analyzer.loadModel(modelPath_));

    // Too few features (half of expected)
    std::vector<float> tooFew(kFlowFeatureCount / 2, 1.0f);
    // This may throw or return Unknown — either is acceptable
    // The important thing is it doesn't crash
    EXPECT_NO_FATAL_FAILURE({
        [[maybe_unused]] auto r = analyzer.predict(tooFew);
    });

    // Too many features (double expected)
    std::vector<float> tooMany(kFlowFeatureCount * 2, 1.0f);
    EXPECT_NO_FATAL_FAILURE({
        [[maybe_unused]] auto r = analyzer.predict(tooMany);
    });
}

// ── AnalyzerFactory with real model ──────────────────────────────────

TEST_F(OnnxModelTest, factory_createdAnalyzerCanLoadAndPredict) {
    auto analyzer = createAnalyzer(AnalyzerBackend::Onnx);
    ASSERT_NE(analyzer, nullptr);
    ASSERT_TRUE(analyzer->loadModel(modelPath_));

    std::vector<float> features(kFlowFeatureCount, 0.0f);
    auto result = analyzer->predictWithConfidence(features);

    EXPECT_FALSE(result.isUnknown());
    EXPECT_GE(result.confidence, 0.0f);
    EXPECT_LE(result.confidence, 1.0f);
}

// ── Batch-like sequential predictions ────────────────────────────────

TEST_F(OnnxModelTest, predict_sequentialCalls_noStateLeakage) {
    OnnxAnalyzer analyzer;
    ASSERT_TRUE(analyzer.loadModel(modelPath_));

    // Run many predictions sequentially to check for memory leaks or state issues
    std::mt19937 rng(123);
    std::uniform_real_distribution<float> dist(-3.0f, 3.0f);

    constexpr int kBatch = 100;
    for (int i = 0; i < kBatch; ++i) {
        std::vector<float> features(kFlowFeatureCount);
        std::ranges::generate(features,
                              [&]() { return dist(rng); });

        auto result = analyzer.predictWithConfidence(features);
        ASSERT_NE(result.classification, AttackType::Unknown)
            << "Prediction " << i << " returned Unknown unexpectedly";
        ASSERT_GE(result.confidence, 0.0f);
    }

    // Verify determinism wasn't broken by the batch
    std::vector<float> check(kFlowFeatureCount, 0.0f);
    auto r1 = analyzer.predict(check);
    auto r2 = analyzer.predict(check);
    EXPECT_EQ(r1, r2);
}
