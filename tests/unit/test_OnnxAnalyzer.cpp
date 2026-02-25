#include <gtest/gtest.h>
#include "infra/analysis/OnnxAnalyzer.h"
#include "infra/analysis/AnalyzerFactory.h"
#include "core/model/AttackType.h"

#include <vector>
#include <filesystem>

using nids::infra::OnnxAnalyzer;
using nids::infra::AnalyzerFactory;
using nids::infra::AnalyzerBackend;
using nids::infra::createAnalyzer;
using nids::core::AttackType;
using nids::core::IPacketAnalyzer;

namespace fs = std::filesystem;

// ── OnnxAnalyzer unit tests ──────────────────────────────────────────

TEST(OnnxAnalyzer, construct_doesNotThrow) {
    EXPECT_NO_THROW(OnnxAnalyzer analyzer);
}

TEST(OnnxAnalyzer, predictWithoutLoad_returnsUnknown) {
    OnnxAnalyzer analyzer;
    // Model not loaded — should return Unknown, not crash
    std::vector<float> features(77, 0.0f);
    EXPECT_EQ(analyzer.predict(features), AttackType::Unknown);
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
    // Passing a directory instead of a file
    EXPECT_FALSE(analyzer.loadModel("/tmp"));
}

TEST(OnnxAnalyzer, predictAfterFailedLoad_returnsUnknown) {
    OnnxAnalyzer analyzer;
    analyzer.loadModel("/nonexistent/model.onnx");
    std::vector<float> features(77, 1.0f);
    EXPECT_EQ(analyzer.predict(features), AttackType::Unknown);
}

TEST(OnnxAnalyzer, predictWithEmptyFeatures_returnsUnknown) {
    OnnxAnalyzer analyzer;
    // Even if model were loaded, empty features can't be classified
    std::vector<float> empty;
    EXPECT_EQ(analyzer.predict(empty), AttackType::Unknown);
}

// ── AnalyzerFactory tests ────────────────────────────────────────────

TEST(AnalyzerFactory, createOnnxBackend_returnsNonNull) {
    auto analyzer = createAnalyzer(AnalyzerBackend::Onnx);
    EXPECT_NE(analyzer, nullptr);
}

TEST(AnalyzerFactory, createOnnxBackend_returnsCorrectType) {
    auto analyzer = createAnalyzer(AnalyzerBackend::Onnx);
    // Verify it implements IPacketAnalyzer (can call loadModel/predict)
    EXPECT_FALSE(analyzer->loadModel("/nonexistent.onnx"));
    EXPECT_EQ(analyzer->predict({}), AttackType::Unknown);
}

TEST(AnalyzerFactory, defaultBackend_isOnnx) {
    auto analyzer = createAnalyzer();
    EXPECT_NE(analyzer, nullptr);
}

// ── Conditional tests requiring a real model file ────────────────────
// These tests run only when a model file exists at the expected path.
// In CI, the model may not be available — tests are skipped gracefully.

class OnnxAnalyzerWithModelTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Check common model paths
        for (const auto& candidate : {
            "src/model/model.onnx",
            "../src/model/model.onnx",
            "model.onnx"
        }) {
            if (fs::exists(candidate)) {
                modelPath_ = candidate;
                break;
            }
        }
    }

    std::string modelPath_;
};

TEST_F(OnnxAnalyzerWithModelTest, loadModel_validPath_returnsTrue) {
    if (modelPath_.empty()) {
        GTEST_SKIP() << "No model file found — skipping model-dependent test";
    }

    OnnxAnalyzer analyzer;
    EXPECT_TRUE(analyzer.loadModel(modelPath_));
}

TEST_F(OnnxAnalyzerWithModelTest, predict_returnsValidAttackType) {
    if (modelPath_.empty()) {
        GTEST_SKIP() << "No model file found — skipping model-dependent test";
    }

    OnnxAnalyzer analyzer;
    ASSERT_TRUE(analyzer.loadModel(modelPath_));

    // All-zeros feature vector (should produce some classification, not crash)
    std::vector<float> features(77, 0.0f);
    auto result = analyzer.predict(features);

    // Result should be a valid AttackType (not necessarily a specific one)
    EXPECT_NE(result, AttackType::Unknown);
}

TEST_F(OnnxAnalyzerWithModelTest, predict_deterministicWithSameInput) {
    if (modelPath_.empty()) {
        GTEST_SKIP() << "No model file found — skipping model-dependent test";
    }

    OnnxAnalyzer analyzer;
    ASSERT_TRUE(analyzer.loadModel(modelPath_));

    std::vector<float> features(77, 0.5f);
    auto result1 = analyzer.predict(features);
    auto result2 = analyzer.predict(features);
    EXPECT_EQ(result1, result2);
}
