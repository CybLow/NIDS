#include <gtest/gtest.h>
#include "infra/analysis/FeatureNormalizer.h"
#include "infra/flow/NativeFlowExtractor.h"  // kFlowFeatureCount

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <vector>

using nids::infra::FeatureNormalizer;
using nids::infra::kFlowFeatureCount;

namespace fs = std::filesystem;

// ── Test fixture with temp metadata files ────────────────────────────

class FeatureNormalizerTest : public ::testing::Test {
protected:
    const std::string testDir_ = "test_normalizer";

    void SetUp() override {
        fs::create_directories(testDir_);
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(testDir_, ec);
    }

    std::string writeMetadata(const std::string& name, const std::string& content) {
        auto path = testDir_ + "/" + name;
        std::ofstream file(path);
        file << content;
        return path;
    }

    /// Create a minimal valid metadata JSON with N features.
    std::string writeValidMetadata(const std::string& name, std::size_t nFeatures,
                                   float clipValue = 10.0f) {
        std::string means = "[";
        std::string stds = "[";
        for (std::size_t i = 0; i < nFeatures; ++i) {
            means += std::to_string(static_cast<double>(i));
            stds += std::to_string(1.0 + static_cast<double>(i));
            if (i + 1 < nFeatures) {
                means += ",";
                stds += ",";
            }
        }
        means += "]";
        stds += "]";

        auto json = R"({"normalization":{"method":"standard_scaler","means":)" +
                    means + R"(,"stds":)" + stds +
                    R"(,"clip_value":)" + std::to_string(clipValue) + R"(}})";
        return writeMetadata(name, json);
    }
};

// ── Initial state ────────────────────────────────────────────────────

TEST_F(FeatureNormalizerTest, defaultConstruction_notLoaded) {
    FeatureNormalizer normalizer;
    EXPECT_FALSE(normalizer.isLoaded());
    EXPECT_EQ(normalizer.featureCount(), 0u);
}

// ── loadMetadata: success cases ──────────────────────────────────────

TEST_F(FeatureNormalizerTest, loadMetadata_validFile_returnsTrue) {
    auto path = writeValidMetadata("valid.json", 3);
    FeatureNormalizer normalizer;
    EXPECT_TRUE(normalizer.loadMetadata(path));
    EXPECT_TRUE(normalizer.isLoaded());
    EXPECT_EQ(normalizer.featureCount(), 3u);
}

TEST_F(FeatureNormalizerTest, loadMetadata_77Features_returnsTrue) {
    auto path = writeValidMetadata("full.json", kFlowFeatureCount);
    FeatureNormalizer normalizer;
    EXPECT_TRUE(normalizer.loadMetadata(path));
    EXPECT_EQ(normalizer.featureCount(), kFlowFeatureCount);
}

// ── loadMetadata: failure cases ──────────────────────────────────────

TEST_F(FeatureNormalizerTest, loadMetadata_nonexistentFile_returnsFalse) {
    FeatureNormalizer normalizer;
    EXPECT_FALSE(normalizer.loadMetadata("nonexistent.json"));
    EXPECT_FALSE(normalizer.isLoaded());
}

TEST_F(FeatureNormalizerTest, loadMetadata_invalidJson_returnsFalse) {
    auto path = writeMetadata("bad.json", "{ not valid json }}}");
    FeatureNormalizer normalizer;
    EXPECT_FALSE(normalizer.loadMetadata(path));
    EXPECT_FALSE(normalizer.isLoaded());
}

TEST_F(FeatureNormalizerTest, loadMetadata_missingNormalizationKey_returnsFalse) {
    auto path = writeMetadata("no_norm.json", R"({"n_classes":16})");
    FeatureNormalizer normalizer;
    EXPECT_FALSE(normalizer.loadMetadata(path));
    EXPECT_FALSE(normalizer.isLoaded());
}

TEST_F(FeatureNormalizerTest, loadMetadata_missingMeans_returnsFalse) {
    auto path = writeMetadata("no_means.json",
        R"({"normalization":{"stds":[1.0,2.0],"clip_value":10.0}})");
    FeatureNormalizer normalizer;
    EXPECT_FALSE(normalizer.loadMetadata(path));
}

TEST_F(FeatureNormalizerTest, loadMetadata_missingStds_returnsFalse) {
    auto path = writeMetadata("no_stds.json",
        R"({"normalization":{"means":[1.0,2.0],"clip_value":10.0}})");
    FeatureNormalizer normalizer;
    EXPECT_FALSE(normalizer.loadMetadata(path));
}

TEST_F(FeatureNormalizerTest, loadMetadata_missingClipValue_returnsFalse) {
    auto path = writeMetadata("no_clip.json",
        R"({"normalization":{"means":[1.0,2.0],"stds":[1.0,2.0]}})");
    FeatureNormalizer normalizer;
    EXPECT_FALSE(normalizer.loadMetadata(path));
    EXPECT_FALSE(normalizer.isLoaded());
}

TEST_F(FeatureNormalizerTest, loadMetadata_meansStdsSizeMismatch_returnsFalse) {
    auto path = writeMetadata("mismatch.json",
        R"({"normalization":{"means":[1.0,2.0],"stds":[1.0],"clip_value":10.0}})");
    FeatureNormalizer normalizer;
    EXPECT_FALSE(normalizer.loadMetadata(path));
}

// ── normalize: StandardScaler correctness ────────────────────────────

TEST_F(FeatureNormalizerTest, normalize_appliesStandardScaler) {
    // means=[0, 10], stds=[1, 2], clip=10
    auto path = writeMetadata("scaler.json",
        R"({"normalization":{"means":[0.0,10.0],"stds":[1.0,2.0],"clip_value":10.0}})");
    FeatureNormalizer normalizer;
    ASSERT_TRUE(normalizer.loadMetadata(path));

    auto result = normalizer.normalize({5.0f, 14.0f});
    ASSERT_EQ(result.size(), 2u);

    // (5 - 0) / 1 = 5.0
    EXPECT_FLOAT_EQ(result[0], 5.0f);
    // (14 - 10) / 2 = 2.0
    EXPECT_FLOAT_EQ(result[1], 2.0f);
}

TEST_F(FeatureNormalizerTest, normalize_clipsToRange) {
    // means=[0], stds=[1], clip=3
    auto path = writeMetadata("clip.json",
        R"({"normalization":{"means":[0.0],"stds":[1.0],"clip_value":3.0}})");
    FeatureNormalizer normalizer;
    ASSERT_TRUE(normalizer.loadMetadata(path));

    // (100 - 0) / 1 = 100 -> clipped to 3
    auto pos = normalizer.normalize({100.0f});
    ASSERT_EQ(pos.size(), 1u);
    EXPECT_FLOAT_EQ(pos[0], 3.0f);

    // (-100 - 0) / 1 = -100 -> clipped to -3
    auto neg = normalizer.normalize({-100.0f});
    ASSERT_EQ(neg.size(), 1u);
    EXPECT_FLOAT_EQ(neg[0], -3.0f);
}

TEST_F(FeatureNormalizerTest, normalize_nearZeroStdReplacedWithOne) {
    // std near zero (1e-12) should be treated as 1.0 to prevent division by zero
    auto path = writeMetadata("zero_std.json",
        R"({"normalization":{"means":[5.0],"stds":[1e-12],"clip_value":10.0}})");
    FeatureNormalizer normalizer;
    ASSERT_TRUE(normalizer.loadMetadata(path));

    // std replaced with 1.0, so (7 - 5) / 1.0 = 2.0
    auto result = normalizer.normalize({7.0f});
    ASSERT_EQ(result.size(), 1u);
    EXPECT_FLOAT_EQ(result[0], 2.0f);
}

// ── normalize: edge cases ────────────────────────────────────────────

TEST_F(FeatureNormalizerTest, normalize_notLoaded_returnsInputUnchanged) {
    FeatureNormalizer normalizer;
    std::vector<float> input = {1.0f, 2.0f, 3.0f};
    auto result = normalizer.normalize(input);
    EXPECT_EQ(result, input);
}

TEST_F(FeatureNormalizerTest, normalize_dimensionMismatch_returnsInputUnchanged) {
    auto path = writeValidMetadata("dim.json", 3);
    FeatureNormalizer normalizer;
    ASSERT_TRUE(normalizer.loadMetadata(path));

    // Pass 5 features when normalizer expects 3
    std::vector<float> input = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
    auto result = normalizer.normalize(input);
    EXPECT_EQ(result, input);
}

TEST_F(FeatureNormalizerTest, normalize_emptyInput_returnsEmpty) {
    // Load with 0-feature metadata (degenerate but valid JSON)
    auto path = writeMetadata("empty.json",
        R"({"normalization":{"means":[],"stds":[],"clip_value":10.0}})");
    FeatureNormalizer normalizer;
    ASSERT_TRUE(normalizer.loadMetadata(path));
    EXPECT_EQ(normalizer.featureCount(), 0u);

    auto result = normalizer.normalize({});
    EXPECT_TRUE(result.empty());
}

// ── reload behavior ──────────────────────────────────────────────────

TEST_F(FeatureNormalizerTest, loadMetadata_canReloadDifferentFile) {
    auto path3 = writeValidMetadata("three.json", 3);
    auto path5 = writeValidMetadata("five.json", 5);

    FeatureNormalizer normalizer;
    ASSERT_TRUE(normalizer.loadMetadata(path3));
    EXPECT_EQ(normalizer.featureCount(), 3u);

    ASSERT_TRUE(normalizer.loadMetadata(path5));
    EXPECT_EQ(normalizer.featureCount(), 5u);
}

TEST_F(FeatureNormalizerTest, loadMetadata_failedReload_clearsLoadedState) {
    auto path = writeValidMetadata("good.json", 3);
    FeatureNormalizer normalizer;
    ASSERT_TRUE(normalizer.loadMetadata(path));
    EXPECT_TRUE(normalizer.isLoaded());

    // Reload with bad file
    EXPECT_FALSE(normalizer.loadMetadata("nonexistent.json"));
    EXPECT_FALSE(normalizer.isLoaded());
}

// ── Full 77-feature normalization ────────────────────────────────────

TEST_F(FeatureNormalizerTest, normalize_full77Features_succeeds) {
    auto path = writeValidMetadata("full77.json", kFlowFeatureCount);
    FeatureNormalizer normalizer;
    ASSERT_TRUE(normalizer.loadMetadata(path));

    std::vector<float> input(kFlowFeatureCount);
    for (std::size_t i = 0; i < kFlowFeatureCount; ++i) {
        input[i] = static_cast<float>(i) * 2.0f;
    }

    auto result = normalizer.normalize(input);
    ASSERT_EQ(result.size(), kFlowFeatureCount);

    // Verify each element: (input[i] - mean[i]) / std[i] with clip
    // mean[i] = i, std[i] = 1+i, clip = 10
    for (std::size_t i = 0; i < kFlowFeatureCount; ++i) {
        float expected = (input[i] - static_cast<float>(i))
                       / (1.0f + static_cast<float>(i));
        expected = std::clamp(expected, -10.0f, 10.0f);
        EXPECT_FLOAT_EQ(result[i], expected) << "Mismatch at feature " << i;
    }
}

// ── Negative inputs ──────────────────────────────────────────────────

TEST_F(FeatureNormalizerTest, normalize_negativeInputs_handledCorrectly) {
    auto path = writeMetadata("neg.json",
        R"({"normalization":{"means":[0.0,0.0],"stds":[1.0,1.0],"clip_value":5.0}})");
    FeatureNormalizer normalizer;
    ASSERT_TRUE(normalizer.loadMetadata(path));

    auto result = normalizer.normalize({-3.0f, -100.0f});
    ASSERT_EQ(result.size(), 2u);
    EXPECT_FLOAT_EQ(result[0], -3.0f);
    EXPECT_FLOAT_EQ(result[1], -5.0f);  // Clipped to -5.0
}

// ── Non-array JSON types for means/stds ──────────────────────────────

TEST_F(FeatureNormalizerTest, loadMetadata_meansNotArray_returnsFalse) {
    auto path = writeMetadata("bad_type.json",
        R"({"normalization":{"means":"not_an_array","stds":[1.0],"clip_value":10.0}})");
    FeatureNormalizer normalizer;
    EXPECT_FALSE(normalizer.loadMetadata(path));
}

TEST_F(FeatureNormalizerTest, loadMetadata_stdsNotArray_returnsFalse) {
    auto path = writeMetadata("bad_type2.json",
        R"({"normalization":{"means":[1.0],"stds":42,"clip_value":10.0}})");
    FeatureNormalizer normalizer;
    EXPECT_FALSE(normalizer.loadMetadata(path));
}

TEST_F(FeatureNormalizerTest, loadMetadata_clipValueNotNumber_returnsFalse) {
    auto path = writeMetadata("bad_clip.json",
        R"({"normalization":{"means":[1.0],"stds":[1.0],"clip_value":"ten"}})");
    FeatureNormalizer normalizer;
    EXPECT_FALSE(normalizer.loadMetadata(path));
}

// ── Zero-value inputs ────────────────────────────────────────────────

TEST_F(FeatureNormalizerTest, normalize_allZeroInputs_normalizedCorrectly) {
    auto path = writeMetadata("zeros.json",
        R"({"normalization":{"means":[5.0,10.0],"stds":[2.0,4.0],"clip_value":10.0}})");
    FeatureNormalizer normalizer;
    ASSERT_TRUE(normalizer.loadMetadata(path));

    auto result = normalizer.normalize({0.0f, 0.0f});
    ASSERT_EQ(result.size(), 2u);
    EXPECT_FLOAT_EQ(result[0], -2.5f);  // (0 - 5) / 2
    EXPECT_FLOAT_EQ(result[1], -2.5f);  // (0 - 10) / 4
}

// ── Normalize with wrong feature count ───────────────────────────────

TEST_F(FeatureNormalizerTest, normalize_featureCountMismatch_returnsRaw) {
    // Load valid 2-feature metadata
    auto path = writeMetadata("two.json",
        R"({"normalization":{"means":[1.0,2.0],"stds":[1.0,1.0],"clip_value":10.0}})");
    FeatureNormalizer normalizer;
    ASSERT_TRUE(normalizer.loadMetadata(path));
    ASSERT_EQ(normalizer.featureCount(), 2u);

    // Pass 3 features instead of 2 → returns raw features unchanged
    std::vector<float> raw = {5.0f, 10.0f, 15.0f};
    auto result = normalizer.normalize(raw);
    ASSERT_EQ(result.size(), 3u);
    EXPECT_FLOAT_EQ(result[0], 5.0f);
    EXPECT_FLOAT_EQ(result[1], 10.0f);
    EXPECT_FLOAT_EQ(result[2], 15.0f);
}
