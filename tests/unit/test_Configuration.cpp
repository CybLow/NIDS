#include <gtest/gtest.h>
#include "core/services/Configuration.h"
#include "infra/config/ConfigLoader.h"

#include <filesystem>
#include <fstream>

using nids::core::Configuration;

namespace fs = std::filesystem;

TEST(Configuration, singletonReturnsSameInstance) {
    auto& a = Configuration::instance();
    auto& b = Configuration::instance();
    EXPECT_EQ(&a, &b);
}

TEST(Configuration, defaultModelPathIsSet) {
    const auto& config = Configuration::instance();
    EXPECT_FALSE(config.modelPath().empty());
    EXPECT_EQ(config.modelPath().filename(), "model.onnx");
}

TEST(Configuration, defaultMetadataPathIsSet) {
    const auto& config = Configuration::instance();
    EXPECT_FALSE(config.modelMetadataPath().empty());
    EXPECT_EQ(config.modelMetadataPath().filename(), "model_metadata.json");
}

TEST(Configuration, setModelPathUpdatesPath) {
    auto& config = Configuration::instance();
    auto original = config.modelPath();

    config.setModelPath("/tmp/custom_model.onnx");
    EXPECT_EQ(config.modelPath(), fs::path("/tmp/custom_model.onnx"));

    // Restore original to avoid polluting other tests
    config.setModelPath(original);
}

TEST(Configuration, defaultDumpFileIsSet) {
    const auto& config = Configuration::instance();
    EXPECT_EQ(config.defaultDumpFile(), "dump.pcap");
}

TEST(Configuration, flowTimeoutIsPositive) {
    const auto& config = Configuration::instance();
    EXPECT_GT(config.flowTimeoutUs(), 0);
}

TEST(Configuration, idleThresholdIsPositive) {
    const auto& config = Configuration::instance();
    EXPECT_GT(config.idleThresholdUs(), 0);
}

TEST(Configuration, flowTimeoutGreaterThanIdleThreshold) {
    const auto& config = Configuration::instance();
    EXPECT_GT(config.flowTimeoutUs(), config.idleThresholdUs());
}

TEST(Configuration, onnxThreadCountIsPositive) {
    const auto& config = Configuration::instance();
    EXPECT_GT(config.onnxIntraOpThreads(), 0);
}

TEST(Configuration, tempDirectoryExists) {
    const auto& config = Configuration::instance();
    EXPECT_TRUE(fs::exists(config.tempDirectory()));
    EXPECT_TRUE(fs::is_directory(config.tempDirectory()));
}

TEST(Configuration, windowTitleIsNonEmpty) {
    const auto& config = Configuration::instance();
    EXPECT_FALSE(config.windowTitle().empty());
}

// -- ConfigLoader tests --

TEST(ConfigLoader, nonexistentFileReturnsTrue) {
    auto& config = Configuration::instance();
    // Non-existent config file should succeed (use defaults)
    EXPECT_TRUE(nids::infra::loadConfigFromFile("/nonexistent/path/config.json", config));
}

TEST(ConfigLoader, validJsonOverridesModelPath) {
    auto& config = Configuration::instance();
    auto original = config.modelPath();

    // Write a temporary config file
    auto tmpPath = fs::temp_directory_path() / "nids_test_config.json";
    {
        std::ofstream out(tmpPath);
        out << R"({
            "model": {
                "path": "/opt/nids/custom_model.onnx",
                "metadata_path": "/opt/nids/custom_meta.json"
            }
        })";
    }

    EXPECT_TRUE(nids::infra::loadConfigFromFile(tmpPath, config));
    EXPECT_EQ(config.modelPath(), fs::path("/opt/nids/custom_model.onnx"));
    EXPECT_EQ(config.modelMetadataPath(), fs::path("/opt/nids/custom_meta.json"));

    // Restore and cleanup
    config.setModelPath(original);
    config.setModelMetadataPath("models/model_metadata.json");
    fs::remove(tmpPath);
}

TEST(ConfigLoader, validJsonOverridesHybridWeights) {
    auto& config = Configuration::instance();
    auto origMl = config.weightMl();
    auto origTi = config.weightThreatIntel();
    auto origHeur = config.weightHeuristic();
    auto origThresh = config.mlConfidenceThreshold();

    auto tmpPath = fs::temp_directory_path() / "nids_test_config_weights.json";
    {
        std::ofstream out(tmpPath);
        out << R"({
            "hybrid_detection": {
                "ml_confidence_threshold": 0.85,
                "weight_ml": 0.6,
                "weight_threat_intel": 0.25,
                "weight_heuristic": 0.15
            }
        })";
    }

    EXPECT_TRUE(nids::infra::loadConfigFromFile(tmpPath, config));
    EXPECT_FLOAT_EQ(config.mlConfidenceThreshold(), 0.85f);
    EXPECT_FLOAT_EQ(config.weightMl(), 0.6f);
    EXPECT_FLOAT_EQ(config.weightThreatIntel(), 0.25f);
    EXPECT_FLOAT_EQ(config.weightHeuristic(), 0.15f);

    // Restore and cleanup
    config.setMlConfidenceThreshold(origThresh);
    config.setWeightMl(origMl);
    config.setWeightThreatIntel(origTi);
    config.setWeightHeuristic(origHeur);
    fs::remove(tmpPath);
}

TEST(ConfigLoader, validJsonOverridesCaptureSettings) {
    auto& config = Configuration::instance();
    auto origDump = config.defaultDumpFile();
    auto origTimeout = config.flowTimeoutUs();
    auto origIdle = config.idleThresholdUs();

    auto tmpPath = fs::temp_directory_path() / "nids_test_config_capture.json";
    {
        std::ofstream out(tmpPath);
        out << R"({
            "capture": {
                "dump_file": "custom_dump.pcap",
                "flow_timeout_us": 300000000,
                "idle_threshold_us": 10000000
            }
        })";
    }

    EXPECT_TRUE(nids::infra::loadConfigFromFile(tmpPath, config));
    EXPECT_EQ(config.defaultDumpFile(), "custom_dump.pcap");
    EXPECT_EQ(config.flowTimeoutUs(), 300000000);
    EXPECT_EQ(config.idleThresholdUs(), 10000000);

    // Restore and cleanup
    config.setDefaultDumpFile(origDump);
    config.setFlowTimeoutUs(origTimeout);
    config.setIdleThresholdUs(origIdle);
    fs::remove(tmpPath);
}

TEST(ConfigLoader, partialJsonKeepsOtherDefaults) {
    auto& config = Configuration::instance();
    auto origTitle = config.windowTitle();
    auto origModelPath = config.modelPath();

    auto tmpPath = fs::temp_directory_path() / "nids_test_config_partial.json";
    {
        std::ofstream out(tmpPath);
        out << R"({
            "ui": {
                "window_title": "Custom NIDS Title"
            }
        })";
    }

    EXPECT_TRUE(nids::infra::loadConfigFromFile(tmpPath, config));
    EXPECT_EQ(config.windowTitle(), "Custom NIDS Title");
    // Model path should remain unchanged
    EXPECT_EQ(config.modelPath(), origModelPath);

    // Restore and cleanup
    config.setWindowTitle(origTitle);
    fs::remove(tmpPath);
}

TEST(ConfigLoader, malformedJsonReturnsFalse) {
    auto& config = Configuration::instance();

    auto tmpPath = fs::temp_directory_path() / "nids_test_config_bad.json";
    {
        std::ofstream out(tmpPath);
        out << "{ this is not valid JSON }}}";
    }

    EXPECT_FALSE(nids::infra::loadConfigFromFile(tmpPath, config));

    fs::remove(tmpPath);
}

TEST(ConfigLoader, emptyJsonSucceeds) {
    auto& config = Configuration::instance();

    auto tmpPath = fs::temp_directory_path() / "nids_test_config_empty.json";
    {
        std::ofstream out(tmpPath);
        out << "{}";
    }

    EXPECT_TRUE(nids::infra::loadConfigFromFile(tmpPath, config));

    fs::remove(tmpPath);
}
