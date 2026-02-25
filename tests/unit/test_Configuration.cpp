#include <gtest/gtest.h>
#include "core/services/Configuration.h"

#include <filesystem>

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

TEST(Configuration, loadFromFile_nonexistentFileReturnsTrue) {
    auto& config = Configuration::instance();
    // Non-existent config file should succeed (use defaults)
    EXPECT_TRUE(config.loadFromFile("/nonexistent/path/config.json"));
}
