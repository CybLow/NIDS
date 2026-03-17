#include "core/services/Configuration.h"
#include "infra/config/ConfigLoader.h"
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

using nids::core::Configuration;

namespace fs = std::filesystem;

TEST(Configuration, singletonReturnsSameInstance) {
  auto &a = Configuration::instance();
  auto &b = Configuration::instance();
  EXPECT_EQ(&a, &b);
}

TEST(Configuration, defaultModelPathIsSet) {
  const auto &config = Configuration::instance();
  EXPECT_FALSE(config.modelPath().empty());
  EXPECT_EQ(config.modelPath().filename(), "model.onnx");
}

TEST(Configuration, defaultMetadataPathIsSet) {
  const auto &config = Configuration::instance();
  EXPECT_FALSE(config.modelMetadataPath().empty());
  EXPECT_EQ(config.modelMetadataPath().filename(), "model_metadata.json");
}

TEST(Configuration, setModelPathUpdatesPath) {
  auto &config = Configuration::instance();
  auto original = config.modelPath();

  config.setModelPath("/tmp/custom_model.onnx");
  EXPECT_EQ(config.modelPath(), fs::path("/tmp/custom_model.onnx"));

  // Restore original to avoid polluting other tests
  config.setModelPath(original);
}

TEST(Configuration, defaultDumpFileIsSet) {
  const auto &config = Configuration::instance();
  EXPECT_EQ(config.defaultDumpFile(), "dump.pcap");
}

TEST(Configuration, flowTimeoutIsPositive) {
  const auto &config = Configuration::instance();
  EXPECT_GT(config.flowTimeoutUs(), 0);
}

TEST(Configuration, idleThresholdIsPositive) {
  const auto &config = Configuration::instance();
  EXPECT_GT(config.idleThresholdUs(), 0);
}

TEST(Configuration, flowTimeoutGreaterThanIdleThreshold) {
  const auto &config = Configuration::instance();
  EXPECT_GT(config.flowTimeoutUs(), config.idleThresholdUs());
}

TEST(Configuration, onnxThreadCountIsPositive) {
  const auto &config = Configuration::instance();
  EXPECT_GT(config.onnxIntraOpThreads(), 0);
}

TEST(Configuration, tempDirectoryExists) {
  const auto &config = Configuration::instance();
  EXPECT_TRUE(fs::exists(config.tempDirectory()));
  EXPECT_TRUE(fs::is_directory(config.tempDirectory()));
}

TEST(Configuration, windowTitleIsNonEmpty) {
  const auto &config = Configuration::instance();
  EXPECT_FALSE(config.windowTitle().empty());
}

// -- ConfigLoader tests --

TEST(ConfigLoader, nonexistentFileReturnsTrue) {
  auto &config = Configuration::instance();
  // Non-existent config file should succeed (use defaults)
  EXPECT_TRUE(
      nids::infra::loadConfigFromFile("/nonexistent/path/config.json", config));
}

TEST(ConfigLoader, validJsonOverridesModelPath) {
  auto &config = Configuration::instance();
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
  auto &config = Configuration::instance();
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
  auto &config = Configuration::instance();
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
  auto &config = Configuration::instance();
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
  auto &config = Configuration::instance();

  auto tmpPath = fs::temp_directory_path() / "nids_test_config_bad.json";
  {
    std::ofstream out(tmpPath);
    out << "{ this is not valid JSON }}}";
  }

  EXPECT_FALSE(nids::infra::loadConfigFromFile(tmpPath, config));

  fs::remove(tmpPath);
}

TEST(ConfigLoader, emptyJsonSucceeds) {
  auto &config = Configuration::instance();

  auto tmpPath = fs::temp_directory_path() / "nids_test_config_empty.json";
  {
    std::ofstream out(tmpPath);
    out << "{}";
  }

  EXPECT_TRUE(nids::infra::loadConfigFromFile(tmpPath, config));

  fs::remove(tmpPath);
}

TEST(ConfigLoader, existingButUnreadableFileReturnsFalse) {
#ifdef _WIN32
  GTEST_SKIP() << "POSIX file permission semantics not portable on Windows";
#endif
  auto &config = Configuration::instance();

  // Create a temporary file, then remove read permission
  auto tmpPath = fs::temp_directory_path() / "nids_test_config_noread.json";
  {
    std::ofstream out(tmpPath);
    out << R"({"model": {"path": "test.onnx"}})";
  }
  // Remove all permissions so ifstream cannot open it
  fs::permissions(tmpPath, fs::perms::none);

  EXPECT_FALSE(nids::infra::loadConfigFromFile(tmpPath, config));

  // Restore permissions and cleanup
  fs::permissions(tmpPath, fs::perms::owner_all);
  fs::remove(tmpPath);
}

// ── ConfigLoader: threat_intel.directory override ────────────────────

TEST(ConfigLoader, validJsonOverridesThreatIntelDirectory) {
  auto &config = Configuration::instance();
  auto origDir = config.threatIntelDirectory();

  auto tmpPath = fs::temp_directory_path() / "nids_test_config_ti.json";
  {
    std::ofstream out(tmpPath);
    out << R"({
            "threat_intel": {
                "directory": "/opt/nids/feeds"
            }
        })";
  }

  EXPECT_TRUE(nids::infra::loadConfigFromFile(tmpPath, config));
  EXPECT_EQ(config.threatIntelDirectory(), "/opt/nids/feeds");

  // Restore and cleanup
  config.setThreatIntelDirectory(origDir);
  fs::remove(tmpPath);
}

// ── ConfigLoader: model.onnx_intra_op_threads override ───────────────

TEST(ConfigLoader, validJsonOverridesOnnxThreads) {
  auto &config = Configuration::instance();
  auto origThreads = config.onnxIntraOpThreads();

  auto tmpPath = fs::temp_directory_path() / "nids_test_config_threads.json";
  {
    std::ofstream out(tmpPath);
    out << R"({
            "model": {
                "onnx_intra_op_threads": 8
            }
        })";
  }

  EXPECT_TRUE(nids::infra::loadConfigFromFile(tmpPath, config));
  EXPECT_EQ(config.onnxIntraOpThreads(), 8);

  // Restore and cleanup
  config.setOnnxIntraOpThreads(origThreads);
  fs::remove(tmpPath);
}

// ── ConfigLoader: all sections combined ──────────────────────────────

// ── Direct setter/getter round-trip tests ─────────────────────────────
// These cover setter code paths not exercised via ConfigLoader.

TEST(Configuration, setAndGetLiveFlowTimeoutUs) {
  auto &config = Configuration::instance();
  auto orig = config.liveFlowTimeoutUs();

  config.setLiveFlowTimeoutUs(30'000'000);
  EXPECT_EQ(config.liveFlowTimeoutUs(), 30'000'000);

  config.setLiveFlowTimeoutUs(orig);
}

TEST(Configuration, setAndGetMaxFlowDurationUs) {
  auto &config = Configuration::instance();
  auto orig = config.maxFlowDurationUs();

  config.setMaxFlowDurationUs(20'000'000);
  EXPECT_EQ(config.maxFlowDurationUs(), 20'000'000);

  config.setMaxFlowDurationUs(orig);
}

TEST(Configuration, setAndGetModelMetadataPath) {
  auto &config = Configuration::instance();
  auto orig = config.modelMetadataPath();

  config.setModelMetadataPath("/tmp/test_meta.json");
  EXPECT_EQ(config.modelMetadataPath(), fs::path("/tmp/test_meta.json"));

  config.setModelMetadataPath(orig);
}

TEST(Configuration, setAndGetThreatIntelDirectory) {
  auto &config = Configuration::instance();
  auto orig = config.threatIntelDirectory();

  config.setThreatIntelDirectory("/opt/ti_feeds");
  EXPECT_EQ(config.threatIntelDirectory(), fs::path("/opt/ti_feeds"));

  config.setThreatIntelDirectory(orig);
}

TEST(ConfigLoader, validJsonOverridesMultipleSections) {
  auto &config = Configuration::instance();
  auto origModel = config.modelPath();
  auto origDump = config.defaultDumpFile();
  auto origTitle = config.windowTitle();
  auto origMl = config.weightMl();

  auto tmpPath = fs::temp_directory_path() / "nids_test_config_multi.json";
  {
    std::ofstream out(tmpPath);
    out << R"({
            "model": {
                "path": "/tmp/test.onnx"
            },
            "capture": {
                "dump_file": "test_dump.pcap"
            },
            "hybrid_detection": {
                "weight_ml": 0.5
            },
            "ui": {
                "window_title": "Multi Test"
            }
        })";
  }

  EXPECT_TRUE(nids::infra::loadConfigFromFile(tmpPath, config));
  EXPECT_EQ(config.modelPath(), fs::path("/tmp/test.onnx"));
  EXPECT_EQ(config.defaultDumpFile(), "test_dump.pcap");
  EXPECT_FLOAT_EQ(config.weightMl(), 0.5f);
  EXPECT_EQ(config.windowTitle(), "Multi Test");

  // Restore and cleanup
  config.setModelPath(origModel);
  config.setDefaultDumpFile(origDump);
  config.setWeightMl(origMl);
  config.setWindowTitle(origTitle);
  fs::remove(tmpPath);
}
