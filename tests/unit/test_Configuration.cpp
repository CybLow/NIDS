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

// ── ConfigLoader: output section overrides ──────────────────────────

TEST(ConfigLoader, validJsonOverridesSyslogOutput) {
  auto &config = Configuration::instance();
  auto orig = config.syslogOutputConfig();

  auto tmpPath = fs::temp_directory_path() / "nids_test_config_syslog.json";
  {
    std::ofstream out(tmpPath);
    out << R"({
            "output": {
                "syslog": {
                    "enabled": true,
                    "host": "siem.example.com",
                    "port": 1514,
                    "transport": "tcp",
                    "format": "cef"
                }
            }
        })";
  }

  EXPECT_TRUE(nids::infra::loadConfigFromFile(tmpPath, config));
  const auto &sc = config.syslogOutputConfig();
  EXPECT_TRUE(sc.enabled);
  EXPECT_EQ(sc.host, "siem.example.com");
  EXPECT_EQ(sc.port, 1514);
  EXPECT_EQ(sc.transport, "tcp");
  EXPECT_EQ(sc.format, "cef");

  config.setSyslogOutputConfig(orig);
  fs::remove(tmpPath);
}

TEST(ConfigLoader, validJsonOverridesJsonFileOutput) {
  auto &config = Configuration::instance();
  auto orig = config.jsonFileOutputConfig();

  auto tmpPath = fs::temp_directory_path() / "nids_test_config_jsonfile.json";
  {
    std::ofstream out(tmpPath);
    out << R"({
            "output": {
                "json_file": {
                    "enabled": true,
                    "path": "/var/log/nids/alerts.jsonl",
                    "max_size_mb": 50,
                    "max_files": 10
                }
            }
        })";
  }

  EXPECT_TRUE(nids::infra::loadConfigFromFile(tmpPath, config));
  const auto &jc = config.jsonFileOutputConfig();
  EXPECT_TRUE(jc.enabled);
  EXPECT_EQ(jc.path, fs::path("/var/log/nids/alerts.jsonl"));
  EXPECT_EQ(jc.maxSizeMb, 50u);
  EXPECT_EQ(jc.maxFiles, 10);

  config.setJsonFileOutputConfig(orig);
  fs::remove(tmpPath);
}

TEST(ConfigLoader, validJsonOverridesConsoleOutput) {
  auto &config = Configuration::instance();
  auto orig = config.consoleOutputEnabled();

  auto tmpPath = fs::temp_directory_path() / "nids_test_config_console.json";
  {
    std::ofstream out(tmpPath);
    out << R"({
            "output": {
                "console": {
                    "enabled": false
                }
            }
        })";
  }

  EXPECT_TRUE(nids::infra::loadConfigFromFile(tmpPath, config));
  EXPECT_FALSE(config.consoleOutputEnabled());

  config.setConsoleOutputEnabled(orig);
  fs::remove(tmpPath);
}

TEST(ConfigLoader, validJsonOverridesAllOutputSinks) {
  auto &config = Configuration::instance();
  auto origSyslog = config.syslogOutputConfig();
  auto origJson = config.jsonFileOutputConfig();
  auto origConsole = config.consoleOutputEnabled();

  auto tmpPath = fs::temp_directory_path() / "nids_test_config_alloutput.json";
  {
    std::ofstream out(tmpPath);
    out << R"({
            "output": {
                "syslog": {
                    "enabled": true,
                    "format": "leef"
                },
                "json_file": {
                    "enabled": true,
                    "max_files": 7
                },
                "console": {
                    "enabled": true
                }
            }
        })";
  }

  EXPECT_TRUE(nids::infra::loadConfigFromFile(tmpPath, config));
  EXPECT_TRUE(config.syslogOutputConfig().enabled);
  EXPECT_EQ(config.syslogOutputConfig().format, "leef");
  EXPECT_TRUE(config.jsonFileOutputConfig().enabled);
  EXPECT_EQ(config.jsonFileOutputConfig().maxFiles, 7);
  EXPECT_TRUE(config.consoleOutputEnabled());

  config.setSyslogOutputConfig(origSyslog);
  config.setJsonFileOutputConfig(origJson);
  config.setConsoleOutputEnabled(origConsole);
  fs::remove(tmpPath);
}

// ── ConfigLoader: hunting section overrides ─────────────────────────

TEST(ConfigLoader, validJsonOverridesHuntingConfig) {
  auto &config = Configuration::instance();
  auto orig = config.huntingConfig();

  auto tmpPath = fs::temp_directory_path() / "nids_test_config_hunting.json";
  {
    std::ofstream out(tmpPath);
    out << R"({
            "hunting": {
                "enabled": true,
                "flow_database_path": "/var/lib/nids/hunt.db",
                "max_database_size_mb": 2048,
                "index_all_flows": false,
                "baseline_window_hours": 72,
                "anomaly_threshold_sigma": 2.5,
                "pcap_storage": {
                    "storage_dir": "/var/lib/nids/pcap",
                    "max_total_size_bytes": 5368709120,
                    "max_retention_hours": 48,
                    "max_file_size_bytes": 52428800,
                    "file_prefix": "hunt_capture"
                }
            }
        })";
  }

  EXPECT_TRUE(nids::infra::loadConfigFromFile(tmpPath, config));
  const auto &hc = config.huntingConfig();
  EXPECT_TRUE(hc.enabled);
  EXPECT_EQ(hc.flowDatabasePath, fs::path("/var/lib/nids/hunt.db"));
  EXPECT_EQ(hc.maxDatabaseSizeMb, 2048u);
  EXPECT_FALSE(hc.indexAllFlows);
  EXPECT_EQ(hc.baselineWindowHours, 72);
  EXPECT_DOUBLE_EQ(hc.anomalyThresholdSigma, 2.5);
  EXPECT_EQ(hc.pcapStorage.storageDir,
            fs::path("/var/lib/nids/pcap"));
  EXPECT_EQ(hc.pcapStorage.maxTotalSizeBytes, 5368709120u);
  EXPECT_EQ(hc.pcapStorage.maxRetentionHours, 48);
  EXPECT_EQ(hc.pcapStorage.maxFileSizeBytes, 52428800u);
  EXPECT_EQ(hc.pcapStorage.filePrefix, "hunt_capture");

  config.setHuntingConfig(orig);
  fs::remove(tmpPath);
}

TEST(Configuration, huntingConfigDefaults) {
  auto &config = Configuration::instance();
  const auto &hc = config.huntingConfig();

  EXPECT_FALSE(hc.enabled);
  EXPECT_EQ(hc.flowDatabasePath, fs::path("data/flows.db"));
  EXPECT_EQ(hc.maxDatabaseSizeMb, 1024u);
  EXPECT_TRUE(hc.indexAllFlows);
  EXPECT_EQ(hc.baselineWindowHours, 168);
  EXPECT_DOUBLE_EQ(hc.anomalyThresholdSigma, 3.0);
  EXPECT_EQ(hc.pcapStorage.storageDir, fs::path("data/pcap"));
  EXPECT_EQ(hc.pcapStorage.maxRetentionHours, 168);
  EXPECT_EQ(hc.pcapStorage.filePrefix, "nids_capture");
}

TEST(Configuration, setHuntingConfig_roundTrip) {
  auto &config = Configuration::instance();
  auto orig = config.huntingConfig();

  Configuration::HuntingConfig hc;
  hc.enabled = true;
  hc.flowDatabasePath = "/test/path.db";
  hc.maxDatabaseSizeMb = 512;
  hc.indexAllFlows = false;
  hc.baselineWindowHours = 24;
  hc.anomalyThresholdSigma = 2.0;
  hc.pcapStorage.storageDir = "/test/pcap";
  hc.pcapStorage.maxTotalSizeBytes = 1024;
  hc.pcapStorage.maxRetentionHours = 12;
  hc.pcapStorage.maxFileSizeBytes = 512;
  hc.pcapStorage.filePrefix = "test_capture";

  config.setHuntingConfig(hc);

  const auto &stored = config.huntingConfig();
  EXPECT_TRUE(stored.enabled);
  EXPECT_EQ(stored.flowDatabasePath, fs::path("/test/path.db"));
  EXPECT_EQ(stored.maxDatabaseSizeMb, 512u);
  EXPECT_FALSE(stored.indexAllFlows);
  EXPECT_EQ(stored.baselineWindowHours, 24);
  EXPECT_DOUBLE_EQ(stored.anomalyThresholdSigma, 2.0);
  EXPECT_EQ(stored.pcapStorage.storageDir, fs::path("/test/pcap"));
  EXPECT_EQ(stored.pcapStorage.maxTotalSizeBytes, 1024u);
  EXPECT_EQ(stored.pcapStorage.maxRetentionHours, 12);
  EXPECT_EQ(stored.pcapStorage.maxFileSizeBytes, 512u);
  EXPECT_EQ(stored.pcapStorage.filePrefix, "test_capture");

  config.setHuntingConfig(orig);
}

TEST(ConfigLoader, validJsonHuntingPartialOverride) {
  auto &config = Configuration::instance();
  auto orig = config.huntingConfig();

  auto tmpPath = fs::temp_directory_path() / "nids_test_config_hunt_partial.json";
  {
    std::ofstream out(tmpPath);
    out << R"({
            "hunting": {
                "enabled": true
            }
        })";
  }

  EXPECT_TRUE(nids::infra::loadConfigFromFile(tmpPath, config));
  EXPECT_TRUE(config.huntingConfig().enabled);
  // Defaults preserved for unset fields.
  EXPECT_EQ(config.huntingConfig().baselineWindowHours, 168);

  config.setHuntingConfig(orig);
  fs::remove(tmpPath);
}
