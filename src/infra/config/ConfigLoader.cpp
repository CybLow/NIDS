#include "infra/config/ConfigLoader.h"
#include "core/services/Configuration.h"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <expected>
#include <fstream>

namespace nids::infra {

namespace {

/// Helper: extract a value from JSON if the key exists, applying a setter.
template <typename T, typename Setter>
void applyIfPresent(const nlohmann::json &obj, const std::string &key,
                    Setter setter) {
  if (obj.contains(key)) {
    setter(obj[key].get<T>());
  }
}

} // anonymous namespace

std::expected<void, std::string> loadConfigFromFile(
    const std::filesystem::path &configPath,
    core::Configuration &config) {
  namespace fs = std::filesystem;

  if (!fs::exists(configPath)) {
    spdlog::debug("Config file '{}' not found, using defaults",
                  configPath.string());
    return {};
  }

  try {
    std::ifstream file(configPath);
    if (!file.is_open()) {
      std::string msg = fmt::format("ConfigLoader: cannot open '{}'",
                                    configPath.string());
      spdlog::error(msg);
      return std::unexpected<std::string>(std::move(msg));
    }

    auto json = nlohmann::json::parse(file);

    // -- Model --
    if (json.contains("model")) {
      const auto &model = json["model"];
      applyIfPresent<std::string>(
          model, "path",
          [&config](const std::string &v) { config.setModelPath(v); });
      applyIfPresent<std::string>(
          model, "metadata_path",
          [&config](const std::string &v) { config.setModelMetadataPath(v); });
      applyIfPresent<int>(model, "onnx_intra_op_threads", [&config](int v) {
        config.setOnnxIntraOpThreads(v);
      });
    }

    // -- Capture --
    if (json.contains("capture")) {
      const auto &capture = json["capture"];
      applyIfPresent<std::string>(
          capture, "dump_file",
          [&config](const std::string &v) { config.setDefaultDumpFile(v); });
      applyIfPresent<int64_t>(capture, "flow_timeout_us", [&config](int64_t v) {
        config.setFlowTimeoutUs(v);
      });
      applyIfPresent<int64_t>(
          capture, "live_flow_timeout_us",
          [&config](int64_t v) { config.setLiveFlowTimeoutUs(v); });
      applyIfPresent<int64_t>(
          capture, "idle_threshold_us",
          [&config](int64_t v) { config.setIdleThresholdUs(v); });
    }

    // -- Threat Intelligence --
    if (json.contains("threat_intel")) {
      const auto &ti = json["threat_intel"];
      applyIfPresent<std::string>(ti, "directory",
                                  [&config](const std::string &v) {
                                    config.setThreatIntelDirectory(v);
                                  });
    }

    // -- Hybrid Detection --
    if (json.contains("hybrid_detection")) {
      const auto &hd = json["hybrid_detection"];
      applyIfPresent<float>(hd, "ml_confidence_threshold", [&config](float v) {
        config.setMlConfidenceThreshold(v);
      });
      applyIfPresent<float>(hd, "weight_ml",
                            [&config](float v) { config.setWeightMl(v); });
      applyIfPresent<float>(hd, "weight_threat_intel", [&config](float v) {
        config.setWeightThreatIntel(v);
      });
      applyIfPresent<float>(hd, "weight_heuristic", [&config](float v) {
        config.setWeightHeuristic(v);
      });
    }

    // -- Output Sinks --
    if (json.contains("output")) {
      const auto &output = json["output"];

      // Syslog
      if (output.contains("syslog")) {
        const auto &sl = output["syslog"];
        core::Configuration::SyslogOutputConfig sc;
        applyIfPresent<bool>(sl, "enabled",
                             [&sc](bool v) { sc.enabled = v; });
        applyIfPresent<std::string>(sl, "host",
                                     [&sc](std::string_view v) { sc.host = v; });
        applyIfPresent<std::uint16_t>(sl, "port",
                                       [&sc](std::uint16_t v) { sc.port = v; });
        applyIfPresent<std::string>(
            sl, "transport",
            [&sc](std::string_view v) { sc.transport = v; });
        applyIfPresent<std::string>(
            sl, "format",
            [&sc](std::string_view v) { sc.format = v; });
        config.setSyslogOutputConfig(sc);
      }

      // JSON file
      if (output.contains("json_file")) {
        const auto &jf = output["json_file"];
        core::Configuration::JsonFileOutputConfig jc;
        applyIfPresent<bool>(jf, "enabled",
                             [&jc](bool v) { jc.enabled = v; });
        applyIfPresent<std::string>(jf, "path",
                                     [&jc](std::string_view v) { jc.path = v; });
        applyIfPresent<std::size_t>(jf, "max_size_mb",
                                    [&jc](std::size_t v) { jc.maxSizeMb = v; });
        applyIfPresent<int>(jf, "max_files",
                            [&jc](int v) { jc.maxFiles = v; });
        config.setJsonFileOutputConfig(jc);
      }

      // Console
      if (output.contains("console")) {
        const auto &con = output["console"];
        applyIfPresent<bool>(con, "enabled", [&config](bool v) {
          config.setConsoleOutputEnabled(v);
        });
      }
    }

    // -- Threat Hunting --
    if (json.contains("hunting")) {
      const auto &hunting = json["hunting"];
      core::Configuration::HuntingConfig hc;
      applyIfPresent<bool>(hunting, "enabled",
                           [&hc](bool v) { hc.enabled = v; });
      applyIfPresent<std::string>(
          hunting, "flow_database_path",
          [&hc](std::string_view v) { hc.flowDatabasePath = v; });
      applyIfPresent<std::size_t>(
          hunting, "max_database_size_mb",
          [&hc](std::size_t v) { hc.maxDatabaseSizeMb = v; });
      applyIfPresent<bool>(hunting, "index_all_flows",
                           [&hc](bool v) { hc.indexAllFlows = v; });
      applyIfPresent<int>(hunting, "baseline_window_hours",
                          [&hc](int v) { hc.baselineWindowHours = v; });
      applyIfPresent<double>(
          hunting, "anomaly_threshold_sigma",
          [&hc](double v) { hc.anomalyThresholdSigma = v; });

      if (hunting.contains("pcap_storage")) {
        const auto &ps = hunting["pcap_storage"];
        applyIfPresent<std::string>(
            ps, "storage_dir",
            [&hc](std::string_view v) { hc.pcapStorage.storageDir = v; });
        applyIfPresent<std::size_t>(
            ps, "max_total_size_bytes",
            [&hc](std::size_t v) {
                hc.pcapStorage.maxTotalSizeBytes = v;
            });
        applyIfPresent<int64_t>(
            ps, "max_retention_hours",
            [&hc](int64_t v) { hc.pcapStorage.maxRetentionHours = v; });
        applyIfPresent<std::size_t>(
            ps, "max_file_size_bytes",
            [&hc](std::size_t v) {
                hc.pcapStorage.maxFileSizeBytes = v;
            });
        applyIfPresent<std::string>(
            ps, "file_prefix",
            [&hc](std::string_view v) {
                hc.pcapStorage.filePrefix = v;
            });
      }

      config.setHuntingConfig(hc);
    }

    // -- YARA Content Scanning --
    if (json.contains("yara")) {
      const auto &yara = json["yara"];
      core::Configuration::YaraConfig yc;
      applyIfPresent<bool>(yara, "enabled",
                           [&yc](bool v) { yc.enabled = v; });
      applyIfPresent<std::string>(
          yara, "rules_directory",
          [&yc](std::string_view v) { yc.rulesDirectory = v; });
      applyIfPresent<bool>(yara, "scan_packets",
                           [&yc](bool v) { yc.scanPackets = v; });
      applyIfPresent<bool>(yara, "scan_streams",
                           [&yc](bool v) { yc.scanStreams = v; });
      applyIfPresent<int>(yara, "scan_timeout_ms",
                          [&yc](int v) { yc.scanTimeoutMs = v; });
      applyIfPresent<std::size_t>(
          yara, "max_stream_size_bytes",
          [&yc](std::size_t v) { yc.maxStreamSizeBytes = v; });
      applyIfPresent<std::size_t>(
          yara, "max_concurrent_streams",
          [&yc](std::size_t v) { yc.maxConcurrentStreams = v; });
      applyIfPresent<bool>(yara, "hot_reload",
                           [&yc](bool v) { yc.hotReload = v; });
      applyIfPresent<float>(yara, "weight",
                            [&yc](float v) { yc.weight = v; });

      config.setYaraConfig(yc);
    }

    // -- Snort Signatures --
    if (json.contains("signatures")) {
      const auto &sig = json["signatures"];
      core::Configuration::SignatureConfig sc;
      applyIfPresent<bool>(sig, "enabled",
                           [&sc](bool v) { sc.enabled = v; });
      applyIfPresent<std::string>(
          sig, "rules_directory",
          [&sc](std::string_view v) { sc.rulesDirectory = v; });
      applyIfPresent<bool>(sig, "hot_reload",
                           [&sc](bool v) { sc.hotReload = v; });
      applyIfPresent<std::string>(
          sig, "home_net",
          [&sc](std::string_view v) { sc.homeNet = v; });
      applyIfPresent<std::string>(
          sig, "external_net",
          [&sc](std::string_view v) { sc.externalNet = v; });
      applyIfPresent<std::string>(
          sig, "http_ports",
          [&sc](std::string_view v) { sc.httpPorts = v; });
      applyIfPresent<float>(sig, "weight",
                            [&sc](float v) { sc.weight = v; });

      config.setSignatureConfig(sc);
    }

    // -- Inline IPS --
    if (json.contains("inline")) {
      const auto &inl = json["inline"];
      core::Configuration::InlineIpsConfig ic;
      applyIfPresent<bool>(inl, "enabled",
                           [&ic](bool v) { ic.enabled = v; });
      applyIfPresent<std::string>(
          inl, "input_interface",
          [&ic](std::string_view v) { ic.inputInterface = v; });
      applyIfPresent<std::string>(
          inl, "output_interface",
          [&ic](std::string_view v) { ic.outputInterface = v; });
      applyIfPresent<bool>(inl, "fail_open",
                           [&ic](bool v) { ic.failOpen = v; });
      applyIfPresent<bool>(inl, "block_on_ti",
                           [&ic](bool v) { ic.blockOnTiMatch = v; });
      applyIfPresent<bool>(inl, "block_on_signature",
                           [&ic](bool v) { ic.blockOnSignature = v; });
      applyIfPresent<bool>(inl, "block_on_yara",
                           [&ic](bool v) { ic.blockOnYara = v; });
      applyIfPresent<bool>(inl, "block_on_ml",
                           [&ic](bool v) { ic.blockOnMlVerdict = v; });
      applyIfPresent<float>(inl, "ml_block_threshold",
                            [&ic](float v) { ic.mlBlockThreshold = v; });
      applyIfPresent<int>(inl, "block_duration_seconds",
                          [&ic](int v) { ic.blockDurationSeconds = v; });
      applyIfPresent<int>(inl, "bypass_clean_packet_threshold",
                          [&ic](int v) { ic.bypassCleanPacketThreshold = v; });
      applyIfPresent<bool>(inl, "bypass_enabled",
                           [&ic](bool v) { ic.bypassEnabled = v; });

      config.setInlineIpsConfig(ic);
    }

    // -- UI --
    if (json.contains("ui")) {
      const auto &ui = json["ui"];
      applyIfPresent<std::string>(
          ui, "window_title",
          [&config](const std::string &v) { config.setWindowTitle(v); });
    }

    spdlog::info("Configuration loaded from '{}'", configPath.string());
    return {};

  } catch (const nlohmann::json::exception &e) {
    std::string msg = fmt::format("ConfigLoader: failed to parse '{}': {}",
                                  configPath.string(), e.what());
    spdlog::error(msg);
    return std::unexpected(std::move(msg));
  }
}

} // namespace nids::infra
