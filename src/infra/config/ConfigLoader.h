#pragma once

/// Loads application configuration from a JSON file and applies overrides
/// to the Configuration singleton. Lives in infra/ because it depends on
/// nlohmann_json (third-party library), keeping core/ free of external deps.
///
/// JSON schema (all keys optional — missing keys keep defaults):
/// {
///   "model": {
///     "path": "models/model.onnx",
///     "metadata_path": "models/model_metadata.json",
///     "onnx_intra_op_threads": 1
///   },
///   "capture": {
///     "dump_file": "dump.pcap",
///     "flow_timeout_us": 600000000,
///     "idle_threshold_us": 5000000
///   },
///   "threat_intel": {
///     "directory": "data/threat_intel"
///   },
///   "hybrid_detection": {
///     "ml_confidence_threshold": 0.7,
///     "weight_ml": 0.5,
///     "weight_threat_intel": 0.3,
///     "weight_heuristic": 0.2
///   },
///   "ui": {
///     "window_title": "NIDS - Network Intrusion Detection System"
///   }
/// }

#include <filesystem>
#include <string>

namespace nids::core {
class Configuration;
}

namespace nids::infra {

/// Load configuration overrides from a JSON file.
///
/// @param configPath  Path to the JSON config file. If the file does not
///                    exist, this is a no-op and returns true (defaults are
///                    kept). Returns false only on parse errors.
/// @param config      The Configuration instance to apply overrides to.
/// @return true on success (or file not found), false on parse error.
[[nodiscard]] bool loadConfigFromFile(
    const std::filesystem::path& configPath,
    nids::core::Configuration& config);

} // namespace nids::infra
