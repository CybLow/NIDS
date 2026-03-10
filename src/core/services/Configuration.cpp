#include "core/services/Configuration.h"

#include <filesystem>

namespace fs = std::filesystem;

namespace nids::core {

Configuration::Configuration()
    : modelPath_("models/model.onnx")
    , metadataPath_("models/model_metadata.json")
    , threatIntelDir_("data/threat_intel")
    , defaultDumpFile_("dump.pcap")
    , flowTimeoutUs_(600'000'000)       // 10 minutes
    , idleThresholdUs_(5'000'000)       // 5 seconds
    , onnxIntraOpThreads_(1)
    , mlConfidenceThreshold_(0.7f)
    , weightMl_(0.5f)
    , weightThreatIntel_(0.3f)
    , weightHeuristic_(0.2f)
    , windowTitle_("NIDS - Network Intrusion Detection System") {}

Configuration& Configuration::instance() {
    static Configuration instance;
    return instance;
}

fs::path Configuration::modelPath() const { return modelPath_; }
fs::path Configuration::modelMetadataPath() const { return metadataPath_; }

void Configuration::setModelPath(const fs::path& path) {
    modelPath_ = path;
}

std::string Configuration::defaultDumpFile() const { return defaultDumpFile_; }
int64_t Configuration::flowTimeoutUs() const { return flowTimeoutUs_; }
int64_t Configuration::idleThresholdUs() const { return idleThresholdUs_; }

fs::path Configuration::tempDirectory() const {
    return fs::temp_directory_path();
}

int Configuration::onnxIntraOpThreads() const { return onnxIntraOpThreads_; }

fs::path Configuration::threatIntelDirectory() const { return threatIntelDir_; }

void Configuration::setThreatIntelDirectory(const fs::path& path) {
    threatIntelDir_ = path;
}

float Configuration::mlConfidenceThreshold() const noexcept { return mlConfidenceThreshold_; }
float Configuration::weightMl() const noexcept { return weightMl_; }
float Configuration::weightThreatIntel() const noexcept { return weightThreatIntel_; }
float Configuration::weightHeuristic() const noexcept { return weightHeuristic_; }

std::string Configuration::windowTitle() const { return windowTitle_; }

bool Configuration::loadFromFile(const fs::path& configPath) {
    // Optional JSON config loading. Returns true if file doesn't exist
    // (defaults are fine), false only on parse errors.
    if (!fs::exists(configPath)) {
        return true;
    }

    // TODO: Parse JSON config when nlohmann-json is available at runtime.
    // For now, defaults are sufficient.
    return true;
}

} // namespace nids::core
