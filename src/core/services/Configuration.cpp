#include "core/services/Configuration.h"

#include <filesystem>

namespace fs = std::filesystem;

namespace nids::core {

Configuration::Configuration()
    : modelPath_("src/model/model.onnx")
    , metadataPath_("src/model/model_metadata.json")
    , defaultDumpFile_("dump.pcap")
    , flowTimeoutUs_(600'000'000)       // 10 minutes
    , idleThresholdUs_(5'000'000)       // 5 seconds
    , onnxIntraOpThreads_(1)
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
