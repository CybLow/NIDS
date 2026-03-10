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

void Configuration::setModelMetadataPath(const fs::path& path) {
    metadataPath_ = path;
}

std::string Configuration::defaultDumpFile() const { return defaultDumpFile_; }
int64_t Configuration::flowTimeoutUs() const { return flowTimeoutUs_; }
int64_t Configuration::idleThresholdUs() const { return idleThresholdUs_; }

void Configuration::setDefaultDumpFile(const std::string& file) {
    defaultDumpFile_ = file;
}

void Configuration::setFlowTimeoutUs(int64_t timeoutUs) {
    flowTimeoutUs_ = timeoutUs;
}

void Configuration::setIdleThresholdUs(int64_t thresholdUs) {
    idleThresholdUs_ = thresholdUs;
}

fs::path Configuration::tempDirectory() const {
    return fs::temp_directory_path();
}

int Configuration::onnxIntraOpThreads() const { return onnxIntraOpThreads_; }

void Configuration::setOnnxIntraOpThreads(int threads) {
    onnxIntraOpThreads_ = threads;
}

fs::path Configuration::threatIntelDirectory() const { return threatIntelDir_; }

void Configuration::setThreatIntelDirectory(const fs::path& path) {
    threatIntelDir_ = path;
}

float Configuration::mlConfidenceThreshold() const noexcept { return mlConfidenceThreshold_; }
float Configuration::weightMl() const noexcept { return weightMl_; }
float Configuration::weightThreatIntel() const noexcept { return weightThreatIntel_; }
float Configuration::weightHeuristic() const noexcept { return weightHeuristic_; }

void Configuration::setMlConfidenceThreshold(float threshold) {
    mlConfidenceThreshold_ = threshold;
}

void Configuration::setWeightMl(float weight) {
    weightMl_ = weight;
}

void Configuration::setWeightThreatIntel(float weight) {
    weightThreatIntel_ = weight;
}

void Configuration::setWeightHeuristic(float weight) {
    weightHeuristic_ = weight;
}

std::string Configuration::windowTitle() const { return windowTitle_; }

void Configuration::setWindowTitle(const std::string& title) {
    windowTitle_ = title;
}

} // namespace nids::core
