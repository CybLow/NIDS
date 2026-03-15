#include "core/services/Configuration.h"

#include <filesystem>

namespace fs = std::filesystem;

namespace nids::core {

Configuration::Configuration() = default;

Configuration &Configuration::instance() {
  static Configuration instance;
  return instance;
}

fs::path Configuration::modelPath() const { return modelPath_; }
fs::path Configuration::modelMetadataPath() const { return metadataPath_; }

void Configuration::setModelPath(const fs::path &path) { modelPath_ = path; }

void Configuration::setModelMetadataPath(const fs::path &path) {
  metadataPath_ = path;
}

const std::string &Configuration::defaultDumpFile() const {
  return defaultDumpFile_;
}
int64_t Configuration::flowTimeoutUs() const { return flowTimeoutUs_; }
int64_t Configuration::liveFlowTimeoutUs() const { return liveFlowTimeoutUs_; }
int64_t Configuration::maxFlowDurationUs() const { return maxFlowDurationUs_; }
int64_t Configuration::idleThresholdUs() const { return idleThresholdUs_; }

void Configuration::setDefaultDumpFile(std::string_view file) {
  defaultDumpFile_ = file;
}

void Configuration::setFlowTimeoutUs(int64_t timeoutUs) {
  flowTimeoutUs_ = timeoutUs;
}

void Configuration::setLiveFlowTimeoutUs(int64_t timeoutUs) {
  liveFlowTimeoutUs_ = timeoutUs;
}

void Configuration::setMaxFlowDurationUs(int64_t durationUs) {
  maxFlowDurationUs_ = durationUs;
}

void Configuration::setIdleThresholdUs(int64_t thresholdUs) {
  idleThresholdUs_ = thresholdUs;
}

fs::path Configuration::tempDirectory() { return fs::temp_directory_path(); }

int Configuration::onnxIntraOpThreads() const { return onnxIntraOpThreads_; }

void Configuration::setOnnxIntraOpThreads(int threads) {
  onnxIntraOpThreads_ = threads;
}

fs::path Configuration::threatIntelDirectory() const { return threatIntelDir_; }

void Configuration::setThreatIntelDirectory(const fs::path &path) {
  threatIntelDir_ = path;
}

float Configuration::mlConfidenceThreshold() const noexcept {
  return mlConfidenceThreshold_;
}
float Configuration::weightMl() const noexcept { return weightMl_; }
float Configuration::weightThreatIntel() const noexcept {
  return weightThreatIntel_;
}
float Configuration::weightHeuristic() const noexcept {
  return weightHeuristic_;
}

void Configuration::setMlConfidenceThreshold(float threshold) {
  mlConfidenceThreshold_ = threshold;
}

void Configuration::setWeightMl(float weight) { weightMl_ = weight; }

void Configuration::setWeightThreatIntel(float weight) {
  weightThreatIntel_ = weight;
}

void Configuration::setWeightHeuristic(float weight) {
  weightHeuristic_ = weight;
}

const std::string &Configuration::windowTitle() const { return windowTitle_; }

void Configuration::setWindowTitle(std::string_view title) {
  windowTitle_ = title;
}

} // namespace nids::core
