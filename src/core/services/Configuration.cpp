#include "core/services/Configuration.h"

#include <filesystem>

namespace fs = std::filesystem;

namespace nids::core {

Configuration::Configuration() = default;

Configuration &Configuration::instance() {
  static Configuration instance;
  return instance;
}

const fs::path& Configuration::modelPath() const noexcept { return modelPath_; }
const fs::path& Configuration::modelMetadataPath() const noexcept { return metadataPath_; }

void Configuration::setModelPath(const fs::path &path) { modelPath_ = path; }

void Configuration::setModelMetadataPath(const fs::path &path) {
  metadataPath_ = path;
}

const std::string &Configuration::defaultDumpFile() const noexcept {
  return defaultDumpFile_;
}
int64_t Configuration::flowTimeoutUs() const noexcept { return flowTimeoutUs_; }
int64_t Configuration::liveFlowTimeoutUs() const noexcept { return liveFlowTimeoutUs_; }
int64_t Configuration::maxFlowDurationUs() const noexcept { return maxFlowDurationUs_; }
int64_t Configuration::idleThresholdUs() const noexcept { return idleThresholdUs_; }

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

int Configuration::onnxIntraOpThreads() const noexcept { return onnxIntraOpThreads_; }

void Configuration::setOnnxIntraOpThreads(int threads) {
  onnxIntraOpThreads_ = threads;
}

const fs::path& Configuration::threatIntelDirectory() const noexcept { return threatIntelDir_; }

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

const std::string &Configuration::windowTitle() const noexcept { return windowTitle_; }

void Configuration::setWindowTitle(std::string_view title) {
  windowTitle_ = title;
}

const Configuration::SyslogOutputConfig&
Configuration::syslogOutputConfig() const noexcept {
  return syslogOutputConfig_;
}

const Configuration::JsonFileOutputConfig&
Configuration::jsonFileOutputConfig() const noexcept {
  return jsonFileOutputConfig_;
}

bool Configuration::consoleOutputEnabled() const noexcept {
  return consoleOutputEnabled_;
}

void Configuration::setSyslogOutputConfig(const SyslogOutputConfig& config) {
  syslogOutputConfig_ = config;
}

void Configuration::setJsonFileOutputConfig(const JsonFileOutputConfig& config) {
  jsonFileOutputConfig_ = config;
}

void Configuration::setConsoleOutputEnabled(bool enabled) {
  consoleOutputEnabled_ = enabled;
}

const Configuration::HuntingConfig&
Configuration::huntingConfig() const noexcept {
  return huntingConfig_;
}

void Configuration::setHuntingConfig(const HuntingConfig& config) {
  huntingConfig_ = config;
}

} // namespace nids::core
