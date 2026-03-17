#include "infra/output/JsonFileSink.h"

#include "core/model/AttackType.h"
#include "core/model/DetectionSource.h"
#include "core/model/ProtocolConstants.h"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fmt/format.h>
#include <iterator>
#include <ranges>

namespace nids::infra {

namespace fs = std::filesystem;

JsonFileSink::JsonFileSink(JsonFileConfig config)
    : config_(std::move(config)) {}

JsonFileSink::~JsonFileSink() {
  try {
    stop();
  } catch (const std::exception &e) {
    spdlog::error("JsonFileSink: exception in destructor: {}", e.what());
  }
}

bool JsonFileSink::start() {
  linesWritten_.store(0);
  writeErrors_.store(0);
  currentSize_ = 0;

  // Ensure parent directory exists.
  if (config_.outputPath.has_parent_path()) {
    std::error_code ec;
    fs::create_directories(config_.outputPath.parent_path(), ec);
    if (ec) {
      spdlog::error("JsonFileSink: cannot create directory '{}': {}",
                    config_.outputPath.parent_path().string(), ec.message());
      return false;
    }
  }

  auto mode = std::ios::out;
  if (config_.appendMode) {
    mode |= std::ios::app;
  } else {
    mode |= std::ios::trunc;
  }

  file_.open(config_.outputPath, mode);
  if (!file_.is_open()) {
    spdlog::error("JsonFileSink: cannot open '{}'",
                  config_.outputPath.string());
    return false;
  }

  // Track current file size for rotation.
  if (config_.appendMode) {
    std::error_code ec;
    auto size = fs::file_size(config_.outputPath, ec);
    if (!ec) {
      currentSize_ = size;
    }
  }

  spdlog::info("JsonFileSink started: {} (append={})",
               config_.outputPath.string(), config_.appendMode);
  return true;
}

void JsonFileSink::onFlowResult(std::size_t flowIndex,
                                const core::DetectionResult &result,
                                const core::FlowInfo &flow) {
  auto line = toJson(flowIndex, result, flow);
  line += '\n';

  std::scoped_lock lock{fileMutex_};

  rotateIfNeeded();

  if (!file_.is_open()) {
    writeErrors_.fetch_add(1);
    return;
  }

  file_ << line;
  if (file_.fail()) {
    writeErrors_.fetch_add(1);
    if (writeErrors_.load() % 100 == 1) {
      spdlog::warn("JsonFileSink: write failed (total errors: {})",
                   writeErrors_.load());
    }
  } else {
    file_.flush();
    currentSize_ += line.size();
    linesWritten_.fetch_add(1);
  }
}

void JsonFileSink::stop() {
  std::scoped_lock lock{fileMutex_};
  if (file_.is_open()) {
    file_.flush();
    file_.close();
    spdlog::info("JsonFileSink stopped: {} lines written, {} errors",
                 linesWritten_.load(), writeErrors_.load());
  }
}

std::string JsonFileSink::toJson(std::size_t flowIndex,
                                 const core::DetectionResult &result,
                                 const core::FlowInfo &flow) {

  using namespace std::chrono;
  const auto now = system_clock::now();
  const auto epoch = now.time_since_epoch();
  const auto millis = duration_cast<milliseconds>(epoch).count();

  // Build TI matches array
  nlohmann::json tiArray = nlohmann::json::array();
  std::ranges::transform(
      result.threatIntelMatches, std::back_inserter(tiArray),
      [](const auto &m) -> nlohmann::json {
        return {{"ip", m.ip},
                {"feed", m.feedName},
                {"direction", m.isSource ? "source" : "destination"}};
      });

  // Build rule matches array
  nlohmann::json ruleArray = nlohmann::json::array();
  std::ranges::transform(result.ruleMatches, std::back_inserter(ruleArray),
                         [](const auto &r) -> nlohmann::json {
                           return {{"name", r.ruleName},
                                   {"description", r.description},
                                   {"severity", r.severity}};
                         });

  // Build probabilities array
  nlohmann::json probArray(result.mlResult.probabilities);

  nlohmann::json j = {
      {"timestamp_ms", millis},
      {"flowIndex", flowIndex},
      {"flow",
       {{"srcIp", flow.srcIp},
        {"dstIp", flow.dstIp},
        {"srcPort", flow.srcPort},
        {"dstPort", flow.dstPort},
        {"protocol", flow.protocol},
        {"protocolName", std::string{core::protocolToName(flow.protocol)}},
        {"totalFwdPackets", flow.totalFwdPackets},
        {"totalBwdPackets", flow.totalBwdPackets},
        {"flowDurationUs", flow.flowDurationUs},
        {"avgPacketSize", flow.avgPacketSize}}},
      {"detection",
       {{"finalVerdict",
         std::string{core::attackTypeToString(result.finalVerdict)}},
        {"combinedScore", result.combinedScore},
        {"detectionSource",
         std::string{core::detectionSourceToString(result.detectionSource)}},
        {"isFlagged", result.isFlagged()},
        {"ml",
         {{"classification", std::string{core::attackTypeToString(
                                 result.mlResult.classification)}},
          {"confidence", result.mlResult.confidence},
          {"probabilities", probArray}}},
        {"threatIntel", tiArray},
        {"heuristicRules", ruleArray}}}};

  return j.dump();
}

void JsonFileSink::rotateIfNeeded() {
  // Caller must hold fileMutex_.
  if (currentSize_ < config_.maxFileSizeBytes)
    return;
  if (!file_.is_open())
    return;

  file_.close();

  // Rotate files: .4 → delete, .3 → .4, .2 → .3, .1 → .2, current → .1
  for (int i = config_.maxFiles - 1; i >= 1; --i) {
    auto src = config_.outputPath;
    src += fmt::format(".{}", i);

    auto dst = config_.outputPath;
    dst += fmt::format(".{}", i + 1);

    std::error_code ec;
    if (fs::exists(src, ec)) {
      if (i == config_.maxFiles - 1) {
        fs::remove(dst, ec);
      }
      fs::rename(src, dst, ec);
    }
  }

  // Move current file to .1
  {
    auto dst = config_.outputPath;
    dst += ".1";
    std::error_code ec;
    fs::rename(config_.outputPath, dst, ec);
  }

  // Open fresh file
  file_.open(config_.outputPath, std::ios::out | std::ios::trunc);
  currentSize_ = 0;

  if (!file_.is_open()) {
    spdlog::error("JsonFileSink: failed to reopen '{}' after rotation",
                  config_.outputPath.string());
  } else {
    spdlog::info("JsonFileSink: rotated log file");
  }
}

} // namespace nids::infra
