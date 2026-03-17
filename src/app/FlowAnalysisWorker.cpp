#include "app/FlowAnalysisWorker.h"
#include "app/HybridDetectionService.h"

#include <spdlog/spdlog.h>

#include <cassert>
#include <utility>

namespace nids::app {

FlowAnalysisWorker::FlowAnalysisWorker(core::BoundedQueue<FlowWorkItem> &queue,
                                       core::IPacketAnalyzer &analyzer,
                                       core::IFeatureNormalizer &normalizer,
                                       core::CaptureSession &session)
    : queue_(queue), analyzer_(analyzer), normalizer_(normalizer),
      session_(session) {}

FlowAnalysisWorker::~FlowAnalysisWorker() {
  try {
    stop();
  } catch (...) {
    spdlog::error("Exception in destructor");
  }
}

void FlowAnalysisWorker::setHybridDetection(
    HybridDetectionService *service) noexcept {
  assert(!running_.load() &&
         "setHybridDetection() must be called before start()");
  hybridService_ = service;
}

void FlowAnalysisWorker::setResultCallback(ResultCallback cb) noexcept {
  assert(!running_.load() &&
         "setResultCallback() must be called before start()");
  resultCallback_ = std::move(cb);
}

void FlowAnalysisWorker::start() {
  if (running_.load()) {
    return;
  }
  running_.store(true);
  processedCount_.store(0);
  batchCount_.store(0);
  callbacksFired_.store(0);
  thread_ = std::jthread([this](std::stop_token /*st*/) { run(); });
  spdlog::debug("FlowAnalysisWorker started");
}

void FlowAnalysisWorker::stop() {
  if (!running_.load()) {
    return;
  }
  // Close the queue so the consumer loop exits after draining.
  // This is idempotent — safe even if the producer already closed it.
  queue_.close();
  // jthread destructor requests stop and joins, but we want explicit control
  // over the running_ flag.
  if (thread_.joinable()) {
    thread_.join();
  }
  running_.store(false);
  spdlog::info("=== FlowAnalysisWorker Diagnostics ===");
  spdlog::info("  Flows processed:    {}", processedCount_.load());
  spdlog::info("  Batches processed:  {}", batchCount_.load());
  spdlog::info("  Callbacks fired:    {}", callbacksFired_.load());
  spdlog::info("======================================");
}

std::size_t FlowAnalysisWorker::processedCount() const noexcept {
  return processedCount_.load();
}

bool FlowAnalysisWorker::isRunning() const noexcept { return running_.load(); }

void FlowAnalysisWorker::run() {
  spdlog::debug(
      "FlowAnalysisWorker consumer loop started (batch size up to {})",
      kMaxBatchSize);

  while (true) {
    auto batch = queue_.popBatch(kMaxBatchSize);
    if (batch.empty()) {
      break; // Queue closed and drained.
    }

    batchCount_.fetch_add(1);
    auto startIndex = processedCount_.load();
    processBatch(batch, startIndex);
    processedCount_.fetch_add(batch.size());
  }

  spdlog::debug("FlowAnalysisWorker consumer loop exited (queue closed)");
}

void FlowAnalysisWorker::processBatch(std::vector<FlowWorkItem> &items,
                                      std::size_t startIndex) {
  const auto batchSize = items.size();

  // 1. Normalize and pack features for batched ONNX inference.
  auto [flatData, featureCount] = buildFlatBatch(items);

  // 2. Batched ML inference — single ONNX Runtime session.Run() call.
  auto mlResults = analyzer_.predictBatch(flatData, featureCount);

  // 3. For each flow: run hybrid detection (TI + rules), store result,
  //    fire callback.
  for (std::size_t i = 0; i < batchSize; ++i) {
    auto index = startIndex + i;
    core::DetectionResult result;

    if (i >= mlResults.size()) {
      mlResults.emplace_back();
    }
    const auto &mlResult = mlResults[i];

    if (hybridService_ != nullptr) [[likely]] {
      result =
          hybridService_->evaluate(mlResult, items[i].metadata.srcIp,
                                   items[i].metadata.dstIp, items[i].metadata);
    } else {
      result.mlResult = mlResult;
      result.finalVerdict = mlResult.classification;
      result.detectionSource = core::DetectionSource::MlOnly;
    }

    session_.setDetectionResult(index, result);

    if (resultCallback_) {
      callbacksFired_.fetch_add(1);
      resultCallback_(index, std::move(result), std::move(items[i].metadata));
    }
  }
}

FlowAnalysisWorker::FlatBatch FlowAnalysisWorker::buildFlatBatch(
    const std::vector<FlowWorkItem> &items) const {
  FlatBatch result;
  const auto batchSize = items.size();

  std::vector<std::vector<float>> normalizedVecs;
  normalizedVecs.reserve(batchSize);

  for (const auto &item : items) {
    normalizedVecs.push_back(normalizer_.normalize(item.features));
    if (result.featureCount == 0 && !normalizedVecs.back().empty()) {
      result.featureCount = normalizedVecs.back().size();
    }
  }

  // Flat buffer: [flow0_f0, flow0_f1, ..., flow1_f0, flow1_f1, ...]
  result.data.reserve(batchSize * result.featureCount);
  for (const auto &nv : normalizedVecs) {
    result.data.insert(result.data.end(), nv.begin(), nv.end());
  }

  return result;
}

} // namespace nids::app
