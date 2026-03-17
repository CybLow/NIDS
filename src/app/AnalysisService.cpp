#include "app/AnalysisService.h"
#include "app/FlowAnalysisWorker.h"
#include "app/HybridDetectionService.h"
#include "core/concurrent/BoundedQueue.h"
#include "core/services/Configuration.h"

#include <spdlog/spdlog.h>

namespace nids::app {

namespace {

/// Queue capacity for the producer-consumer pipeline.
/// Sized to absorb extraction bursts while bounding memory usage.
/// 256 items * ~400 bytes/item ≈ 100 KB.
constexpr std::size_t kFlowQueueCapacity = 256;

} // anonymous namespace

AnalysisService::AnalysisService(
    std::unique_ptr<core::IPacketAnalyzer> analyzer,
    std::unique_ptr<core::IFlowExtractor> extractor,
    std::unique_ptr<core::IFeatureNormalizer> normalizer)
    : analyzer_(std::move(analyzer)), extractor_(std::move(extractor)),
      normalizer_(std::move(normalizer)) {}

std::expected<void, std::string>
AnalysisService::loadModel(const std::string &modelPath) {
  return analyzer_->loadModel(modelPath);
}

std::expected<void, std::string>
AnalysisService::loadNormalization(const std::string &metadataPath) {
  return normalizer_->loadMetadata(metadataPath);
}

void AnalysisService::setHybridDetection(
    HybridDetectionService *service) noexcept {
  hybridService_ = service;
}

void AnalysisService::analyzeCapture(const std::string &pcapPath,
                                     core::CaptureSession &session) {
  if (onStarted_)
    onStarted_();

  spdlog::info(
      "Extracting and analyzing flow features from '{}' (pipelined mode)",
      pcapPath);
  spdlog::info("Hybrid detection: {}",
               hybridService_ != nullptr ? "enabled" : "disabled");

  // ── Producer-consumer pipeline ──────────────────────────────────
  // Extractor thread (this thread) → BoundedQueue → FlowAnalysisWorker
  // (std::jthread).  Extraction and ML inference run concurrently:
  // the extractor is not blocked by inference, and the queue provides
  // backpressure when the worker falls behind.

  core::BoundedQueue<FlowWorkItem> queue(kFlowQueueCapacity);

  FlowAnalysisWorker worker(queue, *analyzer_, *normalizer_, session);
  worker.setHybridDetection(hybridService_);
  worker.setResultCallback([this](std::size_t index,
                                  core::DetectionResult /*result*/,
                                  core::FlowInfo /*metadata*/) {
    if (onProgress_)
      onProgress_(static_cast<int>(index + 1), 0);
  });
  worker.start();

  // Producer callback: each completed flow is pushed into the queue.
  extractor_->setFlowCompletionCallback(
      [&queue](std::vector<float> &&features, core::FlowInfo &&info) {
        std::ignore =
            queue.push(FlowWorkItem{std::move(features), std::move(info)});
      });

  // extractFeatures() runs synchronously on this thread, firing the
  // callback for each completed flow.  The returned vectors serve as
  // a fallback for extractors that don't invoke the callback (mocks).
  auto allFeatures = extractor_->extractFeatures(pcapPath);

  // If the streaming callback was not invoked (e.g. mock extractors),
  // push the batch results through the same worker pipeline.
  // This eliminates duplicated normalize→predict→evaluate→store logic.
  pushBatchFallback(worker, queue, allFeatures);

  // Signal end-of-stream and wait for the worker to drain the queue.
  queue.close();
  extractor_->setFlowCompletionCallback(nullptr);
  worker.stop();

  reportResults(pcapPath, worker.processedCount(), allFeatures.empty());
}

const std::vector<core::FlowInfo> &
AnalysisService::lastFlowMetadata() const noexcept {
  return extractor_->flowMetadata();
}

void AnalysisService::pushBatchFallback(
    const FlowAnalysisWorker &worker, core::BoundedQueue<FlowWorkItem> &queue,
    std::vector<std::vector<float>> &allFeatures) {

  auto streamedBeforeClose = worker.processedCount();
  if (streamedBeforeClose == 0 && !allFeatures.empty()) {
    spdlog::debug("Streaming callback was not invoked — feeding batch "
                  "results through pipeline");
    const auto &metadata = extractor_->flowMetadata();
    for (std::size_t i = 0; i < allFeatures.size(); ++i) {
      core::FlowInfo info;
      if (i < metadata.size()) {
        info = metadata[i];
      }
      std::ignore =
          queue.push(FlowWorkItem{std::move(allFeatures[i]), std::move(info)});
    }
  }
}

void AnalysisService::reportResults(const std::string &pcapPath,
                                    std::size_t processedCount,
                                    bool noFeatures) {
  if (noFeatures && processedCount == 0) {
    spdlog::warn("No flows extracted from '{}' (empty capture or "
                 "extraction failure)",
                 pcapPath);
  }

  auto total = static_cast<int>(processedCount);
  if (total > 0) {
    if (onProgress_)
      onProgress_(total, total);
  }

  spdlog::info("Analysis complete: {} flows processed", total);
  if (onFinished_)
    onFinished_();
}

} // namespace nids::app
