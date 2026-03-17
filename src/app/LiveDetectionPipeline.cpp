#include "app/LiveDetectionPipeline.h"

#include <spdlog/spdlog.h>

#include <cassert>
#include <utility>

namespace nids::app {

LiveDetectionPipeline::LiveDetectionPipeline(
    core::IFlowExtractor &extractor, core::IPacketAnalyzer &analyzer,
    core::IFeatureNormalizer &normalizer, core::CaptureSession &session)
    : extractor_(extractor), analyzer_(analyzer), normalizer_(normalizer),
      session_(session) {}

LiveDetectionPipeline::~LiveDetectionPipeline() {
  try {
    stop();
  } catch (...) {
    // Destructors must not throw.
  }
}

void LiveDetectionPipeline::setHybridDetection(
    HybridDetectionService *service) noexcept {
  assert(!running_.load() &&
         "setHybridDetection() must be called before start()");
  hybridService_ = service;
}

void LiveDetectionPipeline::setResultCallback(ResultCallback cb) noexcept {
  assert(!running_.load() &&
         "setResultCallback() must be called before start()");
  resultCallback_ = std::move(cb);
}

void LiveDetectionPipeline::addOutputSink(core::IOutputSink *sink) {
  assert(!running_.load() && "addOutputSink() must be called before start()");
  if (sink) {
    sinks_.push_back(sink);
  }
}

void LiveDetectionPipeline::start() {
  if (running_.load()) {
    return;
  }

  spdlog::info("LiveDetectionPipeline starting");

  // Reset flow extractor state for the new capture session.
  extractor_.reset();
  droppedFlows_.store(0);
  feedPacketCount_.store(0);
  queuePushCount_.store(0);

  // Create the bounded queue and worker.
  queue_ = std::make_unique<core::BoundedQueue<FlowWorkItem>>(kQueueCapacity);
  worker_ = std::make_unique<FlowAnalysisWorker>(*queue_, analyzer_,
                                                 normalizer_, session_);
  worker_->setHybridDetection(hybridService_);

  // Start all output sinks.
  for (auto *sink : sinks_) {
    if (!sink->start()) {
      spdlog::warn("Output sink '{}' failed to start", sink->name());
    }
  }

  configureResultCallback();

  worker_->start();

  // Register flow completion callback: push completed flows into the queue.
  // tryPush() is non-blocking — if the queue is full, the flow is dropped
  // rather than stalling the PcapPlusPlus capture thread.
  extractor_.setFlowCompletionCallback([this](std::vector<float> &&features,
                                              core::FlowInfo &&info) {
    if (queue_->tryPush(FlowWorkItem{std::move(features), std::move(info)})) {
      queuePushCount_.fetch_add(1);
    } else {
      droppedFlows_.fetch_add(1);
    }
  });

  running_.store(true);
  spdlog::info("LiveDetectionPipeline running (queue capacity: {})",
               kQueueCapacity);
}

void LiveDetectionPipeline::feedPacket(const std::uint8_t *data,
                                       std::size_t length,
                                       std::int64_t timestampUs) {
  feedPacketCount_.fetch_add(1);
  extractor_.processPacket(data, length, timestampUs);
}

void LiveDetectionPipeline::stop() {
  if (!running_.load()) {
    return;
  }

  spdlog::info("LiveDetectionPipeline stopping — finalizing active flows");

  // Finalize all remaining active flows.  This fires the flow completion
  // callback for each flow still in the flow table, pushing them into
  // the queue.
  extractor_.finalizeAllFlows();
  extractor_.setFlowCompletionCallback(nullptr);

  // Signal end-of-stream and wait for the worker to drain.
  if (queue_) {
    queue_->close();
  }
  if (worker_) {
    worker_->stop();
  }

  logDiagnostics();

  // Stop all output sinks (flush buffers, print summaries).
  for (auto *sink : sinks_) {
    sink->stop();
  }

  worker_.reset();
  queue_.reset();
  running_.store(false);
}

std::size_t LiveDetectionPipeline::flowsDetected() const noexcept {
  return worker_ ? worker_->processedCount() : 0;
}

bool LiveDetectionPipeline::isRunning() const noexcept {
  return running_.load();
}

std::size_t LiveDetectionPipeline::droppedFlows() const noexcept {
  return droppedFlows_.load();
}

void LiveDetectionPipeline::configureResultCallback() {
  // If output sinks are registered, wrap the result callback to also
  // dispatch to all sinks.
  if (!sinks_.empty()) {
    auto userCallback = resultCallback_;
    worker_->setResultCallback([this, userCallback = std::move(userCallback)](
                                   std::size_t idx,
                                   core::DetectionResult result,
                                   core::FlowInfo info) {
      // Dispatch to all registered output sinks.
      for (auto *sink : sinks_) {
        sink->onFlowResult(idx, result, info);
      }
      // Then fire the user callback (if any).
      if (userCallback) {
        userCallback(idx, std::move(result), std::move(info));
      }
    });
  } else if (resultCallback_) {
    worker_->setResultCallback(resultCallback_);
  }
}

void LiveDetectionPipeline::logDiagnostics() const {
  auto detected = flowsDetected();
  auto dropped = droppedFlows_.load();
  auto fed = feedPacketCount_.load();
  auto pushed = queuePushCount_.load();
  spdlog::info("=== LiveDetectionPipeline Diagnostics ===");
  spdlog::info("  feedPacket() calls:   {}", fed);
  spdlog::info("  Queue pushes (ok):    {}", pushed);
  spdlog::info("  Queue drops (full):   {}", dropped);
  spdlog::info("  Flows detected:       {}", detected);
  spdlog::info("=========================================");

  if (dropped > 0) {
    spdlog::warn("LiveDetectionPipeline dropped {} flows due to queue "
                 "backpressure — consider increasing queue capacity or "
                 "reducing capture throughput",
                 dropped);
  }
}

} // namespace nids::app
