#include "app/LiveDetectionPipeline.h"

#include <spdlog/spdlog.h>

#include <utility>

namespace nids::app {

LiveDetectionPipeline::LiveDetectionPipeline(
    nids::core::IFlowExtractor& extractor,
    nids::core::IPacketAnalyzer& analyzer,
    nids::core::IFeatureNormalizer& normalizer,
    nids::core::CaptureSession& session)
    : extractor_(extractor)
    , analyzer_(analyzer)
    , normalizer_(normalizer)
    , session_(session) {}

LiveDetectionPipeline::~LiveDetectionPipeline() {
    stop();
}

void LiveDetectionPipeline::setHybridDetection(
    HybridDetectionService* service) noexcept {
    hybridService_ = service;
}

void LiveDetectionPipeline::setResultCallback(ResultCallback cb) noexcept {
    resultCallback_ = std::move(cb);
}

void LiveDetectionPipeline::start() {
    if (running_.load(std::memory_order_relaxed)) {
        return;
    }

    spdlog::info("LiveDetectionPipeline starting");

    // Reset flow extractor state for the new capture session.
    extractor_.reset();
    droppedFlows_.store(0, std::memory_order_relaxed);

    // Create the bounded queue and worker.
    queue_ = std::make_unique<nids::core::BoundedQueue<FlowWorkItem>>(kQueueCapacity);
    worker_ = std::make_unique<FlowAnalysisWorker>(
        *queue_, analyzer_, normalizer_, session_);
    worker_->setHybridDetection(hybridService_);

    if (resultCallback_) {
        worker_->setResultCallback(resultCallback_);
    }

    worker_->start();

    // Register flow completion callback: push completed flows into the queue.
    // tryPush() is non-blocking — if the queue is full, the flow is dropped
    // rather than stalling the PcapPlusPlus capture thread.
    extractor_.setFlowCompletionCallback(
        [this](std::vector<float>&& features, nids::core::FlowInfo&& info) {
            if (!queue_->tryPush(
                    FlowWorkItem{std::move(features), std::move(info)})) {
                droppedFlows_.fetch_add(1, std::memory_order_relaxed);
            }
        });

    running_.store(true, std::memory_order_relaxed);
    spdlog::info("LiveDetectionPipeline running (queue capacity: {})",
                 kQueueCapacity);
}

void LiveDetectionPipeline::feedPacket(const std::uint8_t* data,
                                       std::size_t length,
                                       std::int64_t timestampUs) {
    extractor_.processPacket(data, length, timestampUs);
}

void LiveDetectionPipeline::stop() {
    if (!running_.load(std::memory_order_relaxed)) {
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

    auto detected = flowsDetected();
    auto dropped = droppedFlows_.load(std::memory_order_relaxed);
    spdlog::info("LiveDetectionPipeline stopped: {} flows detected, {} dropped",
                 detected, dropped);

    if (dropped > 0) {
        spdlog::warn("LiveDetectionPipeline dropped {} flows due to queue "
                     "backpressure — consider increasing queue capacity or "
                     "reducing capture throughput",
                     dropped);
    }

    worker_.reset();
    queue_.reset();
    running_.store(false, std::memory_order_relaxed);
}

std::size_t LiveDetectionPipeline::flowsDetected() const noexcept {
    return worker_ ? worker_->processedCount() : 0;
}

bool LiveDetectionPipeline::isRunning() const noexcept {
    return running_.load(std::memory_order_relaxed);
}

std::size_t LiveDetectionPipeline::droppedFlows() const noexcept {
    return droppedFlows_.load(std::memory_order_relaxed);
}

} // namespace nids::app
