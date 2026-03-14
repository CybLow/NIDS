#include "app/FlowAnalysisWorker.h"
#include "app/HybridDetectionService.h"
#include "core/services/IRuleEngine.h"

#include <spdlog/spdlog.h>

#include <utility>

namespace nids::app {

namespace {

/// Convert a FlowInfo (from the extractor) to a FlowMetadata (for heuristic rules).
nids::core::FlowMetadata toFlowMetadata(const nids::core::FlowInfo& info) {
    nids::core::FlowMetadata meta;
    meta.srcIp = info.srcIp;
    meta.dstIp = info.dstIp;
    meta.srcPort = info.srcPort;
    meta.dstPort = info.dstPort;

    switch (info.protocol) {
        case 6:
            meta.protocol = "TCP";
            break;
        case 17:
            meta.protocol = "UDP";
            break;
        case 1:
            meta.protocol = "ICMP";
            break;
        default:
            meta.protocol = "OTHER";
            break;
    }

    meta.totalFwdPackets = info.totalFwdPackets;
    meta.totalBwdPackets = info.totalBwdPackets;
    meta.flowDurationUs = info.flowDurationUs;
    meta.fwdPacketsPerSecond = info.fwdPacketsPerSecond;
    meta.bwdPacketsPerSecond = info.bwdPacketsPerSecond;
    meta.synFlagCount = info.synFlagCount;
    meta.ackFlagCount = info.ackFlagCount;
    meta.rstFlagCount = info.rstFlagCount;
    meta.finFlagCount = info.finFlagCount;
    meta.avgPacketSize = info.avgPacketSize;

    return meta;
}

} // anonymous namespace

FlowAnalysisWorker::FlowAnalysisWorker(
    nids::core::BoundedQueue<FlowWorkItem>& queue,
    nids::core::IPacketAnalyzer& analyzer,
    nids::core::IFeatureNormalizer& normalizer,
    nids::core::CaptureSession& session)
    : queue_(queue)
    , analyzer_(analyzer)
    , normalizer_(normalizer)
    , session_(session) {}

FlowAnalysisWorker::~FlowAnalysisWorker() {
    stop();
}

void FlowAnalysisWorker::setHybridDetection(
    HybridDetectionService* service) noexcept {
    hybridService_ = service;
}

void FlowAnalysisWorker::setResultCallback(ResultCallback cb) noexcept {
    resultCallback_ = std::move(cb);
}

void FlowAnalysisWorker::start() {
    if (running_.load(std::memory_order_relaxed)) {
        return;
    }
    running_.store(true, std::memory_order_relaxed);
    processedCount_.store(0, std::memory_order_relaxed);
    thread_ = std::jthread([this](std::stop_token /*st*/) { run(); });
    spdlog::debug("FlowAnalysisWorker started");
}

void FlowAnalysisWorker::stop() {
    if (!running_.load(std::memory_order_relaxed)) {
        return;
    }
    // Close the queue so the consumer loop exits after draining.
    queue_.close();
    // jthread destructor requests stop and joins, but we want explicit control
    // over the running_ flag.
    if (thread_.joinable()) {
        thread_.join();
    }
    running_.store(false, std::memory_order_relaxed);
    spdlog::debug("FlowAnalysisWorker stopped after processing {} flows",
                  processedCount_.load(std::memory_order_relaxed));
}

std::size_t FlowAnalysisWorker::processedCount() const noexcept {
    return processedCount_.load(std::memory_order_relaxed);
}

bool FlowAnalysisWorker::isRunning() const noexcept {
    return running_.load(std::memory_order_relaxed);
}

void FlowAnalysisWorker::run() {
    spdlog::debug("FlowAnalysisWorker consumer loop started");

    while (auto item = queue_.pop()) {
        auto index = processedCount_.load(std::memory_order_relaxed);
        processItem(std::move(*item), index);
        processedCount_.fetch_add(1, std::memory_order_relaxed);
    }

    spdlog::debug("FlowAnalysisWorker consumer loop exited (queue closed)");
}

void FlowAnalysisWorker::processItem(FlowWorkItem&& item, std::size_t index) {
    auto normalized = normalizer_.normalize(item.features);

    nids::core::DetectionResult result;

    if (hybridService_ != nullptr) [[likely]] {
        auto mlResult = analyzer_.predictWithConfidence(normalized);
        auto flowMeta = toFlowMetadata(item.metadata);
        result = hybridService_->evaluate(
            mlResult, item.metadata.srcIp, item.metadata.dstIp, flowMeta);
    } else {
        auto attackType = analyzer_.predict(normalized);
        result.finalVerdict = attackType;
        result.detectionSource = nids::core::DetectionSource::MlOnly;
    }

    session_.setDetectionResult(index, result);

    if (resultCallback_) {
        resultCallback_(index, std::move(result), std::move(item.metadata));
    }
}

} // namespace nids::app
