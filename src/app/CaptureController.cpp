#include "app/CaptureController.h"
#include "app/LiveDetectionPipeline.h"
#include "core/services/Configuration.h"

#include <spdlog/spdlog.h>

namespace nids::app {

CaptureController::CaptureController(
    std::unique_ptr<nids::core::IPacketCapture> capture)
    : capture_(std::move(capture)) {

    capture_->setPacketCallback([this](const nids::core::PacketInfo& info) {
        session_.addPacket(info);
        if (onPacketReceived_) onPacketReceived_(info);
    });

    capture_->setErrorCallback([this](const std::string& message) {
        if (onCaptureError_) onCaptureError_(message);
    });
}

CaptureController::~CaptureController() {
    if (isCapturing()) {
        stopCapture();
    }
}

void CaptureController::enableLiveDetection(
    LiveDetectionPipeline* pipeline) noexcept {
    pipeline_ = pipeline;
}

void CaptureController::disableLiveDetection() noexcept {
    if (pipeline_ && pipeline_->isRunning()) {
        pipeline_->stop();
        capture_->setRawPacketCallback(nullptr);
    }
    pipeline_ = nullptr;
}

void CaptureController::startCapture(const nids::core::PacketFilter& filter,
                                       const std::string& dumpFile) {
    if (isCapturing())
        return;

    session_.clear();

    if (std::string bpf = filter.generateBpfString(); !capture_->initialize(filter.networkCard, bpf)) {
        spdlog::error("Failed to initialize capture on interface '{}'", filter.networkCard);
        if (onCaptureError_)
            onCaptureError_("Failed to initialize capture on interface: " + filter.networkCard);
        return;
    }

    // Start live detection if a pipeline is configured.
    if (pipeline_) {
        pipeline_->setResultCallback(
            [this](std::size_t /*idx*/, nids::core::DetectionResult result,
                   nids::core::FlowInfo metadata) {
                // Fire callback directly — consumer is responsible for
                // thread marshaling if needed.
                if (onLiveFlow_) onLiveFlow_(std::move(result), std::move(metadata));
            });
        pipeline_->start();

        // Register raw packet callback to feed the flow extractor.
        capture_->setRawPacketCallback(
            [this](const std::uint8_t* data, std::size_t length,
                   std::int64_t timestampUs) {
                pipeline_->feedPacket(data, length, timestampUs);
            });

        spdlog::info("Live detection enabled for capture");
    }

    const auto& actualDumpFile = dumpFile.empty()
        ? nids::core::Configuration::instance().defaultDumpFile()
        : dumpFile;

    capture_->startCapture(actualDumpFile);
    if (onCaptureStarted_) onCaptureStarted_();
}

void CaptureController::stopCapture() {
    if (!isCapturing())
        return;
    capture_->stopCapture();

    // Stop live detection: finalize flows and drain the pipeline.
    if (pipeline_ && pipeline_->isRunning()) {
        capture_->setRawPacketCallback(nullptr);
        // Read flow count before stop() resets the worker (which zeroes the count).
        auto preStopFlows = pipeline_->flowsDetected();
        pipeline_->stop();
        spdlog::info("Live detection stopped: {} flows detected during capture, "
                     "see pipeline diagnostics above for full breakdown",
                     preStopFlows);
    }

    if (onCaptureStopped_) onCaptureStopped_();
}

bool CaptureController::isCapturing() const {
    return capture_->isCapturing();
}

nids::core::CaptureSession& CaptureController::session() {
    return session_;
}

const nids::core::CaptureSession& CaptureController::session() const {
    return session_;
}

std::vector<std::string> CaptureController::listInterfaces() {
    return capture_->listInterfaces();
}

bool CaptureController::isLiveDetectionActive() const noexcept {
    return pipeline_ != nullptr && pipeline_->isRunning();
}

} // namespace nids::app
