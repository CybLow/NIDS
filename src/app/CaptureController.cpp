#include "app/CaptureController.h"
#include "app/LiveDetectionPipeline.h"
#include "core/services/Configuration.h"

#include <spdlog/spdlog.h>

#include <QMetaObject>
#include <QString>

namespace nids::app {

CaptureController::CaptureController(
    std::unique_ptr<nids::core::IPacketCapture> capture,
    QObject* parent)
    : QObject(parent)
    , capture_(std::move(capture)) {

    capture_->setPacketCallback([this](const nids::core::PacketInfo& info) {
        session_.addPacket(info);
        emit packetReceived(info);
    });

    capture_->setErrorCallback([this](const std::string& message) {
        emit captureError(QString::fromStdString(message));
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
        // cppcheck-suppress shadowFunction  // Qt signal emission, not a shadowing variable
        emit captureError(
            QString::fromStdString("Failed to initialize capture on interface: " + filter.networkCard));
        return;
    }

    // Start live detection if a pipeline is configured.
    if (pipeline_) {
        pipeline_->setResultCallback(
            [this](std::size_t /*idx*/, nids::core::DetectionResult result,
                   nids::core::FlowInfo metadata) {
                // Bridge from the worker thread to the main thread.
                QMetaObject::invokeMethod(
                    this,
                    [this, r = std::move(result), m = std::move(metadata)]() {
                        emit liveFlowDetected(r, m);
                    },
                    Qt::QueuedConnection);
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
    emit captureStarted();
}

void CaptureController::stopCapture() {
    if (!isCapturing())
        return;
    capture_->stopCapture();

    // Stop live detection: finalize flows and drain the pipeline.
    if (pipeline_ && pipeline_->isRunning()) {
        capture_->setRawPacketCallback(nullptr);
        pipeline_->stop();
        spdlog::info("Live detection stopped: {} flows detected",
                     pipeline_->flowsDetected());
    }

    emit captureStopped();
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
