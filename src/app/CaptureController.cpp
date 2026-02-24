#include "app/CaptureController.h"

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
}

CaptureController::~CaptureController() {
    if (isCapturing()) {
        stopCapture();
    }
}

void CaptureController::startCapture(const nids::core::PacketFilter& filter,
                                      const std::string& dumpFile) {
    if (isCapturing()) return;

    session_.clear();
    std::string bpf = filter.generateBpfString();

    if (!capture_->initialize(filter.networkCard, bpf)) {
        return;
    }

    capture_->startCapture(dumpFile);
    emit captureStarted();
}

void CaptureController::stopCapture() {
    if (!isCapturing()) return;
    capture_->stopCapture();
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

} // namespace nids::app
