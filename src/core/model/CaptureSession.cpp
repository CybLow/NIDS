#include "core/model/CaptureSession.h"
#include <stdexcept>

namespace nids::core {

void CaptureSession::addPacket(const PacketInfo& packet) {
    std::scoped_lock lock(mutex_);
    packets_.push_back(packet);
}

void CaptureSession::setDetectionResult(std::size_t index, const DetectionResult& result) {
    std::scoped_lock lock(mutex_);
    if (index >= detectionResults_.size()) {
        detectionResults_.resize(index + 1);
    }
    detectionResults_[index] = result;
}

const PacketInfo& CaptureSession::getPacket(std::size_t index) const {
    std::scoped_lock lock(mutex_);
    if (index >= packets_.size()) {
        throw std::out_of_range("Packet index out of range");
    }
    return packets_[index];
}

DetectionResult CaptureSession::getDetectionResult(std::size_t index) const {
    std::scoped_lock lock(mutex_);
    if (index >= detectionResults_.size()) {
        return {};  // Default-constructed: Unknown verdict, zero scores
    }
    return detectionResults_[index];
}

std::size_t CaptureSession::packetCount() const {
    std::scoped_lock lock(mutex_);
    return packets_.size();
}

std::size_t CaptureSession::analysisResultCount() const {
    std::scoped_lock lock(mutex_);
    return detectionResults_.size();
}

void CaptureSession::clear() {
    std::scoped_lock lock(mutex_);
    packets_.clear();
    detectionResults_.clear();
}

} // namespace nids::core
