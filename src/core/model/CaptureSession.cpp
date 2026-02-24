#include "core/model/CaptureSession.h"
#include <stdexcept>

namespace nids::core {

void CaptureSession::addPacket(const PacketInfo& packet) {
    std::lock_guard<std::mutex> lock(mutex_);
    packets_.push_back(packet);
}

void CaptureSession::setAnalysisResult(std::size_t index, AttackType type) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= analysisResults_.size()) {
        analysisResults_.resize(index + 1, AttackType::Unknown);
    }
    analysisResults_[index] = type;
}

const PacketInfo& CaptureSession::getPacket(std::size_t index) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= packets_.size()) {
        throw std::out_of_range("Packet index out of range");
    }
    return packets_[index];
}

AttackType CaptureSession::getAnalysisResult(std::size_t index) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= analysisResults_.size()) {
        return AttackType::Unknown;
    }
    return analysisResults_[index];
}

std::size_t CaptureSession::packetCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return packets_.size();
}

std::size_t CaptureSession::analysisResultCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return analysisResults_.size();
}

void CaptureSession::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    packets_.clear();
    analysisResults_.clear();
}

} // namespace nids::core
