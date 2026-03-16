#include "core/model/CaptureSession.h"

#include <mutex>
#include <stdexcept>

namespace nids::core {

namespace {

/// Default in-memory analysis repository used when no external one is injected.
/// Thread-safe via its own mutex.
class DefaultAnalysisRepository : public IAnalysisRepository {
public:
    void store(std::size_t flowIndex, const DetectionResult& result) override {
        std::scoped_lock lock(mutex_);
        if (flowIndex >= results_.size()) {
            results_.resize(flowIndex + 1);
        }
        results_[flowIndex] = result;
    }

    [[nodiscard]] DetectionResult get(std::size_t flowIndex) const override {
        std::scoped_lock lock(mutex_);
        if (flowIndex >= results_.size()) {
            return {};
        }
        return results_[flowIndex];
    }

    [[nodiscard]] std::size_t size() const noexcept override {
        std::scoped_lock lock(mutex_);
        return results_.size();
    }

    void clear() override {
        std::scoped_lock lock(mutex_);
        results_.clear();
    }

private:
    mutable std::mutex mutex_;
    std::vector<DetectionResult> results_;
};

} // anonymous namespace

CaptureSession::CaptureSession()
    : ownedRepository_(std::make_unique<DefaultAnalysisRepository>()),
      repository_(ownedRepository_.get()) {}

CaptureSession::CaptureSession(IAnalysisRepository& repository)
    : repository_(&repository) {}

void CaptureSession::addPacket(const PacketInfo& packet) {
    std::scoped_lock lock(packetsMutex_);
    packets_.push_back(packet);
}

void CaptureSession::setDetectionResult(std::size_t index, const DetectionResult& result) {
    repository_->store(index, result);
}

PacketInfo CaptureSession::getPacket(std::size_t index) const {
    std::scoped_lock lock(packetsMutex_);
    if (index >= packets_.size()) {
        throw std::out_of_range("Packet index out of range");
    }
    return packets_[index]; // Return by value — safe across threads.
}

DetectionResult CaptureSession::getDetectionResult(std::size_t index) const {
    return repository_->get(index);
}

std::size_t CaptureSession::packetCount() const {
    std::scoped_lock lock(packetsMutex_);
    return packets_.size();
}

std::size_t CaptureSession::detectionResultCount() const {
    return repository_->size();
}

void CaptureSession::clear() {
    {
        std::scoped_lock lock(packetsMutex_);
        packets_.clear();
    }
    repository_->clear();
}

} // namespace nids::core
