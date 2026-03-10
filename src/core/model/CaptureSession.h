#pragma once

#include "core/model/PacketInfo.h"
#include "core/model/DetectionResult.h"

#include <vector>
#include <string>
#include <mutex>
#include <cstddef>

namespace nids::core {

class CaptureSession {
public:
    void addPacket(const PacketInfo& packet);

    /// Store a detection result for a flow.
    void setDetectionResult(std::size_t index, const DetectionResult& result);

    [[nodiscard]] const PacketInfo& getPacket(std::size_t index) const;

    /// Retrieve the detection result for a flow.
    /// Returns a result with Unknown verdict if no result has been stored.
    [[nodiscard]] DetectionResult getDetectionResult(std::size_t index) const;

    [[nodiscard]] std::size_t packetCount() const;
    [[nodiscard]] std::size_t analysisResultCount() const;

    void clear();

private:
    mutable std::mutex mutex_;
    std::vector<PacketInfo> packets_;
    std::vector<DetectionResult> detectionResults_;
};

} // namespace nids::core
