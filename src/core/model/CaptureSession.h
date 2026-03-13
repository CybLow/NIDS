#pragma once

#include "core/model/PacketInfo.h"
#include "core/model/DetectionResult.h"

#include <vector>
#include <string>
#include <mutex>
#include <cstddef>

namespace nids::core {

/** Thread-safe storage for captured packets and their detection results. */
class CaptureSession {
public:
    /** Append a captured packet to the session. */
    void addPacket(const PacketInfo& packet);

    /// Store a detection result for a flow.
    void setDetectionResult(std::size_t index, const DetectionResult& result);

    /**
     * Retrieve the packet at the given index.
     * @param index Zero-based packet index.
     * @return Const reference to the stored PacketInfo.
     */
    [[nodiscard]] const PacketInfo& getPacket(std::size_t index) const;

    /// Retrieve the detection result for a flow.
    /// Returns a result with Unknown verdict if no result has been stored.
    [[nodiscard]] DetectionResult getDetectionResult(std::size_t index) const;

    /** Return the number of captured packets in this session. */
    [[nodiscard]] std::size_t packetCount() const;
    /** Return the number of stored detection results. */
    [[nodiscard]] std::size_t analysisResultCount() const;

    /** Remove all packets and detection results from the session. */
    void clear();

private:
    mutable std::mutex mutex_;
    std::vector<PacketInfo> packets_;
    std::vector<DetectionResult> detectionResults_;
};

} // namespace nids::core
