#pragma once

#include "core/model/PacketInfo.h"
#include "core/model/DetectionResult.h"

#include <vector>
#include <string>
#include <mutex>
#include <cstddef>

namespace nids::core {

/**
 * Thread-safe storage for captured packets and their detection results.
 *
 * Uses separate mutexes for packets and detection results to reduce
 * contention between the capture thread (addPacket), worker thread
 * (setDetectionResult), and UI thread (reads).
 */
class CaptureSession {
public:
    /** Append a captured packet to the session. */
    void addPacket(const PacketInfo& packet);

    /// Store a detection result for a flow.
    void setDetectionResult(std::size_t index, const DetectionResult& result);

    /**
     * Retrieve a copy of the packet at the given index.
     *
     * Returns by value to avoid dangling-reference hazards: the internal
     * vector can be reallocated by addPacket() on the capture thread at
     * any time, so returning a const reference would be unsafe.
     *
     * @param index Zero-based packet index.
     * @return Copy of the stored PacketInfo.
     * @throws std::out_of_range if index >= packetCount().
     */
    [[nodiscard]] PacketInfo getPacket(std::size_t index) const;

    /// Retrieve the detection result for a flow.
    /// Returns a result with Unknown verdict if no result has been stored.
    [[nodiscard]] DetectionResult getDetectionResult(std::size_t index) const;

    /** Return the number of captured packets in this session. */
    [[nodiscard]] std::size_t packetCount() const;
    /** Return the number of stored detection results. */
    [[nodiscard]] std::size_t detectionResultCount() const;

    /** Remove all packets and detection results from the session. */
    void clear();

private:
    mutable std::mutex packetsMutex_;   ///< Guards packets_ only.
    mutable std::mutex resultsMutex_;   ///< Guards detectionResults_ only.
    std::vector<PacketInfo> packets_;
    std::vector<DetectionResult> detectionResults_;
};

} // namespace nids::core
