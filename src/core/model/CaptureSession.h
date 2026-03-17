#pragma once

#include "core/model/PacketInfo.h"
#include "core/model/DetectionResult.h"
#include "core/services/IAnalysisRepository.h"

#include <memory>
#include <vector>
#include <string>
#include <mutex>
#include <cstddef>

namespace nids::core {

/**
 * Thread-safe storage for captured packets and their detection results.
 *
 * Packet storage is managed directly (mutex-protected vector).
 * Detection result storage is delegated to an IAnalysisRepository
 * (Repository pattern, AGENTS.md 5.6).  By default an internal
 * in-memory repository is used; inject a custom one via the constructor
 * overload for persistence or testing.
 */
class CaptureSession {
public:
    /** Construct with a default in-memory analysis repository. */
    CaptureSession();

    /** Construct with an injected analysis repository (non-owning). */
    explicit CaptureSession(IAnalysisRepository& repository);

    ~CaptureSession() = default;

    // Non-copyable, non-movable.
    // Move is deleted because repository_ is a raw pointer into ownedRepository_;
    // a moved-from object would leave repository_ dangling.
    CaptureSession(const CaptureSession&) = delete;
    CaptureSession& operator=(const CaptureSession&) = delete;
    CaptureSession(CaptureSession&&) = delete;
    CaptureSession& operator=(CaptureSession&&) = delete;

    /** Append a captured packet to the session. */
    void addPacket(const PacketInfo& packet);

    /// Store a detection result for a flow.
    void setDetectionResult(std::size_t index, const DetectionResult& result) const;

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
    /** Return the number of stored detection results that are flagged (attacks). */
    [[nodiscard]] std::size_t flaggedResultCount() const;

    /** Remove all packets and detection results from the session. */
    void clear();

private:
    mutable std::mutex packetsMutex_;   ///< Guards packets_ only.
    std::vector<PacketInfo> packets_;

    /// Owned default repository (null when using injected reference).
    std::unique_ptr<IAnalysisRepository> ownedRepository_;
    /// Active repository (always valid — points to owned or injected).
    IAnalysisRepository* repository_;
};

} // namespace nids::core
