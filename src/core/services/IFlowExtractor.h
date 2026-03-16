#pragma once

#include "core/model/FlowInfo.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace nids::core {

/** Abstract interface for extracting flow-level features from network traffic.
 *
 * Supports three modes of operation:
 * - **Batch**: call extractFeatures(pcapPath) and iterate the returned vectors.
 * - **Streaming (file)**: set a FlowCompletionCallback; the callback fires for
 *   each completed flow during extractFeatures().
 * - **Live**: call processPacket() for each captured packet during live capture.
 *   When flows complete (FIN/RST, timeout, max-packets), the
 *   FlowCompletionCallback fires.  Call finalizeAllFlows() when capture ends
 *   to flush remaining active flows.
 */
class IFlowExtractor {
public:
    virtual ~IFlowExtractor() = default;

    /// Callback invoked when a flow is completed (FIN/RST, timeout, max-packets,
    /// or end-of-capture).  Receives the 77-float feature vector and connection
    /// metadata.  The callback runs on the extraction thread — keep it fast or
    /// enqueue work to another thread.
    using FlowCompletionCallback =
        std::function<void(std::vector<float>&&, FlowInfo&&)>;

    /// Register a callback for completed flows.  Pass nullptr to disable.
    virtual void setFlowCompletionCallback(FlowCompletionCallback cb) = 0;

    // ── Batch mode ─────────────────────────────────────────────────

    /// Extract flow features directly from a pcap file, returning one feature
    /// vector per flow.  Each inner vector has exactly kFlowFeatureCount floats.
    /// Returns an empty vector on failure.
    ///
    /// If a FlowCompletionCallback is set, it is invoked for each completed flow
    /// during processing (before this method returns).
    [[nodiscard]] virtual std::vector<std::vector<float>> extractFeatures(
        const std::string& pcapPath) = 0;

    /// Returns per-flow metadata for the most recent extractFeatures() call.
    /// The vector is indexed in the same order as the extractFeatures() output.
    /// Empty if extractFeatures() has not been called yet.
    [[nodiscard]] virtual const std::vector<FlowInfo>& flowMetadata() const noexcept = 0;

    // ── Live mode ──────────────────────────────────────────────────

    /// Feed a single raw packet into the flow table during live capture.
    ///
    /// The packet is parsed and its flow state updated.  When a flow
    /// completes (FIN/RST, timeout, max-packets), the FlowCompletionCallback
    /// fires.  Periodic timeout sweeps are performed automatically.
    ///
    /// @param data        Raw packet data (including link-layer header).
    /// @param length      Length of the packet data in bytes.
    /// @param timestampUs Packet timestamp in microseconds since epoch.
    virtual void processPacket(const std::uint8_t* data, std::size_t length,
                               std::int64_t timestampUs) = 0;

    /// Finalize all remaining active flows (end-of-capture).
    ///
    /// Invokes the FlowCompletionCallback for each flow still in the flow
    /// table, then clears the active flow state.  Call this when live capture
    /// ends to flush flows that never saw FIN/RST.
    virtual void finalizeAllFlows() = 0;

    /// Reset all internal state (flow table, completed flows, metadata).
    /// Call before starting a new capture session.
    virtual void reset() = 0;

    // ── Configuration ──────────────────────────────────────────────

    /// Set the idle flow timeout (microseconds).
    /// Flows with no new packets for this duration are expired.
    virtual void setFlowTimeout(std::int64_t timeoutUs) = 0;

    /// Set the maximum flow duration (microseconds).
    /// Long-lived flows are split at this interval in live mode.
    /// Pass 0 to disable duration-based splitting.
    virtual void setMaxFlowDuration(std::int64_t durationUs) = 0;
};

} // namespace nids::core
