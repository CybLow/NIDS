#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace nids::core {

/// Per-flow connection metadata retained after feature extraction.
/// Used by HybridDetectionService to run TI lookups and heuristic rules.
struct FlowInfo {
    /** Source IP address (dotted-decimal). */
    std::string srcIp;
    /** Destination IP address (dotted-decimal). */
    std::string dstIp;
    /** Source port number. */
    std::uint16_t srcPort = 0;
    /** Destination port number. */
    std::uint16_t dstPort = 0;
    std::uint8_t protocol = 0;          ///< IPPROTO_TCP=6, IPPROTO_UDP=17, IPPROTO_ICMP=1

    /** Total number of forward (src→dst) packets in the flow. */
    std::uint64_t totalFwdPackets = 0;
    /** Total number of backward (dst→src) packets in the flow. */
    std::uint64_t totalBwdPackets = 0;
    /** Flow duration in microseconds. */
    double flowDurationUs = 0.0;
    /** Forward packet rate (packets per second). */
    double fwdPacketsPerSecond = 0.0;
    /** Backward packet rate (packets per second). */
    double bwdPacketsPerSecond = 0.0;
    /** Number of TCP SYN flags observed. */
    std::uint64_t synFlagCount = 0;
    /** Number of TCP ACK flags observed. */
    std::uint64_t ackFlagCount = 0;
    /** Number of TCP RST flags observed. */
    std::uint64_t rstFlagCount = 0;
    /** Number of TCP FIN flags observed. */
    std::uint64_t finFlagCount = 0;
    /** Average packet size in bytes across the flow. */
    double avgPacketSize = 0.0;
};

/** Abstract interface for extracting flow-level features from pcap files.
 *
 * Supports two modes of operation:
 * - **Batch**: call extractFeatures(pcapPath) and iterate the returned vectors.
 * - **Streaming**: set a FlowCompletionCallback via setFlowCompletionCallback();
 *   the callback fires for each completed flow during extractFeatures() (or,
 *   in future live mode, as packets arrive).  The batch return value still
 *   contains all flows.
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
};

} // namespace nids::core
