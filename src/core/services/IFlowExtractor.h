#pragma once

#include <string>
#include <vector>
#include <cstdint>

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

/** Abstract interface for extracting flow-level features from pcap files. */
class IFlowExtractor {
public:
    virtual ~IFlowExtractor() = default;

    /// Extract flow features directly from a pcap file, returning one feature
    /// vector per flow.  Each inner vector has exactly kFlowFeatureCount floats.
    /// Returns an empty vector on failure.
    [[nodiscard]] virtual std::vector<std::vector<float>> extractFeatures(
        const std::string& pcapPath) = 0;

    /// Returns per-flow metadata for the most recent extractFeatures() call.
    /// The vector is indexed in the same order as the extractFeatures() output.
    /// Empty if extractFeatures() has not been called yet.
    [[nodiscard]] virtual const std::vector<FlowInfo>& flowMetadata() const noexcept = 0;
};

} // namespace nids::core
