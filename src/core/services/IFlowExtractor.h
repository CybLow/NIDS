#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace nids::core {

/// Per-flow connection metadata retained after feature extraction.
/// Used by HybridDetectionService to run TI lookups and heuristic rules.
struct FlowInfo {
    std::string srcIp;
    std::string dstIp;
    std::uint16_t srcPort = 0;
    std::uint16_t dstPort = 0;
    std::uint8_t protocol = 0;          ///< IPPROTO_TCP=6, IPPROTO_UDP=17, IPPROTO_ICMP=1

    // Basic stats for heuristic rule evaluation
    std::uint64_t totalFwdPackets = 0;
    std::uint64_t totalBwdPackets = 0;
    double flowDurationUs = 0.0;
    double fwdPacketsPerSecond = 0.0;
    double bwdPacketsPerSecond = 0.0;
    std::uint64_t synFlagCount = 0;
    std::uint64_t ackFlagCount = 0;
    std::uint64_t rstFlagCount = 0;
    std::uint64_t finFlagCount = 0;
    double avgPacketSize = 0.0;
};

class IFlowExtractor {
public:
    virtual ~IFlowExtractor() = default;

    [[nodiscard]] virtual bool extractFlows(const std::string& pcapPath,
                                            const std::string& outputCsvPath) = 0;

    [[nodiscard]] virtual std::vector<std::vector<float>> loadFeatures(
        const std::string& csvPath) = 0;

    /// Returns per-flow metadata for the most recent extractFlows() call.
    /// The vector is indexed in the same order as the CSV rows / loadFeatures() output.
    /// Empty if extractFlows() has not been called yet.
    [[nodiscard]] virtual const std::vector<FlowInfo>& flowMetadata() const noexcept = 0;
};

} // namespace nids::core
