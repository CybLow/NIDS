#pragma once

/// Interface for heuristic rule-based detection.
///
/// Evaluates flow metadata against a set of predefined heuristic rules
/// (suspicious ports, scan patterns, brute-force indicators, flood signatures).
/// Rules operate on connection-level metadata only -- NO packet payload inspection.
///
/// Defined in core/ so that app/ layer code can depend on this interface
/// without pulling in infrastructure details (Clean Architecture).

#include <string>
#include <string_view>
#include <vector>
#include <cstdint>

namespace nids::core {

/// Metadata for a single flow, used as input to heuristic rule evaluation.
/// This is a lightweight struct extracted from NativeFlowExtractor output.
struct FlowMetadata {
    /** Source IP address (dotted-decimal). */
    std::string srcIp;
    /** Destination IP address (dotted-decimal). */
    std::string dstIp;
    /** Source port number. */
    std::uint16_t srcPort = 0;
    /** Destination port number. */
    std::uint16_t dstPort = 0;
    std::string protocol;           ///< "TCP", "UDP", "ICMP"

    /** Total number of forward (src→dst) packets. */
    std::uint64_t totalFwdPackets = 0;
    /** Total number of backward (dst→src) packets. */
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
    /** Average packet size in bytes. */
    double avgPacketSize = 0.0;
};

/// Result of evaluating a single heuristic rule.
struct HeuristicRuleResult {
    std::string ruleName;         ///< Machine-readable ID (e.g., "suspicious_port")
    std::string description;      ///< Human-readable explanation
    float severity = 0.0f;       ///< Severity [0.0, 1.0]
};

/** Abstract interface for heuristic rule-based detection. */
class IRuleEngine {
public:
    virtual ~IRuleEngine() = default;

    /// Evaluate all rules against a single flow's metadata.
    /// Returns a (possibly empty) vector of rule matches.
    [[nodiscard]] virtual std::vector<HeuristicRuleResult> evaluate(
        const FlowMetadata& flow) const = 0;

    /// Evaluate port-scan heuristic across multiple flows from the same source.
    /// Takes a source IP and the set of distinct destination ports observed.
    /// Returns a rule match if the port count exceeds the scan threshold.
    [[nodiscard]] virtual std::vector<HeuristicRuleResult> evaluatePortScan(
        std::string_view srcIp,
        const std::vector<std::uint16_t>& distinctDstPorts) const = 0;

    /// Returns the number of active rules.
    [[nodiscard]] virtual std::size_t ruleCount() const noexcept = 0;
};

} // namespace nids::core
