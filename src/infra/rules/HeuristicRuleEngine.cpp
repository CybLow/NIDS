#include "infra/rules/HeuristicRuleEngine.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cstdint>

namespace nids::infra {

namespace {

/// Known suspicious/malicious ports.
/// Sources: Metasploit defaults, Back Orifice, IRC C2 channels, common backdoors.
constexpr std::array<std::uint16_t, 12> kSuspiciousPorts = {
    4444,   // Metasploit default reverse shell
    5555,   // Common backdoor / Android debug bridge
    31337,  // Back Orifice
    1337,   // Common hacker folklore port
    12345,  // NetBus trojan
    54321,  // Back Orifice 2000
    6666,   // IRC (often used for C2)
    6667,   // IRC
    6668,   // IRC
    6669,   // IRC
    8888,   // Common alternative HTTP (also used by malware)
    9999,   // Common alternative admin port / backdoor
};

/// Authentication service ports (used for brute-force detection).
constexpr std::array<std::uint16_t, 5> kAuthPorts = {
    21,    // FTP
    22,    // SSH
    23,    // Telnet
    3389,  // RDP
    5900,  // VNC
};

/// Thresholds
constexpr double kSynFloodRatio = 5.0;          // SYN/ACK ratio threshold
constexpr std::uint64_t kSynFloodMinSyns = 50;  // Minimum SYN count to trigger
constexpr double kIcmpFloodRate = 100.0;         // ICMP packets per second
constexpr std::uint64_t kIcmpFloodMinPkts = 20;  // Minimum ICMP packets
constexpr double kBruteForceRate = 10.0;          // Connections per second to auth port
constexpr std::uint64_t kBruteForceMinPkts = 20;  // Minimum packets
constexpr double kHighPacketRate = 10000.0;       // Packets per second
constexpr std::uint64_t kHighPktMinPkts = 100;    // Minimum packets to trigger
constexpr std::uint64_t kResetFloodMinRsts = 30;  // Minimum RST count
constexpr double kResetFloodRstRatio = 0.5;       // RST / total packets ratio
constexpr std::size_t kPortScanThreshold = 20;    // Distinct ports from same source

[[nodiscard]] bool isSuspiciousPort(std::uint16_t port) {
    return std::ranges::find(kSuspiciousPorts, port) != kSuspiciousPorts.end();
}

[[nodiscard]] bool isAuthPort(std::uint16_t port) {
    return std::ranges::find(kAuthPorts, port) != kAuthPorts.end();
}

} // anonymous namespace

std::vector<nids::core::HeuristicRuleResult> HeuristicRuleEngine::evaluate(
    const nids::core::FlowMetadata& flow) const {

    std::vector<nids::core::HeuristicRuleResult> results;
    results.reserve(4);  // Typically 0-2 rules fire, pre-allocate small

    auto tryAdd = [&results](auto&& result) {
        if (result.has_value()) {
            results.push_back(std::move(*result));
        }
    };

    tryAdd(checkSuspiciousPort(flow));
    tryAdd(checkSynFlood(flow));
    tryAdd(checkIcmpFlood(flow));
    tryAdd(checkBruteForce(flow));
    tryAdd(checkHighPacketRate(flow));
    tryAdd(checkResetFlood(flow));

    return results;
}

std::vector<nids::core::HeuristicRuleResult> HeuristicRuleEngine::evaluatePortScan(
    std::string_view srcIp,
    const std::vector<std::uint16_t>& distinctDstPorts) const {

    std::vector<nids::core::HeuristicRuleResult> results;

    if (distinctDstPorts.size() >= kPortScanThreshold) {
        results.push_back({
            .ruleName = "port_scan",
            .description = std::string("Source ") + std::string(srcIp)
                + " contacted " + std::to_string(distinctDstPorts.size())
                + " distinct destination ports (threshold: "
                + std::to_string(kPortScanThreshold) + ")",
            .severity = std::min(1.0f,
                static_cast<float>(distinctDstPorts.size()) /
                static_cast<float>(kPortScanThreshold * 3))
        });
    }

    return results;
}

std::size_t HeuristicRuleEngine::ruleCount() const noexcept {
    return kTotalRuleCount;
}

// ── Individual rule implementations ─────────────────────────────────

std::optional<nids::core::HeuristicRuleResult>
HeuristicRuleEngine::checkSuspiciousPort(const nids::core::FlowMetadata& flow) {
    bool srcSuspicious = isSuspiciousPort(flow.srcPort);
    bool dstSuspicious = isSuspiciousPort(flow.dstPort);

    if (!srcSuspicious && !dstSuspicious) {
        return std::nullopt;
    }

    std::string desc;
    if (srcSuspicious && dstSuspicious) {
        desc = "Both source port " + std::to_string(flow.srcPort)
             + " and destination port " + std::to_string(flow.dstPort)
             + " are known suspicious ports";
    } else if (dstSuspicious) {
        desc = "Destination port " + std::to_string(flow.dstPort)
             + " is a known suspicious port (potential backdoor/C2)";
    } else {
        desc = "Source port " + std::to_string(flow.srcPort)
             + " is a known suspicious port (potential backdoor/C2)";
    }

    float severity = (srcSuspicious && dstSuspicious) ? 0.8f : 0.6f;

    return nids::core::HeuristicRuleResult{
        .ruleName = "suspicious_port",
        .description = std::move(desc),
        .severity = severity
    };
}

std::optional<nids::core::HeuristicRuleResult>
HeuristicRuleEngine::checkSynFlood(const nids::core::FlowMetadata& flow) {
    if (flow.protocol != "TCP") {
        return std::nullopt;
    }

    if (flow.synFlagCount < kSynFloodMinSyns) {
        return std::nullopt;
    }

    // SYN flood: many SYNs, very few ACKs (connections never complete)
    double synAckRatio = (flow.ackFlagCount > 0)
        ? static_cast<double>(flow.synFlagCount) / static_cast<double>(flow.ackFlagCount)
        : static_cast<double>(flow.synFlagCount);

    if (synAckRatio < kSynFloodRatio) {
        return std::nullopt;
    }

    return nids::core::HeuristicRuleResult{
        .ruleName = "syn_flood",
        .description = "High SYN/ACK ratio (" + std::to_string(synAckRatio)
            + ") with " + std::to_string(flow.synFlagCount)
            + " SYN flags -- potential SYN flood",
        .severity = std::min(1.0f, static_cast<float>(synAckRatio / (kSynFloodRatio * 4)))
    };
}

std::optional<nids::core::HeuristicRuleResult>
HeuristicRuleEngine::checkIcmpFlood(const nids::core::FlowMetadata& flow) {
    if (flow.protocol != "ICMP") {
        return std::nullopt;
    }

    auto totalPackets = flow.totalFwdPackets + flow.totalBwdPackets;
    if (totalPackets < kIcmpFloodMinPkts) {
        return std::nullopt;
    }

    // Calculate packet rate
    double durationSec = flow.flowDurationUs / 1'000'000.0;
    if (durationSec <= 0.0) {
        return std::nullopt;
    }

    double pktRate = static_cast<double>(totalPackets) / durationSec;
    if (pktRate < kIcmpFloodRate) {
        return std::nullopt;
    }

    return nids::core::HeuristicRuleResult{
        .ruleName = "icmp_flood",
        .description = "ICMP traffic at " + std::to_string(pktRate)
            + " packets/sec with " + std::to_string(totalPackets)
            + " total packets -- potential ICMP flood",
        .severity = std::min(1.0f, static_cast<float>(pktRate / (kIcmpFloodRate * 10)))
    };
}

std::optional<nids::core::HeuristicRuleResult>
HeuristicRuleEngine::checkBruteForce(const nids::core::FlowMetadata& flow) {
    if (flow.protocol != "TCP") {
        return std::nullopt;
    }

    if (!isAuthPort(flow.dstPort)) {
        return std::nullopt;
    }

    auto totalPackets = flow.totalFwdPackets + flow.totalBwdPackets;
    if (totalPackets < kBruteForceMinPkts) {
        return std::nullopt;
    }

    double durationSec = flow.flowDurationUs / 1'000'000.0;
    if (durationSec <= 0.0) {
        return std::nullopt;
    }

    double pktRate = static_cast<double>(totalPackets) / durationSec;
    if (pktRate < kBruteForceRate) {
        return std::nullopt;
    }

    // High packet rate to an authentication port suggests brute force
    std::string serviceName;
    switch (flow.dstPort) {
        case 21:   serviceName = "FTP";    break;
        case 22:   serviceName = "SSH";    break;
        case 23:   serviceName = "Telnet"; break;
        case 3389: serviceName = "RDP";    break;
        case 5900: serviceName = "VNC";    break;
        default:   serviceName = "Auth";   break;
    }

    return nids::core::HeuristicRuleResult{
        .ruleName = "brute_force",
        .description = "High packet rate (" + std::to_string(pktRate)
            + " pkt/s) to " + serviceName + " port "
            + std::to_string(flow.dstPort) + " -- potential brute force",
        .severity = std::min(1.0f, static_cast<float>(pktRate / (kBruteForceRate * 10)))
    };
}

std::optional<nids::core::HeuristicRuleResult>
HeuristicRuleEngine::checkHighPacketRate(const nids::core::FlowMetadata& flow) {
    auto totalPackets = flow.totalFwdPackets + flow.totalBwdPackets;
    if (totalPackets < kHighPktMinPkts) {
        return std::nullopt;
    }

    double durationSec = flow.flowDurationUs / 1'000'000.0;
    if (durationSec <= 0.0) {
        return std::nullopt;
    }

    double pktRate = static_cast<double>(totalPackets) / durationSec;
    if (pktRate < kHighPacketRate) {
        return std::nullopt;
    }

    return nids::core::HeuristicRuleResult{
        .ruleName = "high_packet_rate",
        .description = "Extremely high packet rate: "
            + std::to_string(pktRate) + " packets/sec over "
            + std::to_string(totalPackets) + " packets -- potential DoS/DDoS",
        .severity = std::min(1.0f, static_cast<float>(pktRate / (kHighPacketRate * 5)))
    };
}

std::optional<nids::core::HeuristicRuleResult>
HeuristicRuleEngine::checkResetFlood(const nids::core::FlowMetadata& flow) {
    if (flow.protocol != "TCP") {
        return std::nullopt;
    }

    if (flow.rstFlagCount < kResetFloodMinRsts) {
        return std::nullopt;
    }

    auto totalPackets = flow.totalFwdPackets + flow.totalBwdPackets;
    if (totalPackets == 0) {
        return std::nullopt;
    }

    double rstRatio = static_cast<double>(flow.rstFlagCount)
                    / static_cast<double>(totalPackets);

    if (rstRatio < kResetFloodRstRatio) {
        return std::nullopt;
    }

    return nids::core::HeuristicRuleResult{
        .ruleName = "reset_flood",
        .description = "High RST ratio (" + std::to_string(rstRatio)
            + ") with " + std::to_string(flow.rstFlagCount)
            + " RST flags -- potential reset attack or scan response",
        .severity = std::min(1.0f, static_cast<float>(rstRatio))
    };
}

} // namespace nids::infra
