#include "infra/rules/HeuristicRuleEngine.h"
#include "core/model/ProtocolConstants.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <format>
#include <string_view>

namespace nids::infra {

namespace {

/// Known suspicious/malicious ports.
/// Sources: Metasploit defaults, Back Orifice, IRC C2 channels, common
/// backdoors.
constexpr std::array<std::uint16_t, 12> kSuspiciousPorts = {
    4444,  // Metasploit default reverse shell
    5555,  // Common backdoor / Android debug bridge
    31337, // Back Orifice
    1337,  // Common hacker folklore port
    12345, // NetBus trojan
    54321, // Back Orifice 2000
    6666,  // IRC (often used for C2)
    6667,  // IRC
    6668,  // IRC
    6669,  // IRC
    8888,  // Common alternative HTTP (also used by malware)
    9999,  // Common alternative admin port / backdoor
};

/// Authentication service ports (used for brute-force detection).
constexpr std::array<std::uint16_t, 5> kAuthPorts = {
    21,   // FTP
    22,   // SSH
    23,   // Telnet
    3389, // RDP
    5900, // VNC
};

/// Service names corresponding 1:1 with kAuthPorts.
constexpr std::array<std::string_view, 5> kAuthServiceNames = {
    "FTP", "SSH", "Telnet", "RDP", "VNC"};

/// Thresholds
constexpr double kSynFloodRatio = 5.0;          // SYN/ACK ratio threshold
constexpr std::uint64_t kSynFloodMinSyns = 50;  // Minimum SYN count to trigger
constexpr double kIcmpFloodRate = 100.0;        // ICMP packets per second
constexpr std::uint64_t kIcmpFloodMinPkts = 20; // Minimum ICMP packets
constexpr double kBruteForceRate = 10.0; // Connections per second to auth port
constexpr std::uint64_t kBruteForceMinPkts = 20; // Minimum packets
constexpr double kHighPacketRate = 10000.0;      // Packets per second
constexpr std::uint64_t kHighPktMinPkts = 100;   // Minimum packets to trigger
constexpr std::uint64_t kResetFloodMinRsts = 30; // Minimum RST count
constexpr double kResetFloodRstRatio = 0.5;      // RST / total packets ratio
constexpr std::size_t kPortScanThreshold =
    20; // Distinct ports from same source

[[nodiscard]] bool isSuspiciousPort(std::uint16_t port) {
  return std::ranges::find(kSuspiciousPorts, port) != kSuspiciousPorts.end();
}

[[nodiscard]] bool isAuthPort(std::uint16_t port) {
  return std::ranges::find(kAuthPorts, port) != kAuthPorts.end();
}

/// Look up the service name for an authentication port.
/// Returns "Auth" if the port is not in kAuthPorts (should not happen if called
/// after isAuthPort).
[[nodiscard]] std::string_view authServiceName(std::uint16_t port) {
  if (auto it = std::ranges::find(kAuthPorts, port); it != kAuthPorts.end()) {
    auto idx = static_cast<std::size_t>(std::distance(kAuthPorts.begin(), it));
    return kAuthServiceNames[idx];
  }
  return "Auth";
}

/// Compute packet rate (packets/sec) from a flow.
/// Returns std::nullopt if the flow duration is zero or negative, meaning
/// no meaningful rate can be calculated.
[[nodiscard]] std::optional<double> packetRate(const core::FlowInfo &flow) {
  double durationSec = flow.flowDurationUs / 1'000'000.0;
  if (durationSec <= 0.0) {
    return std::nullopt;
  }
  auto totalPackets = flow.totalFwdPackets + flow.totalBwdPackets;
  return static_cast<double>(totalPackets) / durationSec;
}

} // anonymous namespace

std::vector<core::RuleMatch>
HeuristicRuleEngine::evaluate(const core::FlowInfo &flow) const {

  std::vector<core::RuleMatch> results;
  results.reserve(4); // Typically 0-2 rules fire, pre-allocate small

  auto tryAdd = [&results](std::optional<core::RuleMatch> &&result) {
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

std::vector<core::RuleMatch> HeuristicRuleEngine::evaluatePortScan(
    std::string_view srcIp,
    const std::vector<std::uint16_t> &distinctDstPorts) const {

  std::vector<core::RuleMatch> results;

  if (distinctDstPorts.size() >= kPortScanThreshold) {
    results.push_back(
        {.ruleName = "port_scan",
         .description =
             std::format("Source {} contacted {} distinct destination ports "
                         "(threshold: {})",
                         srcIp, distinctDstPorts.size(), kPortScanThreshold),
         .severity =
             std::min(1.0f, static_cast<float>(distinctDstPorts.size()) /
                                static_cast<float>(kPortScanThreshold * 3))});
  }

  return results;
}

std::size_t HeuristicRuleEngine::ruleCount() const noexcept {
  return kTotalRuleCount;
}

// ── Individual rule implementations ─────────────────────────────────

std::optional<core::RuleMatch>
HeuristicRuleEngine::checkSuspiciousPort(const core::FlowInfo &flow) {
  bool srcSuspicious = isSuspiciousPort(flow.srcPort);
  bool dstSuspicious = isSuspiciousPort(flow.dstPort);

  if (!srcSuspicious && !dstSuspicious) {
    return std::nullopt;
  }

  std::string desc;
  if (srcSuspicious && dstSuspicious) {
    desc = std::format("Both source port {} and destination port {} are known "
                       "suspicious ports",
                       flow.srcPort, flow.dstPort);
  } else if (dstSuspicious) {
    desc = std::format("Destination port {} is a known suspicious port "
                       "(potential backdoor/C2)",
                       flow.dstPort);
  } else {
    desc = std::format(
        "Source port {} is a known suspicious port (potential backdoor/C2)",
        flow.srcPort);
  }

  float severity = (srcSuspicious && dstSuspicious) ? 0.8f : 0.6f;

  return core::RuleMatch{.ruleName = "suspicious_port",
                         .description = std::move(desc),
                         .severity = severity};
}

std::optional<core::RuleMatch>
HeuristicRuleEngine::checkSynFlood(const core::FlowInfo &flow) {
  if (flow.protocol != core::kIpProtoTcp) {
    return std::nullopt;
  }

  if (flow.synFlagCount < kSynFloodMinSyns) {
    return std::nullopt;
  }

  // SYN flood: many SYNs, very few ACKs (connections never complete)
  double synAckRatio = (flow.ackFlagCount > 0)
                           ? static_cast<double>(flow.synFlagCount) /
                                 static_cast<double>(flow.ackFlagCount)
                           : static_cast<double>(flow.synFlagCount);

  if (synAckRatio < kSynFloodRatio) {
    return std::nullopt;
  }

  return core::RuleMatch{
      .ruleName = "syn_flood",
      .description = std::format(
          "High SYN/ACK ratio ({}) with {} SYN flags -- potential SYN flood",
          synAckRatio, flow.synFlagCount),
      .severity = std::min(
          1.0f, static_cast<float>(synAckRatio / (kSynFloodRatio * 4)))};
}

std::optional<core::RuleMatch>
HeuristicRuleEngine::checkIcmpFlood(const core::FlowInfo &flow) {
  if (flow.protocol != core::kIpProtoIcmp) {
    return std::nullopt;
  }

  auto totalPackets = flow.totalFwdPackets + flow.totalBwdPackets;
  if (totalPackets < kIcmpFloodMinPkts) {
    return std::nullopt;
  }

  auto rate = packetRate(flow);
  if (!rate.has_value() || *rate < kIcmpFloodRate) {
    return std::nullopt;
  }

  return core::RuleMatch{
      .ruleName = "icmp_flood",
      .description = std::format("ICMP traffic at {} packets/sec with {} total "
                                 "packets -- potential ICMP flood",
                                 *rate, totalPackets),
      .severity =
          std::min(1.0f, static_cast<float>(*rate / (kIcmpFloodRate * 10)))};
}

std::optional<core::RuleMatch>
HeuristicRuleEngine::checkBruteForce(const core::FlowInfo &flow) {
  if (flow.protocol != core::kIpProtoTcp) {
    return std::nullopt;
  }

  if (!isAuthPort(flow.dstPort)) {
    return std::nullopt;
  }

  if (auto totalPackets = flow.totalFwdPackets + flow.totalBwdPackets;
      totalPackets < kBruteForceMinPkts) {
    return std::nullopt;
  }

  auto rate = packetRate(flow);
  if (!rate.has_value() || *rate < kBruteForceRate) {
    return std::nullopt;
  }

  // High packet rate to an authentication port suggests brute force
  auto serviceName = authServiceName(flow.dstPort);

  return core::RuleMatch{
      .ruleName = "brute_force",
      .description = std::format(
          "High packet rate ({} pkt/s) to {} port {} -- potential brute force",
          *rate, serviceName, flow.dstPort),
      .severity =
          std::min(1.0f, static_cast<float>(*rate / (kBruteForceRate * 10)))};
}

std::optional<core::RuleMatch>
HeuristicRuleEngine::checkHighPacketRate(const core::FlowInfo &flow) {
  auto totalPackets = flow.totalFwdPackets + flow.totalBwdPackets;
  if (totalPackets < kHighPktMinPkts) {
    return std::nullopt;
  }

  auto rate = packetRate(flow);
  if (!rate.has_value() || *rate < kHighPacketRate) {
    return std::nullopt;
  }

  return core::RuleMatch{
      .ruleName = "high_packet_rate",
      .description = std::format("Extremely high packet rate: {} packets/sec "
                                 "over {} packets -- potential DoS/DDoS",
                                 *rate, totalPackets),
      .severity =
          std::min(1.0f, static_cast<float>(*rate / (kHighPacketRate * 5)))};
}

std::optional<core::RuleMatch>
HeuristicRuleEngine::checkResetFlood(const core::FlowInfo &flow) {
  if (flow.protocol != core::kIpProtoTcp) {
    return std::nullopt;
  }

  if (flow.rstFlagCount < kResetFloodMinRsts) {
    return std::nullopt;
  }

  auto totalPackets = flow.totalFwdPackets + flow.totalBwdPackets;
  if (totalPackets == 0) {
    return std::nullopt;
  }

  double rstRatio = static_cast<double>(flow.rstFlagCount) /
                    static_cast<double>(totalPackets);

  if (rstRatio < kResetFloodRstRatio) {
    return std::nullopt;
  }

  return core::RuleMatch{
      .ruleName = "reset_flood",
      .description = std::format("High RST ratio ({}) with {} RST flags -- "
                                 "potential reset attack or scan response",
                                 rstRatio, flow.rstFlagCount),
      .severity = std::min(1.0f, static_cast<float>(rstRatio))};
}

} // namespace nids::infra
