#pragma once

/// PacketVerdict — per-packet decision for inline IPS mode.
///
/// Returned by VerdictEngine for every packet on the hot path.
/// Determines whether a packet is forwarded, dropped, or rejected.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace nids::core {

/// Per-packet verdict for inline IPS mode.
enum class PacketVerdict : std::uint8_t {
    Forward,    ///< Forward packet to output interface
    Drop,       ///< Silently drop the packet
    Reject,     ///< Drop + send TCP RST or ICMP unreachable
    Alert,      ///< Forward but generate an alert
    Bypass,     ///< Forward and skip further inspection for this flow
};

/// Source of the verdict decision.
enum class VerdictSource : std::uint8_t {
    Default,        ///< No detection triggered, default forward
    ThreatIntel,    ///< Known-bad IP from TI feed
    Signature,      ///< Snort rule match
    YaraMatch,      ///< YARA content match
    MlClassifier,   ///< ML flow-level classification (delayed)
    DynamicBlock,   ///< Previously blocked flow (ML-informed)
    BypassManager,  ///< Flow verified clean, bypassed to kernel
    AdminBlock,     ///< Manual block rule
};

/// Combined verdict result with metadata.
struct VerdictResult {
    PacketVerdict verdict = PacketVerdict::Forward;
    VerdictSource source = VerdictSource::Default;
    std::string reason;
};

[[nodiscard]] constexpr std::string_view verdictToString(
    PacketVerdict v) noexcept {
    constexpr std::array<std::string_view, 5> names = {{
        "Forward", "Drop", "Reject", "Alert", "Bypass"
    }};
    auto idx = static_cast<std::size_t>(v);
    return idx < names.size() ? names[idx] : "Unknown";
}

[[nodiscard]] constexpr std::string_view verdictSourceToString(
    VerdictSource s) noexcept {
    constexpr std::array<std::string_view, 8> names = {{
        "Default", "ThreatIntel", "Signature", "YaraMatch",
        "MlClassifier", "DynamicBlock", "BypassManager", "AdminBlock"
    }};
    auto idx = static_cast<std::size_t>(s);
    return idx < names.size() ? names[idx] : "Unknown";
}

} // namespace nids::core
