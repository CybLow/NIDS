#pragma once

/// Well-known IP protocol numbers used throughout the NIDS codebase.
///
/// Centralizes the magic numbers 1/6/17 so that all layers reference the same
/// named constants.  Values match IANA "Assigned Internet Protocol Numbers":
/// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

#include <cstdint>
#include <string_view>

namespace nids::core {

/// ICMP (Internet Control Message Protocol), IP protocol 1.
inline constexpr std::uint8_t kIpProtoIcmp = 1;
/// TCP (Transmission Control Protocol), IP protocol 6.
inline constexpr std::uint8_t kIpProtoTcp  = 6;
/// UDP (User Datagram Protocol), IP protocol 17.
inline constexpr std::uint8_t kIpProtoUdp  = 17;

/**
 * Map an IP protocol number to its human-readable name.
 *
 * @param protocol  IANA IP protocol number.
 * @return "TCP", "UDP", "ICMP", or "Other" for unrecognized values.
 */
[[nodiscard]] constexpr std::string_view protocolToName(std::uint8_t protocol) noexcept {
    switch (protocol) {
    case kIpProtoTcp:  return "TCP";
    case kIpProtoUdp:  return "UDP";
    case kIpProtoIcmp: return "ICMP";
    default:           return "Other";
    }
}

} // namespace nids::core
