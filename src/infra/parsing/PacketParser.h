#pragma once

/// Shared packet header parser for PcapPlusPlus-based packet processing.
///
/// Extracts IP, TCP/UDP/ICMP header fields from a parsed PcapPlusPlus Packet
/// into a POD struct.  Used by both PcapCapture (UI packet display) and
/// NativeFlowExtractor (flow feature extraction) to eliminate parsing
/// duplication.
///
/// Lives in infra/ because it depends on PcapPlusPlus (a third-party C library)
/// which is not allowed in core/ (AGENTS.md 1.1).

#include <cstdint>
#include <string>

// Forward declarations to avoid pulling pcpp headers into every consumer.
namespace pcpp {
class Packet;
} // namespace pcpp

namespace nids::infra {

/// TCP flag bitmasks (RFC 793).
namespace tcp_flags {
constexpr std::uint8_t kFin = 0x01;
constexpr std::uint8_t kSyn = 0x02;
constexpr std::uint8_t kRst = 0x04;
constexpr std::uint8_t kPsh = 0x08;
constexpr std::uint8_t kAck = 0x10;
constexpr std::uint8_t kUrg = 0x20;
constexpr std::uint8_t kEce = 0x40;
constexpr std::uint8_t kCwr = 0x80;
} // namespace tcp_flags

/// Result of parsing a single packet's headers.
struct ParsedFields {
    std::string srcIp;
    std::string dstIp;
    std::uint16_t srcPort = 0;
    std::uint16_t dstPort = 0;
    std::uint8_t protocol = 0;         ///< IANA protocol number
    std::uint32_t ipHeaderLen = 0;     ///< IP header length in bytes
    std::uint32_t totalPacketLen = 0;  ///< IP total length field
    std::uint32_t transportHeaderLen = 0;
    std::uint32_t headerBytes = 0;     ///< ipHeaderLen + transportHeaderLen
    std::uint32_t payloadSize = 0;     ///< totalPacketLen - headerBytes
    std::uint8_t tcpFlags = 0;         ///< Bitmask of tcp_flags constants
    std::uint16_t tcpWindow = 0;       ///< TCP window size (0 for non-TCP)
};

/// Parse IPv4 + transport headers from a PcapPlusPlus Packet.
///
/// Extracts IP addresses, ports, protocol number, header/payload sizes,
/// and TCP flags.  Returns false for non-IPv4 packets or if the transport
/// header is truncated (unsupported protocols also return false).
///
/// @param packet  Parsed PcapPlusPlus packet (must outlive the call).
/// @param out     Populated on success; unmodified on failure.
/// @return True if parsing succeeded.
[[nodiscard]] bool parsePacketHeaders(const pcpp::Packet& packet, ParsedFields& out);

} // namespace nids::infra
