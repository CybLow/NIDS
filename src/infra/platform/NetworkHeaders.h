#pragma once

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#endif

#include <cstdint>

namespace nids::platform {

#ifdef _WIN32

struct EthernetHeader {
  std::uint8_t destMac[6];
  std::uint8_t srcMac[6];
  std::uint16_t etherType;
};

struct IPv4Header {
  std::uint8_t versionIhl;
  std::uint8_t tos;
  std::uint16_t totalLength;
  std::uint16_t identification;
  std::uint16_t flagsFragOffset;
  std::uint8_t ttl;
  std::uint8_t protocol;
  std::uint16_t headerChecksum;
  std::uint32_t srcAddr;
  std::uint32_t dstAddr;

  [[nodiscard]] std::uint8_t ihl() const noexcept {
    return (versionIhl & 0x0F) * 4;
  }
};

struct TcpHeader {
  std::uint16_t srcPort;
  std::uint16_t dstPort;
  std::uint32_t seqNum;
  std::uint32_t ackNum;
  std::uint8_t dataOffset;
  std::uint8_t flags;
  std::uint16_t window;
  std::uint16_t checksum;
  std::uint16_t urgentPtr;
};

struct UdpHeader {
  std::uint16_t srcPort;
  std::uint16_t dstPort;
  std::uint16_t length;
  std::uint16_t checksum;
};

constexpr std::uint16_t kEtherTypeIPv4 = 0x0800;
constexpr std::uint8_t kIpProtoTcp = 6;
constexpr std::uint8_t kIpProtoUdp = 17;
constexpr std::uint8_t kIpProtoIcmp = 1;
constexpr std::size_t kEthernetHeaderSize = 14;

#else

/** Portable alias for the platform Ethernet header. */
using EthernetHeader = struct ether_header;
/** Portable alias for the platform IPv4 header. */
using IPv4Header = struct ip;
/** Portable alias for the platform TCP header. */
using TcpHeader = struct tcphdr;
/** Portable alias for the platform UDP header. */
using UdpHeader = struct udphdr;

/** EtherType value for IPv4. */
constexpr std::uint16_t kEtherTypeIPv4 = ETHERTYPE_IP;
/** IP protocol number for TCP. */
constexpr std::uint8_t kIpProtoTcp = IPPROTO_TCP;
/** IP protocol number for UDP. */
constexpr std::uint8_t kIpProtoUdp = IPPROTO_UDP;
/** IP protocol number for ICMP. */
constexpr std::uint8_t kIpProtoIcmp = IPPROTO_ICMP;
/** Size of an Ethernet frame header in bytes. */
constexpr std::size_t kEthernetHeaderSize = sizeof(struct ether_header);

#endif

/** Get the source port from a TCP header (network-to-host byte order). */
inline std::uint16_t getTcpSrcPort(const TcpHeader *h) noexcept {
#ifdef _WIN32
  return ntohs(h->srcPort);
#else
  return ntohs(h->th_sport);
#endif
}

/** Get the destination port from a TCP header (network-to-host byte order). */
inline std::uint16_t getTcpDstPort(const TcpHeader *h) noexcept {
#ifdef _WIN32
  return ntohs(h->dstPort);
#else
  return ntohs(h->th_dport);
#endif
}

/** Get the source port from a UDP header (network-to-host byte order). */
inline std::uint16_t getUdpSrcPort(const UdpHeader *h) noexcept {
#ifdef _WIN32
  return ntohs(h->srcPort);
#else
  return ntohs(h->uh_sport);
#endif
}

/** Get the destination port from a UDP header (network-to-host byte order). */
inline std::uint16_t getUdpDstPort(const UdpHeader *h) noexcept {
#ifdef _WIN32
  return ntohs(h->dstPort);
#else
  return ntohs(h->uh_dport);
#endif
}

/** Get the EtherType field from an Ethernet header (network-to-host byte
 * order). */
inline std::uint16_t getEtherType(const EthernetHeader *h) noexcept {
#ifdef _WIN32
  return ntohs(h->etherType);
#else
  return ntohs(h->ether_type);
#endif
}

/** Get the protocol field from an IPv4 header. */
inline std::uint8_t getIpProtocol(const IPv4Header *h) noexcept {
#ifdef _WIN32
  return h->protocol;
#else
  return h->ip_p;
#endif
}

/** Get the IP header length in bytes (IHL field * 4). */
inline std::uint8_t getIpIhl(const IPv4Header *h) noexcept {
#ifdef _WIN32
  return (h->versionIhl & 0x0F) * 4;
#else
  return static_cast<std::uint8_t>(h->ip_hl * 4);
#endif
}

/** Get the total length of the IP datagram (network-to-host byte order). */
inline std::uint16_t getIpTotalLength(const IPv4Header *h) noexcept {
#ifdef _WIN32
  return ntohs(h->totalLength);
#else
  return ntohs(h->ip_len);
#endif
}

/** Get the source IP address as a dotted-decimal string (thread-local buffer).
 */
inline const char *getIpSrcStr(const IPv4Header *h) noexcept {
#ifdef _WIN32
  static thread_local char buf[INET_ADDRSTRLEN];
  struct in_addr addr;
  addr.s_addr = h->srcAddr;
  inet_ntop(AF_INET, &addr, buf, sizeof(buf));
  return buf;
#else
  static thread_local char
      buf[INET_ADDRSTRLEN]; // NOSONAR - inet_ntop requires C char array
  inet_ntop(AF_INET, &(h->ip_src), buf, sizeof(buf));
  return buf;
#endif
}

/** Get the destination IP address as a dotted-decimal string (thread-local
 * buffer). */
inline const char *getIpDstStr(const IPv4Header *h) noexcept {
#ifdef _WIN32
  static thread_local char buf[INET_ADDRSTRLEN];
  struct in_addr addr;
  addr.s_addr = h->dstAddr;
  inet_ntop(AF_INET, &addr, buf, sizeof(buf));
  return buf;
#else
  static thread_local char
      buf[INET_ADDRSTRLEN]; // NOSONAR - inet_ntop requires C char array
  inet_ntop(AF_INET, &(h->ip_dst), buf, sizeof(buf));
  return buf;
#endif
}

// TCP flag bits (RFC 793 + RFC 3168 ECN)
/** TCP FIN flag bitmask. */
constexpr std::uint8_t kTcpFin = 0x01;
/** TCP SYN flag bitmask. */
constexpr std::uint8_t kTcpSyn = 0x02;
/** TCP RST flag bitmask. */
constexpr std::uint8_t kTcpRst = 0x04;
/** TCP PSH flag bitmask. */
constexpr std::uint8_t kTcpPsh = 0x08;
/** TCP ACK flag bitmask. */
constexpr std::uint8_t kTcpAck = 0x10;
/** TCP URG flag bitmask. */
constexpr std::uint8_t kTcpUrg = 0x20;
/** TCP ECE flag bitmask (RFC 3168). */
constexpr std::uint8_t kTcpEce = 0x40;
/** TCP CWR flag bitmask (RFC 3168). */
constexpr std::uint8_t kTcpCwr = 0x80;

/// Minimal ICMP header (first 4 bytes): type, code, checksum.
/// The ICMP header is always at least 8 bytes (including identifier + sequence
/// for echo), but we only need type and code for flow keying.
struct IcmpHeader {
  /** ICMP message type. */
  std::uint8_t type;
  /** ICMP message subtype code. */
  std::uint8_t code;
  /** Header checksum. */
  std::uint16_t checksum;
};

/// Minimum ICMP header size (type + code + checksum + id + seq).
constexpr std::size_t kIcmpHeaderSize = 8;

/** Get the TCP flags byte from a TCP header. */
inline std::uint8_t getTcpFlags(const TcpHeader *h) noexcept {
#ifdef _WIN32
  return h->flags;
#else
  return h->th_flags;
#endif
}

/** Get the TCP window size (network-to-host byte order). */
inline std::uint16_t getTcpWindow(const TcpHeader *h) noexcept {
#ifdef _WIN32
  return ntohs(h->window);
#else
  return ntohs(h->th_win);
#endif
}

/** Get the TCP data offset (header length) in bytes. */
inline std::uint8_t getTcpDataOffset(const TcpHeader *h) noexcept {
#ifdef _WIN32
  return (h->dataOffset >> 4) * 4;
#else
  return static_cast<std::uint8_t>(h->th_off * 4);
#endif
}

} // namespace nids::platform
