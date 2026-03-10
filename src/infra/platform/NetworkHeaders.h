#pragma once

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
#else
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <arpa/inet.h>
    #include <netinet/if_ether.h>
#endif

#include <cstdint>

namespace nids::platform {

#ifdef _WIN32

struct EthernetHeader {
    std::uint8_t  destMac[6];
    std::uint8_t  srcMac[6];
    std::uint16_t etherType;
};

struct IPv4Header {
    std::uint8_t  versionIhl;
    std::uint8_t  tos;
    std::uint16_t totalLength;
    std::uint16_t identification;
    std::uint16_t flagsFragOffset;
    std::uint8_t  ttl;
    std::uint8_t  protocol;
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
    std::uint8_t  dataOffset;
    std::uint8_t  flags;
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

using EthernetHeader = struct ether_header;
using IPv4Header = struct ip;
using TcpHeader = struct tcphdr;
using UdpHeader = struct udphdr;

constexpr std::uint16_t kEtherTypeIPv4 = ETHERTYPE_IP;
constexpr std::uint8_t kIpProtoTcp = IPPROTO_TCP;
constexpr std::uint8_t kIpProtoUdp = IPPROTO_UDP;
constexpr std::uint8_t kIpProtoIcmp = IPPROTO_ICMP;
constexpr std::size_t kEthernetHeaderSize = sizeof(struct ether_header);

#endif

inline std::uint16_t getTcpSrcPort(const TcpHeader* h) noexcept {
#ifdef _WIN32
    return ntohs(h->srcPort);
#else
    return ntohs(h->th_sport);
#endif
}

inline std::uint16_t getTcpDstPort(const TcpHeader* h) noexcept {
#ifdef _WIN32
    return ntohs(h->dstPort);
#else
    return ntohs(h->th_dport);
#endif
}

inline std::uint16_t getUdpSrcPort(const UdpHeader* h) noexcept {
#ifdef _WIN32
    return ntohs(h->srcPort);
#else
    return ntohs(h->uh_sport);
#endif
}

inline std::uint16_t getUdpDstPort(const UdpHeader* h) noexcept {
#ifdef _WIN32
    return ntohs(h->dstPort);
#else
    return ntohs(h->uh_dport);
#endif
}

inline std::uint16_t getEtherType(const EthernetHeader* h) noexcept {
#ifdef _WIN32
    return ntohs(h->etherType);
#else
    return ntohs(h->ether_type);
#endif
}

inline std::uint8_t getIpProtocol(const IPv4Header* h) noexcept {
#ifdef _WIN32
    return h->protocol;
#else
    return h->ip_p;
#endif
}

inline std::uint8_t getIpIhl(const IPv4Header* h) noexcept {
#ifdef _WIN32
    return (h->versionIhl & 0x0F) * 4;
#else
    return static_cast<std::uint8_t>(h->ip_hl * 4);
#endif
}

inline std::uint16_t getIpTotalLength(const IPv4Header* h) noexcept {
#ifdef _WIN32
    return ntohs(h->totalLength);
#else
    return ntohs(h->ip_len);
#endif
}

inline const char* getIpSrcStr(const IPv4Header* h) noexcept {
#ifdef _WIN32
    static thread_local char buf[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = h->srcAddr;
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
#else
    return inet_ntoa(h->ip_src);
#endif
}

inline const char* getIpDstStr(const IPv4Header* h) noexcept {
#ifdef _WIN32
    static thread_local char buf[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = h->dstAddr;
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
#else
    return inet_ntoa(h->ip_dst);
#endif
}

// TCP flag bits (RFC 793 + RFC 3168 ECN)
constexpr std::uint8_t kTcpFin = 0x01;
constexpr std::uint8_t kTcpSyn = 0x02;
constexpr std::uint8_t kTcpRst = 0x04;
constexpr std::uint8_t kTcpPsh = 0x08;
constexpr std::uint8_t kTcpAck = 0x10;
constexpr std::uint8_t kTcpUrg = 0x20;
constexpr std::uint8_t kTcpEce = 0x40;
constexpr std::uint8_t kTcpCwr = 0x80;

/// Minimal ICMP header (first 4 bytes): type, code, checksum.
/// The ICMP header is always at least 8 bytes (including identifier + sequence
/// for echo), but we only need type and code for flow keying.
struct IcmpHeader {
    std::uint8_t type;
    std::uint8_t code;
    std::uint16_t checksum;
};

/// Minimum ICMP header size (type + code + checksum + id + seq).
constexpr std::size_t kIcmpHeaderSize = 8;

inline std::uint8_t getTcpFlags(const TcpHeader* h) noexcept {
#ifdef _WIN32
    return h->flags;
#else
    return static_cast<std::uint8_t>(h->th_flags);
#endif
}

inline std::uint16_t getTcpWindow(const TcpHeader* h) noexcept {
#ifdef _WIN32
    return ntohs(h->window);
#else
    return ntohs(h->th_win);
#endif
}

inline std::uint8_t getTcpDataOffset(const TcpHeader* h) noexcept {
#ifdef _WIN32
    return (h->dataOffset >> 4) * 4;
#else
    return h->th_off * 4;
#endif
}

} // namespace nids::platform
