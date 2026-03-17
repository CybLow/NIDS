#pragma once

/// Shared pcap packet construction helpers for tests.
///
/// Provides low-level functions to build raw Ethernet+IP+TCP/UDP/ICMP packets
/// and assemble them into valid pcap files on disk. Used by NativeFlowExtractor
/// tests, stress tests, and any test that needs synthetic pcap data.

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <pcapplusplus/IPv4Layer.h>

namespace nids::testing {

// ── PCAP file format constants ──────────────────────────────────────

/// PCAP global header (libpcap format, little-endian, version 2.4, link type 1
/// = Ethernet).
inline constexpr std::uint8_t kPcapGlobalHeader[] = {
    0xd4, 0xc3, 0xb2, 0xa1, // magic
    0x02, 0x00, 0x04, 0x00, // version 2.4
    0x00, 0x00, 0x00, 0x00, // thiszone
    0x00, 0x00, 0x00, 0x00, // sigfigs
    0xff, 0xff, 0x00, 0x00, // snaplen
    0x01, 0x00, 0x00, 0x00, // link type = Ethernet
};

// ── Low-level byte helpers ──────────────────────────────────────────

/// Write a 32-bit value in little-endian format.
inline void writeLE32(std::vector<std::uint8_t>& buf, std::uint32_t val) {
    buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((val >> 24) & 0xFF));
}

/// Write a 16-bit value in network (big-endian) byte order.
inline void writeNBO16(std::uint8_t* dst, std::uint16_t val) {
    dst[0] = static_cast<std::uint8_t>((val >> 8) & 0xFF);
    dst[1] = static_cast<std::uint8_t>(val & 0xFF);
}

/// Write an IPv4 address from dotted-decimal string into 4 bytes.
inline void writeIPv4(std::uint8_t* dst, const char* ip) {
    auto addr = pcpp::IPv4Address(ip);
    auto bytes = addr.toBytes();
    std::memcpy(dst, bytes, 4);
}

// ── Packet builders ─────────────────────────────────────────────────

/// Build a raw Ethernet+IP+TCP packet.
/// Returns the raw packet bytes (no pcap header).
inline std::vector<std::uint8_t>
buildTcpPacket(const char* srcIp, const char* dstIp, std::uint16_t srcPort,
               std::uint16_t dstPort,
               std::uint8_t tcpFlags = 0x02, // SYN by default
               std::uint16_t window = 8192, std::uint16_t payloadSize = 0) {
    std::uint16_t ipTotalLen = 20 + 20 + payloadSize;
    std::uint16_t totalLen = 14 + ipTotalLen;
    std::vector<std::uint8_t> pkt(totalLen, 0);

    // Ethernet header
    pkt[12] = 0x08;
    pkt[13] = 0x00; // EtherType = IPv4

    // IPv4 header (offset 14)
    auto* ip = pkt.data() + 14;
    ip[0] = 0x45; // version 4, IHL = 5 (20 bytes)
    writeNBO16(ip + 2, ipTotalLen);
    ip[6] = 0x40; // Don't Fragment
    ip[8] = 0x40; // TTL
    ip[9] = 6;    // Protocol = TCP
    writeIPv4(ip + 12, srcIp);
    writeIPv4(ip + 16, dstIp);

    // TCP header (offset 34)
    auto* tcp = pkt.data() + 34;
    writeNBO16(tcp, srcPort);
    writeNBO16(tcp + 2, dstPort);
    tcp[12] = 0x50; // Data offset = 5 (20 bytes)
    tcp[13] = tcpFlags;
    writeNBO16(tcp + 14, window);

    return pkt;
}

/// Build a raw Ethernet+IP+UDP packet.
inline std::vector<std::uint8_t>
buildUdpPacket(const char* srcIp, const char* dstIp, std::uint16_t srcPort,
               std::uint16_t dstPort, std::uint16_t payloadSize = 0) {
    std::uint16_t udpLen = 8 + payloadSize;
    std::uint16_t ipTotalLen = 20 + udpLen;
    std::uint16_t totalLen = 14 + ipTotalLen;
    std::vector<std::uint8_t> pkt(totalLen, 0);

    // Ethernet
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    // IPv4
    auto* ip = pkt.data() + 14;
    ip[0] = 0x45;
    writeNBO16(ip + 2, ipTotalLen);
    ip[8] = 0x40;
    ip[9] = 17; // UDP
    writeIPv4(ip + 12, srcIp);
    writeIPv4(ip + 16, dstIp);

    // UDP header (offset 34)
    auto* udp = pkt.data() + 34;
    writeNBO16(udp, srcPort);
    writeNBO16(udp + 2, dstPort);
    writeNBO16(udp + 4, udpLen);

    return pkt;
}

/// Build a raw Ethernet+IP+ICMP packet.
inline std::vector<std::uint8_t>
buildIcmpPacket(const char* srcIp, const char* dstIp,
                std::uint8_t icmpType = 8, std::uint8_t icmpCode = 0) {
    constexpr std::uint16_t ipTotalLen = 20 + 8;
    constexpr std::uint16_t totalLen = 14 + ipTotalLen;
    std::vector<std::uint8_t> pkt(totalLen, 0);

    pkt[12] = 0x08;
    pkt[13] = 0x00;

    auto* ip = pkt.data() + 14;
    ip[0] = 0x45;
    writeNBO16(ip + 2, ipTotalLen);
    ip[8] = 0x40;
    ip[9] = 1; // ICMP
    writeIPv4(ip + 12, srcIp);
    writeIPv4(ip + 16, dstIp);

    // ICMP header (offset 34)
    auto* icmp = pkt.data() + 34;
    icmp[0] = icmpType;
    icmp[1] = icmpCode;

    return pkt;
}

/// Build a raw Ethernet + VLAN tag + IP + TCP packet (802.1Q).
inline std::vector<std::uint8_t>
buildVlanTcpPacket(const char* srcIp, const char* dstIp, std::uint16_t srcPort,
                   std::uint16_t dstPort, std::uint16_t vlanId = 100,
                   std::uint8_t tcpFlags = 0x02) {
    std::uint16_t ipTotalLen = 20 + 20;
    std::uint16_t totalLen = 14 + 4 + ipTotalLen;
    std::vector<std::uint8_t> pkt(totalLen, 0);

    // Ethernet header with VLAN EtherType (0x8100)
    pkt[12] = 0x81;
    pkt[13] = 0x00;

    pkt[14] = static_cast<std::uint8_t>((vlanId >> 8) & 0x0F);
    pkt[15] = static_cast<std::uint8_t>(vlanId & 0xFF);
    pkt[16] = 0x08;
    pkt[17] = 0x00; // Real EtherType = IPv4

    // IPv4 header (offset 18)
    auto* ip = pkt.data() + 18;
    ip[0] = 0x45;
    writeNBO16(ip + 2, ipTotalLen);
    ip[6] = 0x40;
    ip[8] = 0x40;
    ip[9] = 6; // TCP
    writeIPv4(ip + 12, srcIp);
    writeIPv4(ip + 16, dstIp);

    // TCP header (offset 38)
    auto* tcp = pkt.data() + 38;
    writeNBO16(tcp, srcPort);
    writeNBO16(tcp + 2, dstPort);
    tcp[12] = 0x50; // Data offset = 5
    tcp[13] = tcpFlags;
    writeNBO16(tcp + 14, 8192);

    return pkt;
}

// ── Pcap file assembly ──────────────────────────────────────────────

/// A single packet entry for pcap file construction.
struct PcapPacketEntry {
    std::vector<std::uint8_t> data;
    std::uint32_t tsSec = 0;
    std::uint32_t tsUsec = 0;
};

/// Write a complete pcap file with multiple packets to a temp directory.
/// Returns the full path to the written file.
inline std::string writePcapFile(const std::string& name,
                                 const std::vector<PcapPacketEntry>& packets) {
    auto path = (std::filesystem::temp_directory_path() / name).string();
    std::vector<std::uint8_t> buf;

    // Global header
    buf.insert(buf.end(), std::begin(kPcapGlobalHeader),
               std::end(kPcapGlobalHeader));

    // Packet records
    for (const auto& entry : packets) {
        writeLE32(buf, entry.tsSec);
        writeLE32(buf, entry.tsUsec);
        auto capLen = static_cast<std::uint32_t>(entry.data.size());
        writeLE32(buf, capLen);
        writeLE32(buf, capLen);
        buf.insert(buf.end(), entry.data.begin(), entry.data.end());
    }

    std::ofstream ofs(path, std::ios::binary);
    ofs.write(reinterpret_cast<const char*>(buf.data()),
              static_cast<std::streamsize>(buf.size()));
    ofs.close();
    return path;
}

} // namespace nids::testing
