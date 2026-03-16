#include "infra/parsing/PacketParser.h"
#include "core/model/ProtocolConstants.h"

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IcmpLayer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/SystemUtils.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>

namespace nids::infra {

namespace {

/// Extract TCP flags from a TCP header into a bitmask.
[[nodiscard]] std::uint8_t extractTcpFlags(const pcpp::tcphdr* hdr) noexcept {
    std::uint8_t flags = 0;
    if (hdr->finFlag) flags |= tcp_flags::kFin;
    if (hdr->synFlag) flags |= tcp_flags::kSyn;
    if (hdr->rstFlag) flags |= tcp_flags::kRst;
    if (hdr->pshFlag) flags |= tcp_flags::kPsh;
    if (hdr->ackFlag) flags |= tcp_flags::kAck;
    if (hdr->urgFlag) flags |= tcp_flags::kUrg;
    if (hdr->cwrFlag) flags |= tcp_flags::kCwr;
    if (hdr->eceFlag) flags |= tcp_flags::kEce;
    return flags;
}

} // anonymous namespace

bool parsePacketHeaders(const pcpp::Packet& packet, ParsedFields& out) {
    // PcapPlusPlus automatically handles VLAN (802.1Q) tag parsing
    const auto* ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (!ipLayer) [[unlikely]]
        return false;

    out.srcIp = ipLayer->getSrcIPv4Address().toString();
    out.dstIp = ipLayer->getDstIPv4Address().toString();
    out.ipHeaderLen = static_cast<std::uint32_t>(ipLayer->getHeaderLen());
    out.protocol = ipLayer->getIPv4Header()->protocol;
    out.totalPacketLen = pcpp::netToHost16(ipLayer->getIPv4Header()->totalLength);

    using nids::core::kIpProtoTcp;
    using nids::core::kIpProtoUdp;
    using nids::core::kIpProtoIcmp;

    if (out.protocol == kIpProtoTcp) [[likely]] {
        const auto* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
        if (!tcpLayer) [[unlikely]]
            return false;
        out.srcPort = tcpLayer->getSrcPort();
        out.dstPort = tcpLayer->getDstPort();
        out.transportHeaderLen =
            static_cast<std::uint32_t>(tcpLayer->getHeaderLen());
        if (out.transportHeaderLen < 20)
            out.transportHeaderLen = 20;

        const auto* tcpHdr = tcpLayer->getTcpHeader();
        out.tcpFlags = extractTcpFlags(tcpHdr);
        out.tcpWindow = pcpp::netToHost16(tcpHdr->windowSize);
    } else if (out.protocol == kIpProtoUdp) [[likely]] {
        const auto* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
        if (!udpLayer) [[unlikely]]
            return false;
        out.srcPort = udpLayer->getSrcPort();
        out.dstPort = udpLayer->getDstPort();
        out.transportHeaderLen = 8;
    } else if (out.protocol == kIpProtoIcmp) {
        const auto* icmpLayer = packet.getLayerOfType<pcpp::IcmpLayer>();
        if (!icmpLayer) [[unlikely]]
            return false;
        out.srcPort = icmpLayer->getIcmpHeader()->type;
        out.dstPort = 0;
        out.transportHeaderLen = 8;
    } else [[unlikely]] {
        return false; // Unsupported protocol
    }

    out.headerBytes = out.ipHeaderLen + out.transportHeaderLen;
    out.payloadSize = out.totalPacketLen > out.headerBytes
                          ? out.totalPacketLen - out.headerBytes
                          : 0;
    return true;
}

} // namespace nids::infra
