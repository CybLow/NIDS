#include "infra/flow/NativeFlowExtractor.h"
#include "infra/platform/NetworkHeaders.h"
#include "infra/capture/PcapHandle.h"

#include <pcap.h>
#include <spdlog/spdlog.h>

#include <numeric>
#include <cmath>
#include <algorithm>
#include <cassert>
#include <concepts>
#include <ranges>
// Note: std::ranges::fold_left (C++23) is not available under C++20.
// std::accumulate is used for reductions until the project adopts C++23.

namespace nids::infra {

namespace {

using nids::platform::EthernetHeader;
using nids::platform::IPv4Header;
using nids::platform::TcpHeader;
using nids::platform::UdpHeader;
using nids::platform::IcmpHeader;
using nids::platform::kEthernetHeaderSize;
using nids::platform::kIcmpHeaderSize;
using nids::platform::kIpProtoTcp;
using nids::platform::kIpProtoUdp;
using nids::platform::kIpProtoIcmp;
using nids::platform::kEtherTypeIPv4;
using nids::platform::kTcpFin;
using nids::platform::kTcpSyn;
using nids::platform::kTcpRst;
using nids::platform::kTcpPsh;
using nids::platform::kTcpAck;
using nids::platform::kTcpUrg;
using nids::platform::kTcpCwr;
using nids::platform::kTcpEce;
using nids::platform::getEtherType;
using nids::platform::getIpIhl;
using nids::platform::getIpProtocol;
using nids::platform::getIpTotalLength;
using nids::platform::getIpSrcStr;
using nids::platform::getIpDstStr;
using nids::platform::getTcpSrcPort;
using nids::platform::getTcpDstPort;
using nids::platform::getTcpDataOffset;
using nids::platform::getTcpFlags;
using nids::platform::getTcpWindow;
using nids::platform::getUdpSrcPort;
using nids::platform::getUdpDstPort;
constexpr std::int64_t kIdleThresholdUs = 5'000'000;   // 5 seconds (standard idle threshold)
constexpr std::int64_t kDefaultFlowTimeoutUs = 600'000'000;  // 600 seconds
constexpr std::uint16_t kEtherTypeVlan = 0x8100;

template<std::ranges::sized_range Container>
    requires std::is_arithmetic_v<std::ranges::range_value_t<Container>>
double mean(const Container& c) {
    if (c.empty()) return 0.0;
    double sum = std::accumulate(c.begin(), c.end(), 0.0,
        [](double acc, auto val) { return acc + static_cast<double>(val); });
    return sum / static_cast<double>(c.size());
}

template<std::ranges::sized_range Container>
    requires std::is_arithmetic_v<std::ranges::range_value_t<Container>>
double stddev(const Container& c) {
    if (c.size() <= 1) return 0.0;
    double m = mean(c);
    double accum = std::transform_reduce(c.begin(), c.end(), 0.0, std::plus<>{},
        [m](auto val) { double d = static_cast<double>(val) - m; return d * d; });
    return std::sqrt(accum / static_cast<double>(c.size() - 1));
}

template<std::ranges::sized_range Container>
    requires std::is_arithmetic_v<std::ranges::range_value_t<Container>>
double variance(const Container& c) {
    if (c.size() <= 1) return 0.0;
    double m = mean(c);
    double accum = std::transform_reduce(c.begin(), c.end(), 0.0, std::plus<>{},
        [m](auto val) { double d = static_cast<double>(val) - m; return d * d; });
    return accum / static_cast<double>(c.size());
}

void pushLengthStats(std::vector<float>& features, const std::vector<std::uint32_t>& lengths) {
    if (lengths.empty()) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(std::ranges::max(lengths)));
        features.push_back(static_cast<float>(std::ranges::min(lengths)));
        features.push_back(static_cast<float>(mean(lengths)));
        features.push_back(static_cast<float>(stddev(lengths)));
    }
}

void pushIatStats(std::vector<float>& features, const std::vector<std::int64_t>& iats) {
    if (iats.empty()) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f, 0.0f});
    } else {
        double totalUs = std::accumulate(iats.begin(), iats.end(), 0.0,
            [](double acc, auto val) { return acc + static_cast<double>(val); });
        features.push_back(static_cast<float>(totalUs));
        features.push_back(static_cast<float>(mean(iats)));
        features.push_back(static_cast<float>(stddev(iats)));
        features.push_back(static_cast<float>(std::ranges::max(iats)));
        features.push_back(static_cast<float>(std::ranges::min(iats)));
    }
}

} // anonymous namespace

const std::vector<std::string>& flowFeatureNames() {
    // Feature names matching toFeatureVector() order.
    // 77 features total (kFlowFeatureCount).
    static const std::vector<std::string> names = {
        // 0: Destination port
        "Destination Port",
        // 1: Flow duration
        "Flow Duration",
        // 2-5: Packet/byte counts
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        // 6-9: Forward packet length stats
        "Fwd Packet Length Max",
        "Fwd Packet Length Min",
        "Fwd Packet Length Mean",
        "Fwd Packet Length Std",
        // 10-13: Backward packet length stats
        "Bwd Packet Length Max",
        "Bwd Packet Length Min",
        "Bwd Packet Length Mean",
        "Bwd Packet Length Std",
        // 14-15: Flow rates
        "Flow Bytes/s",
        "Flow Packets/s",
        // 16-19: Flow IAT stats
        "Flow IAT Mean",
        "Flow IAT Std",
        "Flow IAT Max",
        "Flow IAT Min",
        // 20-24: Forward IAT stats
        "Fwd IAT Total",
        "Fwd IAT Mean",
        "Fwd IAT Std",
        "Fwd IAT Max",
        "Fwd IAT Min",
        // 25-29: Backward IAT stats
        "Bwd IAT Total",
        "Bwd IAT Mean",
        "Bwd IAT Std",
        "Bwd IAT Max",
        "Bwd IAT Min",
        // 30-33: PSH/URG flags per direction
        "Fwd PSH Flags",
        "Bwd PSH Flags",
        "Fwd URG Flags",
        "Bwd URG Flags",
        // 34-35: Header lengths
        "Fwd Header Length",
        "Bwd Header Length",
        // 36-37: Per-direction packet rates
        "Fwd Packets/s",
        "Bwd Packets/s",
        // 38-42: All-packet length stats
        "Min Packet Length",
        "Max Packet Length",
        "Packet Length Mean",
        "Packet Length Std",
        "Packet Length Variance",
        // 43-50: TCP flag counts
        "FIN Flag Count",
        "SYN Flag Count",
        "RST Flag Count",
        "PSH Flag Count",
        "ACK Flag Count",
        "URG Flag Count",
        "CWE Flag Count",
        "ECE Flag Count",
        // 51: Down/Up ratio
        "Down/Up Ratio",
        // 52: Average packet size
        "Average Packet Size",
        // 53-54: Average segment sizes
        "Avg Fwd Segment Size",
        "Avg Bwd Segment Size",
        // 55-57: Forward bulk metrics
        "Fwd Avg Bytes/Bulk",
        "Fwd Avg Packets/Bulk",
        "Fwd Avg Bulk Rate",
        // 58-60: Backward bulk metrics
        "Bwd Avg Bytes/Bulk",
        "Bwd Avg Packets/Bulk",
        "Bwd Avg Bulk Rate",
        // 61-64: Subflow metrics
        "Subflow Fwd Packets",
        "Subflow Fwd Bytes",
        "Subflow Bwd Packets",
        "Subflow Bwd Bytes",
        // 65-66: Initial TCP window sizes
        "Init_Win_bytes_forward",
        "Init_Win_bytes_backward",
        // 67-68: Forward data packets and min segment
        "act_data_pkt_fwd",
        "min_seg_size_forward",
        // 69-72: Active time stats
        "Active Mean",
        "Active Std",
        "Active Max",
        "Active Min",
        // 73-76: Idle time stats
        "Idle Mean",
        "Idle Std",
        "Idle Max",
        "Idle Min",
    };
    assert(names.size() == static_cast<std::size_t>(kFlowFeatureCount)
           && "flowFeatureNames() size must match kFlowFeatureCount");
    return names;
}

NativeFlowExtractor::NativeFlowExtractor() : flowTimeoutUs_(kDefaultFlowTimeoutUs) {}

void NativeFlowExtractor::setFlowTimeout(std::int64_t timeoutUs) {
    flowTimeoutUs_ = timeoutUs;
}

std::vector<float> FlowStats::toFeatureVector(std::uint16_t dstPort) const {
    std::vector<float> features;
    features.reserve(kFlowFeatureCount);

    double durationUs = static_cast<double>(lastTimeUs - startTimeUs);
    if (durationUs < 0) durationUs = 0;

    // 0: Destination Port
    features.push_back(static_cast<float>(dstPort));
    // 1: Flow Duration (microseconds)
    features.push_back(static_cast<float>(durationUs));
    // 2-5: Total Fwd/Bwd Packets and Bytes
    features.push_back(static_cast<float>(totalFwdPackets));
    features.push_back(static_cast<float>(totalBwdPackets));
    features.push_back(static_cast<float>(totalFwdBytes));
    features.push_back(static_cast<float>(totalBwdBytes));
    // 6-9: Fwd Packet Length Max, Min, Mean, Std
    pushLengthStats(features, fwdPacketLengths);
    // 10-13: Bwd Packet Length Max, Min, Mean, Std
    pushLengthStats(features, bwdPacketLengths);
    // 14-15: Flow Bytes/s, Flow Packets/s
    if (durationUs > 0) {
        double totalBytes = static_cast<double>(totalFwdBytes + totalBwdBytes);
        double totalPackets = static_cast<double>(totalFwdPackets + totalBwdPackets);
        features.push_back(static_cast<float>(totalBytes / (durationUs / 1e6)));
        features.push_back(static_cast<float>(totalPackets / (durationUs / 1e6)));
    } else {
        features.push_back(0.0f);
        features.push_back(0.0f);
    }
    // 16-19: Flow IAT Mean, Std, Max, Min
    if (flowIatUs.empty()) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(mean(flowIatUs)));
        features.push_back(static_cast<float>(stddev(flowIatUs)));
        features.push_back(static_cast<float>(std::ranges::max(flowIatUs)));
        features.push_back(static_cast<float>(std::ranges::min(flowIatUs)));
    }
    // 20-24: Fwd IAT Total, Mean, Std, Max, Min
    pushIatStats(features, fwdIatUs);
    // 25-29: Bwd IAT Total, Mean, Std, Max, Min
    pushIatStats(features, bwdIatUs);
    // 30-33: Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags
    features.push_back(static_cast<float>(fwdPshFlags));
    features.push_back(static_cast<float>(bwdPshFlags));
    features.push_back(static_cast<float>(fwdUrgFlags));
    features.push_back(static_cast<float>(bwdUrgFlags));
    // 34-35: Fwd Header Length, Bwd Header Length
    features.push_back(static_cast<float>(fwdHeaderBytes));
    features.push_back(static_cast<float>(bwdHeaderBytes));
    // 36-37: Fwd Packets/s, Bwd Packets/s
    if (durationUs > 0) {
        features.push_back(static_cast<float>(totalFwdPackets) / static_cast<float>(durationUs / 1e6));
        features.push_back(static_cast<float>(totalBwdPackets) / static_cast<float>(durationUs / 1e6));
    } else {
        features.push_back(0.0f);
        features.push_back(0.0f);
    }
    // 38-42: Packet Length Min, Max, Mean, Std, Variance (all packets)
    if (allPacketLengths.empty()) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(std::ranges::min(allPacketLengths)));
        features.push_back(static_cast<float>(std::ranges::max(allPacketLengths)));
        features.push_back(static_cast<float>(mean(allPacketLengths)));
        features.push_back(static_cast<float>(stddev(allPacketLengths)));
        features.push_back(static_cast<float>(variance(allPacketLengths)));
    }
    // 43-50: FIN, SYN, RST, PSH, ACK, URG, CWR, ECE counts
    features.push_back(static_cast<float>(finCount));
    features.push_back(static_cast<float>(synCount));
    features.push_back(static_cast<float>(rstCount));
    features.push_back(static_cast<float>(pshCount));
    features.push_back(static_cast<float>(ackCount));
    features.push_back(static_cast<float>(urgCount));
    features.push_back(static_cast<float>(cwrCount));
    features.push_back(static_cast<float>(eceCount));
    // 51: Down/Up Ratio (backward/forward packets)
    if (totalFwdPackets > 0) {
        features.push_back(static_cast<float>(totalBwdPackets) / static_cast<float>(totalFwdPackets));
    } else {
        features.push_back(0.0f);
    }
    // 52: Average Packet Size
    std::uint64_t totalPackets = totalFwdPackets + totalBwdPackets;
    std::uint64_t totalBytes = totalFwdBytes + totalBwdBytes;
    features.push_back(totalPackets > 0 ? static_cast<float>(totalBytes) / static_cast<float>(totalPackets) : 0.0f);
    // 53-54: Fwd Segment Size Avg, Bwd Segment Size Avg
    features.push_back(totalFwdPackets > 0 ? static_cast<float>(totalFwdBytes - fwdHeaderBytes) / static_cast<float>(totalFwdPackets) : 0.0f);
    features.push_back(totalBwdPackets > 0 ? static_cast<float>(totalBwdBytes - bwdHeaderBytes) / static_cast<float>(totalBwdPackets) : 0.0f);
    // 55-57: Fwd Bytes/Bulk Avg, Fwd Packet/Bulk Avg, Fwd Bulk Rate Avg
    if (fwdBulkBytes.empty()) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(mean(fwdBulkBytes)));
        features.push_back(static_cast<float>(mean(fwdBulkPackets)));
        double totalFwdBulkBytes = std::accumulate(fwdBulkBytes.begin(), fwdBulkBytes.end(), 0.0,
            [](double acc, auto val) { return acc + static_cast<double>(val); });
        features.push_back(durationUs > 0 ? static_cast<float>(totalFwdBulkBytes / (durationUs / 1e6)) : 0.0f);
    }
    // 58-60: Bwd Bytes/Bulk Avg, Bwd Packet/Bulk Avg, Bwd Bulk Rate Avg
    if (bwdBulkBytes.empty()) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(mean(bwdBulkBytes)));
        features.push_back(static_cast<float>(mean(bwdBulkPackets)));
        double totalBwdBulkBytes = std::accumulate(bwdBulkBytes.begin(), bwdBulkBytes.end(), 0.0,
            [](double acc, auto val) { return acc + static_cast<double>(val); });
        features.push_back(durationUs > 0 ? static_cast<float>(totalBwdBulkBytes / (durationUs / 1e6)) : 0.0f);
    }
    // 61-64: Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes
    features.push_back(static_cast<float>(totalFwdPackets));
    features.push_back(static_cast<float>(totalFwdBytes));
    features.push_back(static_cast<float>(totalBwdPackets));
    features.push_back(static_cast<float>(totalBwdBytes));
    // 65-66: Init_Win_bytes_forward, Init_Win_bytes_backward
    features.push_back(static_cast<float>(fwdInitWinBytes));
    features.push_back(static_cast<float>(bwdInitWinBytes));
    // 67-68: act_data_pkt_fwd, min_seg_size_forward
    features.push_back(static_cast<float>(actDataPktFwd));
    features.push_back(static_cast<float>(minSegSizeForward));
    // 69-72: Active Mean, Std, Max, Min
    if (activePeriodsUs.empty()) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(mean(activePeriodsUs)));
        features.push_back(static_cast<float>(stddev(activePeriodsUs)));
        features.push_back(static_cast<float>(std::ranges::max(activePeriodsUs)));
        features.push_back(static_cast<float>(std::ranges::min(activePeriodsUs)));
    }
    // 73-76: Idle Mean, Std, Max, Min
    if (idlePeriodsUs.empty()) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(mean(idlePeriodsUs)));
        features.push_back(static_cast<float>(stddev(idlePeriodsUs)));
        features.push_back(static_cast<float>(std::ranges::max(idlePeriodsUs)));
        features.push_back(static_cast<float>(std::ranges::min(idlePeriodsUs)));
    }

    assert(features.size() == static_cast<std::size_t>(kFlowFeatureCount)
           && "toFeatureVector() output size must match kFlowFeatureCount");
    return features;
}

std::vector<std::vector<float>> NativeFlowExtractor::extractFeatures(
    const std::string& pcapPath) {
    char errbuf[PCAP_ERRBUF_SIZE];
    auto handle = makePcapHandle(pcap_open_offline(pcapPath.c_str(), errbuf));
    if (!handle) {
        spdlog::error("Cannot open pcap file: {}", errbuf);
        return {};
    }

    flows_.clear();
    completedFlows_.clear();
    struct pcap_pkthdr* header;
    const unsigned char* data;

    while (pcap_next_ex(handle.get(), &header, &data) > 0) {
        std::int64_t tsUs = static_cast<std::int64_t>(header->ts.tv_sec) * 1000000
                            + header->ts.tv_usec;
        processPacket(data, header->caplen, tsUs);
    }

    finalizeBulks();
    buildFlowMetadata();
    return buildFeatureVectors();
}

void NativeFlowExtractor::finalizeBulks() {
    for (auto& [key, stats] : flows_) {
        if (stats.curFwdBulkPkts >= 2) {
            stats.fwdBulkPackets.push_back(stats.curFwdBulkPkts);
            stats.fwdBulkBytes.push_back(stats.curFwdBulkBytes);
        }
        if (stats.curBwdBulkPkts >= 2) {
            stats.bwdBulkPackets.push_back(stats.curBwdBulkPkts);
            stats.bwdBulkBytes.push_back(stats.curBwdBulkBytes);
        }
    }
}

void NativeFlowExtractor::processPacket(const std::uint8_t* data,
                                          std::uint32_t len,
                                          std::int64_t timestampUs) {
    if (len < kEthernetHeaderSize) [[unlikely]] return;

    auto* eth = reinterpret_cast<const EthernetHeader*>(data);
    std::uint16_t etherType = getEtherType(eth);
    const std::uint8_t* payload = data + kEthernetHeaderSize;
    std::uint32_t payloadLen = len - kEthernetHeaderSize;

    if (etherType == kEtherTypeVlan && payloadLen >= 4) [[unlikely]] {
        etherType = (static_cast<std::uint16_t>(payload[2]) << 8) | payload[3];
        payload += 4;
        payloadLen -= 4;
    }

    if (etherType != kEtherTypeIPv4 || payloadLen < 20) [[unlikely]] return;

    auto* ip = reinterpret_cast<const IPv4Header*>(payload);
    std::uint8_t ipIhl = getIpIhl(ip);
    std::uint8_t protocol = getIpProtocol(ip);
    std::uint32_t ipTotalLen = getIpTotalLength(ip);
    if (payloadLen < ipIhl || ipTotalLen < ipIhl) return;

    std::string srcIp(getIpSrcStr(ip));
    std::string dstIp(getIpDstStr(ip));

    std::uint16_t srcPort = 0;
    std::uint16_t dstPort = 0;
    std::uint32_t transportHeaderLen = 0;
    std::uint32_t totalPacketLen = ipTotalLen;

    if (protocol == kIpProtoTcp) [[likely]] {
        if (payloadLen < ipIhl + 20u) [[unlikely]] return;
        auto* tcp = reinterpret_cast<const TcpHeader*>(payload + ipIhl);
        srcPort = getTcpSrcPort(tcp);
        dstPort = getTcpDstPort(tcp);
        transportHeaderLen = getTcpDataOffset(tcp);
        if (transportHeaderLen < 20) transportHeaderLen = 20;
    } else if (protocol == kIpProtoUdp) {
        if (payloadLen < ipIhl + 8u) [[unlikely]] return;
        auto* udp = reinterpret_cast<const UdpHeader*>(payload + ipIhl);
        srcPort = getUdpSrcPort(udp);
        dstPort = getUdpDstPort(udp);
        transportHeaderLen = 8;
    } else if (protocol == kIpProtoIcmp) {
        if (payloadLen < ipIhl + kIcmpHeaderSize) [[unlikely]] return;
        auto* icmp = reinterpret_cast<const IcmpHeader*>(payload + ipIhl);
        // Use ICMP type as src_port for flow keying (matches preprocessing).
        srcPort = icmp->type;
        dstPort = 0;
        transportHeaderLen = static_cast<std::uint32_t>(kIcmpHeaderSize);
    } else {
        return;  // Unsupported protocol
    }

    std::uint32_t headerBytes = ipIhl + transportHeaderLen;
    std::uint32_t payloadSize = totalPacketLen > headerBytes ? totalPacketLen - headerBytes : 0;

    FlowKey keyFwd{.srcIp = srcIp, .dstIp = dstIp, .srcPort = srcPort,
                   .dstPort = dstPort, .protocol = protocol};
    FlowKey keyBwd{.srcIp = dstIp, .dstIp = srcIp, .srcPort = dstPort,
                   .dstPort = srcPort, .protocol = protocol};

    auto itFwd = flows_.find(keyFwd);
    auto itBwd = flows_.find(keyBwd);
    if (itFwd != flows_.end() && (timestampUs - itFwd->second.lastTimeUs > flowTimeoutUs_)) {
        completedFlows_.emplace_back(keyFwd, std::move(itFwd->second));
        flows_.erase(itFwd);
        itFwd = flows_.end();
    }
    if (itBwd != flows_.end() && (timestampUs - itBwd->second.lastTimeUs > flowTimeoutUs_)) {
        completedFlows_.emplace_back(keyBwd, std::move(itBwd->second));
        flows_.erase(itBwd);
    }

    // Re-lookup after possible timeout evictions.
    itFwd = flows_.find(keyFwd);
    itBwd = flows_.find(keyBwd);

    // Determine which flow entry to use and direction.
    // We store the key by value so we can reference the stats without const_cast.
    FlowKey activeKey;
    bool isForward = false;
    bool isNew = false;
    if (itFwd != flows_.end()) {
        activeKey = itFwd->first;
        isForward = true;
    } else if (itBwd != flows_.end()) {
        activeKey = itBwd->first;
        isForward = false;
    } else {
        activeKey = keyFwd;
        isForward = true;
        isNew = true;
    }

    // Insert or access the flow stats.
    FlowStats& stats = isNew ? flows_[activeKey] : flows_[activeKey];
    if (stats.startTimeUs == 0) {
        stats.startTimeUs = timestampUs;
    }

    std::int64_t prevLastTimeUs = stats.lastTimeUs;
    std::int64_t flowGapUs = (prevLastTimeUs > 0) ? (timestampUs - prevLastTimeUs) : 0;
    if (flowGapUs > 0) stats.flowIatUs.push_back(flowGapUs);
    stats.lastTimeUs = timestampUs;
    std::uint32_t packetLen = totalPacketLen;

    if (isForward) {
        stats.totalFwdPackets++;
        stats.totalFwdBytes += packetLen;
        stats.fwdPacketLengths.push_back(packetLen);
        stats.fwdHeaderBytes += headerBytes;

        if (stats.lastFwdTimeUs >= 0) {
            stats.fwdIatUs.push_back(timestampUs - stats.lastFwdTimeUs);
        }
        stats.lastFwdTimeUs = timestampUs;
    } else {
        stats.totalBwdPackets++;
        stats.totalBwdBytes += packetLen;
        stats.bwdPacketLengths.push_back(packetLen);
        stats.bwdHeaderBytes += headerBytes;

        if (stats.lastBwdTimeUs >= 0) {
            std::int64_t iat = timestampUs - stats.lastBwdTimeUs;
            stats.bwdIatUs.push_back(iat);
            stats.flowIatUs.push_back(iat);
        }
        stats.lastBwdTimeUs = timestampUs;
    }

    stats.allPacketLengths.push_back(packetLen);

    bool tcpFinOrRst = false;
    if (protocol == kIpProtoTcp) {
        auto* tcp = reinterpret_cast<const TcpHeader*>(payload + ipIhl);
        std::uint8_t flags = getTcpFlags(tcp);
        tcpFinOrRst = (flags & (kTcpFin | kTcpRst)) != 0;
        std::uint16_t win = getTcpWindow(tcp);

        if (isForward) {
            if (flags & kTcpPsh) stats.fwdPshFlags++;
            if (flags & kTcpUrg) stats.fwdUrgFlags++;
            if (stats.fwdInitWinBytes == 0) stats.fwdInitWinBytes = win;
            if (payloadSize > 0) {
                stats.actDataPktFwd++;
                if (stats.minSegSizeForward == 0 || payloadSize < stats.minSegSizeForward) {
                    stats.minSegSizeForward = payloadSize;
                }
            }
        } else {
            if (flags & kTcpPsh) stats.bwdPshFlags++;
            if (flags & kTcpUrg) stats.bwdUrgFlags++;
            if (stats.bwdInitWinBytes == 0) stats.bwdInitWinBytes = win;
        }

        if (flags & kTcpFin) stats.finCount++;
        if (flags & kTcpSyn) stats.synCount++;
        if (flags & kTcpRst) stats.rstCount++;
        if (flags & kTcpPsh) stats.pshCount++;
        if (flags & kTcpAck) stats.ackCount++;
        if (flags & kTcpUrg) stats.urgCount++;
        if (flags & kTcpCwr) stats.cwrCount++;
        if (flags & kTcpEce) stats.eceCount++;
    }

    // Bulk tracking: bulk = 2+ packets in same direction
    if (isForward) {
        stats.curFwdBulkPkts++;
        stats.curFwdBulkBytes += packetLen;
        if (!stats.lastPacketWasFwd && stats.curBwdBulkPkts >= 2) {
            stats.bwdBulkPackets.push_back(stats.curBwdBulkPkts);
            stats.bwdBulkBytes.push_back(stats.curBwdBulkBytes);
        }
        if (!stats.lastPacketWasFwd) {
            stats.curBwdBulkPkts = 0;
            stats.curBwdBulkBytes = 0;
        }
        stats.lastPacketWasFwd = true;
    } else {
        stats.curBwdBulkPkts++;
        stats.curBwdBulkBytes += packetLen;
        if (stats.lastPacketWasFwd && stats.curFwdBulkPkts >= 2) {
            stats.fwdBulkPackets.push_back(stats.curFwdBulkPkts);
            stats.fwdBulkBytes.push_back(stats.curFwdBulkBytes);
        }
        if (stats.lastPacketWasFwd) {
            stats.curFwdBulkPkts = 0;
            stats.curFwdBulkBytes = 0;
        }
        stats.lastPacketWasFwd = false;
    }

    // Active/idle tracking (5s threshold)
    if (flowGapUs > kIdleThresholdUs && prevLastTimeUs > 0) {
        if (stats.lastActiveTimeUs >= 0) {
            stats.activePeriodsUs.push_back(prevLastTimeUs - stats.lastActiveTimeUs);
        }
        stats.lastIdleTimeUs = prevLastTimeUs;
        stats.lastActiveTimeUs = -1;
    }
    if (stats.lastIdleTimeUs >= 0) {
        stats.idlePeriodsUs.push_back(timestampUs - stats.lastIdleTimeUs);
        stats.lastIdleTimeUs = -1;
    }
    stats.lastActiveTimeUs = timestampUs;

    if (tcpFinOrRst) [[unlikely]] {
        if (stats.curFwdBulkPkts >= 2) {
            stats.fwdBulkPackets.push_back(stats.curFwdBulkPkts);
            stats.fwdBulkBytes.push_back(stats.curFwdBulkBytes);
        }
        if (stats.curBwdBulkPkts >= 2) {
            stats.bwdBulkPackets.push_back(stats.curBwdBulkPkts);
            stats.bwdBulkBytes.push_back(stats.curBwdBulkBytes);
        }
        completedFlows_.emplace_back(activeKey, std::move(stats));
        flows_.erase(activeKey);
        return;
    }

    // Max-flow-size splitting: prevent mega-flows from collapsing into a
    // single sample.  When exceeded, finalize the current flow and start
    // a fresh one for the same 5-tuple.
    auto totalPkts = stats.totalFwdPackets + stats.totalBwdPackets;
    if (totalPkts >= kMaxFlowPackets) [[unlikely]] {
        if (stats.curFwdBulkPkts >= 2) {
            stats.fwdBulkPackets.push_back(stats.curFwdBulkPkts);
            stats.fwdBulkBytes.push_back(stats.curFwdBulkBytes);
        }
        if (stats.curBwdBulkPkts >= 2) {
            stats.bwdBulkPackets.push_back(stats.curBwdBulkPkts);
            stats.bwdBulkBytes.push_back(stats.curBwdBulkBytes);
        }
        completedFlows_.emplace_back(activeKey, std::move(stats));
        flows_[activeKey] = FlowStats{};  // Start new flow for same 5-tuple
    }
}

const std::vector<nids::core::FlowInfo>& NativeFlowExtractor::flowMetadata() const noexcept {
    return flowMetadata_;
}

void NativeFlowExtractor::buildFlowMetadata() {
    flowMetadata_.clear();
    flowMetadata_.reserve(completedFlows_.size() + flows_.size());

    auto buildOne = [&](const FlowKey& key, const FlowStats& stats) {
        nids::core::FlowInfo info;
        info.srcIp = key.srcIp;
        info.dstIp = key.dstIp;
        info.srcPort = key.srcPort;
        info.dstPort = key.dstPort;
        info.protocol = key.protocol;

        info.totalFwdPackets = stats.totalFwdPackets;
        info.totalBwdPackets = stats.totalBwdPackets;

        double durationUs = static_cast<double>(stats.lastTimeUs - stats.startTimeUs);
        info.flowDurationUs = durationUs;

        if (durationUs > 0.0) {
            double durationSec = durationUs / 1'000'000.0;
            info.fwdPacketsPerSecond = static_cast<double>(stats.totalFwdPackets) / durationSec;
            info.bwdPacketsPerSecond = static_cast<double>(stats.totalBwdPackets) / durationSec;
        }

        info.synFlagCount = stats.synCount;
        info.ackFlagCount = stats.ackCount;
        info.rstFlagCount = stats.rstCount;
        info.finFlagCount = stats.finCount;

        auto totalPackets = stats.totalFwdPackets + stats.totalBwdPackets;
        auto totalBytes = stats.totalFwdBytes + stats.totalBwdBytes;
        if (totalPackets > 0) {
            info.avgPacketSize = static_cast<double>(totalBytes) / static_cast<double>(totalPackets);
        }

        flowMetadata_.push_back(std::move(info));
    };

    for (const auto& [key, stats] : completedFlows_) {
        buildOne(key, stats);
    }
    for (const auto& [key, stats] : flows_) {
        buildOne(key, stats);
    }
}

std::vector<std::vector<float>> NativeFlowExtractor::buildFeatureVectors() const {
    std::vector<std::vector<float>> result;
    result.reserve(completedFlows_.size() + flows_.size());

    for (const auto& [key, stats] : completedFlows_) {
        result.push_back(stats.toFeatureVector(key.dstPort));
    }
    for (const auto& [key, stats] : flows_) {
        result.push_back(stats.toFeatureVector(key.dstPort));
    }

    return result;
}

} // namespace nids::infra
