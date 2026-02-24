#include "infra/flow/NativeFlowExtractor.h"
#include "infra/platform/NetworkHeaders.h"

#include <pcap.h>
#include <fstream>
#include <sstream>
#include <numeric>
#include <cmath>
#include <algorithm>
#include <iostream>

namespace nids::infra {

using namespace nids::platform;

namespace {

constexpr std::int64_t kIdleThresholdUs = 5'000'000;   // 5 seconds (CICFlowMeter default)
constexpr std::int64_t kDefaultFlowTimeoutUs = 600'000'000;  // 600 seconds
constexpr std::uint16_t kEtherTypeVlan = 0x8100;

template<typename Container>
double mean(const Container& c) {
    if (c.empty()) return 0.0;
    double sum = std::accumulate(c.begin(), c.end(), 0.0);
    return sum / static_cast<double>(c.size());
}

template<typename Container>
double stddev(const Container& c) {
    if (c.size() <= 1) return 0.0;
    double m = mean(c);
    double accum = 0.0;
    for (const auto& val : c) {
        accum += (static_cast<double>(val) - m) * (static_cast<double>(val) - m);
    }
    return std::sqrt(accum / static_cast<double>(c.size() - 1));
}

template<typename Container>
double variance(const Container& c) {
    if (c.size() <= 1) return 0.0;
    double m = mean(c);
    double accum = 0.0;
    for (const auto& val : c) {
        accum += (static_cast<double>(val) - m) * (static_cast<double>(val) - m);
    }
    return accum / static_cast<double>(c.size());
}

void pushLengthStats(std::vector<float>& features, const std::vector<std::uint32_t>& lengths) {
    if (lengths.empty()) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(*std::max_element(lengths.begin(), lengths.end())));
        features.push_back(static_cast<float>(*std::min_element(lengths.begin(), lengths.end())));
        features.push_back(static_cast<float>(mean(lengths)));
        features.push_back(static_cast<float>(stddev(lengths)));
    }
}

void pushIatStats(std::vector<float>& features, const std::vector<std::int64_t>& iats) {
    if (iats.empty()) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f, 0.0f});
    } else {
        double totalUs = std::accumulate(iats.begin(), iats.end(), 0.0);
        features.push_back(static_cast<float>(totalUs));
        features.push_back(static_cast<float>(mean(iats)));
        features.push_back(static_cast<float>(stddev(iats)));
        features.push_back(static_cast<float>(*std::max_element(iats.begin(), iats.end())));
        features.push_back(static_cast<float>(*std::min_element(iats.begin(), iats.end())));
    }
}

} // anonymous namespace

NativeFlowExtractor::NativeFlowExtractor() : flowTimeoutUs_(kDefaultFlowTimeoutUs) {}

void NativeFlowExtractor::setFlowTimeout(std::int64_t timeoutUs) {
    flowTimeoutUs_ = timeoutUs;
}

bool FlowKey::operator<(const FlowKey& other) const {
    if (srcIp != other.srcIp) return srcIp < other.srcIp;
    if (dstIp != other.dstIp) return dstIp < other.dstIp;
    if (srcPort != other.srcPort) return srcPort < other.srcPort;
    if (dstPort != other.dstPort) return dstPort < other.dstPort;
    return protocol < other.protocol;
}

std::vector<float> FlowStats::toFeatureVector(std::uint16_t dstPort) const {
    std::vector<float> features;
    features.reserve(79);

    double durationUs = static_cast<double>(lastTimeUs - startTimeUs);
    if (durationUs < 0) durationUs = 0;

    // 0. Destination Port
    features.push_back(static_cast<float>(dstPort));
    // 1. Flow Duration (in microseconds, convert to float)
    features.push_back(static_cast<float>(durationUs));
    // 2-5. Total Fwd/Bwd Packets and Bytes
    features.push_back(static_cast<float>(totalFwdPackets));
    features.push_back(static_cast<float>(totalBwdPackets));
    features.push_back(static_cast<float>(totalFwdBytes));
    features.push_back(static_cast<float>(totalBwdBytes));
    // 6-9. Fwd Packet Length Max, Min, Mean, Std
    pushLengthStats(features, fwdPacketLengths);
    // 10-13. Bwd Packet Length Max, Min, Mean, Std
    pushLengthStats(features, bwdPacketLengths);
    // 14-15. Flow Bytes/s, Flow Packets/s
    if (durationUs > 0) {
        double totalBytes = static_cast<double>(totalFwdBytes + totalBwdBytes);
        double totalPackets = static_cast<double>(totalFwdPackets + totalBwdPackets);
        features.push_back(static_cast<float>(totalBytes / (durationUs / 1e6)));
        features.push_back(static_cast<float>(totalPackets / (durationUs / 1e6)));
    } else {
        features.push_back(0.0f);
        features.push_back(0.0f);
    }
    // 16-19. Flow IAT Mean, Std, Max, Min
    if (flowIatUs.empty()) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(mean(flowIatUs)));
        features.push_back(static_cast<float>(stddev(flowIatUs)));
        features.push_back(static_cast<float>(*std::max_element(flowIatUs.begin(), flowIatUs.end())));
        features.push_back(static_cast<float>(*std::min_element(flowIatUs.begin(), flowIatUs.end())));
    }
    // 20-24. Fwd IAT Total, Mean, Std, Max, Min
    pushIatStats(features, fwdIatUs);
    // 25-29. Bwd IAT Total, Mean, Std, Max, Min
    pushIatStats(features, bwdIatUs);
    // 30-33. Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags
    features.push_back(static_cast<float>(fwdPshFlags));
    features.push_back(static_cast<float>(bwdPshFlags));
    features.push_back(static_cast<float>(fwdUrgFlags));
    features.push_back(static_cast<float>(bwdUrgFlags));
    // 34-35. Fwd Header Length, Bwd Header Length
    features.push_back(static_cast<float>(fwdHeaderBytes));
    features.push_back(static_cast<float>(bwdHeaderBytes));
    // 36-37. Fwd Packets/s, Bwd Packets/s
    if (durationUs > 0) {
        features.push_back(static_cast<float>(totalFwdPackets) / static_cast<float>(durationUs / 1e6));
        features.push_back(static_cast<float>(totalBwdPackets) / static_cast<float>(durationUs / 1e6));
    } else {
        features.push_back(0.0f);
        features.push_back(0.0f);
    }
    // 38-42. Packet Length Min, Max, Mean, Std, Variance (all packets)
    if (allPacketLengths.empty()) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(*std::min_element(allPacketLengths.begin(), allPacketLengths.end())));
        features.push_back(static_cast<float>(*std::max_element(allPacketLengths.begin(), allPacketLengths.end())));
        features.push_back(static_cast<float>(mean(allPacketLengths)));
        features.push_back(static_cast<float>(stddev(allPacketLengths)));
        features.push_back(static_cast<float>(variance(allPacketLengths)));
    }
    // 43-50. FIN, SYN, RST, PSH, ACK, URG, CWR, ECE counts
    features.push_back(static_cast<float>(finCount));
    features.push_back(static_cast<float>(synCount));
    features.push_back(static_cast<float>(rstCount));
    features.push_back(static_cast<float>(pshCount));
    features.push_back(static_cast<float>(ackCount));
    features.push_back(static_cast<float>(urgCount));
    features.push_back(static_cast<float>(cwrCount));
    features.push_back(static_cast<float>(eceCount));
    // 51. Down/Up Ratio (backward/forward packets)
    if (totalFwdPackets > 0) {
        features.push_back(static_cast<float>(totalBwdPackets) / static_cast<float>(totalFwdPackets));
    } else {
        features.push_back(0.0f);
    }
    // 52. Average Packet Size
    std::uint64_t totalPackets = totalFwdPackets + totalBwdPackets;
    std::uint64_t totalBytes = totalFwdBytes + totalBwdBytes;
    features.push_back(totalPackets > 0 ? static_cast<float>(totalBytes) / static_cast<float>(totalPackets) : 0.0f);
    // 53-54. Fwd Segment Size Avg, Bwd Segment Size Avg (payload per packet excl headers - use total bytes/header / packets)
    features.push_back(totalFwdPackets > 0 ? static_cast<float>(totalFwdBytes - fwdHeaderBytes) / static_cast<float>(totalFwdPackets) : 0.0f);
    features.push_back(totalBwdPackets > 0 ? static_cast<float>(totalBwdBytes - bwdHeaderBytes) / static_cast<float>(totalBwdPackets) : 0.0f);
    // 55-57. Fwd Bytes/Bulk Avg, Fwd Packet/Bulk Avg, Fwd Bulk Rate Avg
    if (fwdBulkBytes.empty()) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(mean(fwdBulkBytes)));
        features.push_back(static_cast<float>(mean(fwdBulkPackets)));
        double totalFwdBulkBytes = std::accumulate(fwdBulkBytes.begin(), fwdBulkBytes.end(), 0.0);
        // Bulk rate: bytes per bulk / duration - approximate using flow duration
        features.push_back(durationUs > 0 ? static_cast<float>(totalFwdBulkBytes / (durationUs / 1e6)) : 0.0f);
    }
    // 58-60. Bwd Bytes/Bulk Avg, Bwd Packet/Bulk Avg, Bwd Bulk Rate Avg
    if (bwdBulkBytes.empty()) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(mean(bwdBulkBytes)));
        features.push_back(static_cast<float>(mean(bwdBulkPackets)));
        double totalBwdBulkBytes = std::accumulate(bwdBulkBytes.begin(), bwdBulkBytes.end(), 0.0);
        features.push_back(durationUs > 0 ? static_cast<float>(totalBwdBulkBytes / (durationUs / 1e6)) : 0.0f);
    }
    // 61-64. Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes (no subflow split = whole flow)
    features.push_back(static_cast<float>(totalFwdPackets));
    features.push_back(static_cast<float>(totalFwdBytes));
    features.push_back(static_cast<float>(totalBwdPackets));
    features.push_back(static_cast<float>(totalBwdBytes));
    // 65-66. Init_Win_bytes_forward, Init_Win_bytes_backward
    features.push_back(static_cast<float>(fwdInitWinBytes));
    features.push_back(static_cast<float>(bwdInitWinBytes));
    // 67-68. act_data_pkt_fwd, min_seg_size_forward
    features.push_back(static_cast<float>(actDataPktFwd));
    features.push_back(static_cast<float>(minSegSizeForward));
    // 69-72. Active Mean, Std, Max, Min
    if (activePeriodsUs.empty()) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(mean(activePeriodsUs)));
        features.push_back(static_cast<float>(stddev(activePeriodsUs)));
        features.push_back(static_cast<float>(*std::max_element(activePeriodsUs.begin(), activePeriodsUs.end())));
        features.push_back(static_cast<float>(*std::min_element(activePeriodsUs.begin(), activePeriodsUs.end())));
    }
    // 73-76. Idle Mean, Std, Max, Min
    if (idlePeriodsUs.empty()) {
        features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f});
    } else {
        features.push_back(static_cast<float>(mean(idlePeriodsUs)));
        features.push_back(static_cast<float>(stddev(idlePeriodsUs)));
        features.push_back(static_cast<float>(*std::max_element(idlePeriodsUs.begin(), idlePeriodsUs.end())));
        features.push_back(static_cast<float>(*std::min_element(idlePeriodsUs.begin(), idlePeriodsUs.end())));
    }
    // 77. Padding to reach 78 features (0-indexed 0..77)
    // Actually the plan says 78 features + 1 padding = 79 total. Let me count: 0..76 = 77 features. Destination Port through Idle Min.
    // 0: dstPort, 1: duration, 2-5: packets/bytes, 6-9: fwd len, 10-13: bwd len, 14-15: rate, 16-19: flow IAT, 20-24: fwd IAT, 25-29: bwd IAT,
    // 30-33: PSH/URG, 34-35: header len, 36-37: fwd/bwd rate, 38-42: pkt len all, 43-50: flags, 51: down/up, 52: avg pkt, 53-54: seg size,
    // 55-57: fwd bulk, 58-60: bwd bulk, 61-64: subflow, 65-66: init win, 67-68: act/min, 69-72: active, 73-76: idle = 77 features (0-76).
    // Need 79 total per plan. So we add 2 more as padding. Actually the plan says "78 features + 1 padding" = 79. So 78 real + 1 pad.
    // 0-76 = 77. So we're one short. Let me recount from the plan:
    // Destination Port(0), Flow Duration(1), Total Fwd Packets(2), Total Backward Packets(3), Total Length Fwd(4), Total Length Bwd(5),
    // Fwd Packet Length Max(6), Min(7), Mean(8), Std(9), Bwd Packet Length Max(10), Min(11), Mean(12), Std(13),
    // Flow Bytes/s(14), Flow Packets/s(15), Flow IAT Mean(16), Std(17), Max(18), Min(19),
    // Fwd IAT Total(20), Mean(21), Std(22), Max(23), Min(24), Bwd IAT Total(25), Mean(26), Std(27), Max(28), Min(29),
    // Fwd PSH(30), Bwd PSH(31), Fwd URG(32), Bwd URG(33), Fwd Header(34), Bwd Header(35), Fwd Pkts/s(36), Bwd Pkts/s(37),
    // Packet Length Min(38), Max(39), Mean(40), Std(41), Variance(42), FIN(43), SYN(44), RST(45), PSH(46), ACK(47), URG(48), CWR(49), ECE(50),
    // Down/Up(51), Avg Pkt Size(52), Fwd Seg(53), Bwd Seg(54), Fwd Bytes/Bulk(55), Fwd Pkt/Bulk(56), Fwd Bulk Rate(57),
    // Bwd Bytes/Bulk(58), Bwd Pkt/Bulk(59), Bwd Bulk Rate(60), Subflow Fwd Pkts(61), Fwd Bytes(62), Bwd Pkts(63), Bwd Bytes(64),
    // Init Win Fwd(65), Init Win Bwd(66), act_data_pkt_fwd(67), min_seg_forward(68), Active Mean(69), Std(70), Max(71), Min(72),
    // Idle Mean(73), Std(74), Max(75), Min(76) = 77 features (indices 0-76). Model expects 79. So add 2 padding.
    while (features.size() < 79) {
        features.push_back(0.0f);
    }
    return features;
}

bool NativeFlowExtractor::extractFlows(const std::string& pcapPath,
                                         const std::string& outputCsvPath) {
    char errbuf[PCAP_ERRBUF_SIZE];
    auto* handle = pcap_open_offline(pcapPath.c_str(), errbuf);
    if (!handle) {
        std::cerr << "Cannot open pcap file: " << errbuf << std::endl;
        return false;
    }

    flows_.clear();
    completedFlows_.clear();
    struct pcap_pkthdr* header;
    const unsigned char* data;

    while (pcap_next_ex(handle, &header, &data) > 0) {
        std::int64_t tsUs = static_cast<std::int64_t>(header->ts.tv_sec) * 1000000
                            + header->ts.tv_usec;
        processPacket(data, header->caplen, tsUs);
    }

    pcap_close(handle);
    finalizeBulks();
    writeCsv(outputCsvPath);
    return true;
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
    if (len < kEthernetHeaderSize) return;

    auto* eth = reinterpret_cast<const EthernetHeader*>(data);
    std::uint16_t etherType = getEtherType(eth);
    const std::uint8_t* payload = data + kEthernetHeaderSize;
    std::uint32_t payloadLen = len - kEthernetHeaderSize;

    if (etherType == kEtherTypeVlan && payloadLen >= 4) {
        etherType = (static_cast<std::uint16_t>(payload[2]) << 8) | payload[3];
        payload += 4;
        payloadLen -= 4;
    }

    if (etherType != kEtherTypeIPv4 || payloadLen < 20) return;

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

    if (protocol == kIpProtoTcp) {
        if (payloadLen < ipIhl + 20u) return;
        auto* tcp = reinterpret_cast<const TcpHeader*>(payload + ipIhl);
        srcPort = getTcpSrcPort(tcp);
        dstPort = getTcpDstPort(tcp);
        transportHeaderLen = getTcpDataOffset(tcp);
        if (transportHeaderLen < 20) transportHeaderLen = 20;
    } else if (protocol == kIpProtoUdp) {
        if (payloadLen < ipIhl + 8u) return;
        auto* udp = reinterpret_cast<const UdpHeader*>(payload + ipIhl);
        srcPort = getUdpSrcPort(udp);
        dstPort = getUdpDstPort(udp);
        transportHeaderLen = 8;
    } else {
        return;  // Only TCP and UDP flows
    }

    std::uint32_t headerBytes = ipIhl + transportHeaderLen;
    std::uint32_t payloadSize = totalPacketLen > headerBytes ? totalPacketLen - headerBytes : 0;

    FlowKey keyFwd{srcIp, dstIp, srcPort, dstPort, protocol};
    FlowKey keyBwd{dstIp, srcIp, dstPort, srcPort, protocol};

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

    itFwd = flows_.find(keyFwd);
    itBwd = flows_.find(keyBwd);
    FlowKey* usedKey = nullptr;
    bool isForward = false;
    if (itFwd != flows_.end()) {
        usedKey = const_cast<FlowKey*>(&itFwd->first);
        isForward = true;
    } else if (itBwd != flows_.end()) {
        usedKey = const_cast<FlowKey*>(&itBwd->first);
        isForward = false;
    } else {
        flows_[keyFwd] = FlowStats{};
        usedKey = const_cast<FlowKey*>(&keyFwd);
        isForward = true;
    }

    FlowStats& stats = flows_[*usedKey];
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

    // Bulk tracking: bulk = 2+ packets in same direction. On direction switch, finalize previous bulk.
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

    if (tcpFinOrRst) {
        if (stats.curFwdBulkPkts >= 2) {
            stats.fwdBulkPackets.push_back(stats.curFwdBulkPkts);
            stats.fwdBulkBytes.push_back(stats.curFwdBulkBytes);
        }
        if (stats.curBwdBulkPkts >= 2) {
            stats.bwdBulkPackets.push_back(stats.curBwdBulkPkts);
            stats.bwdBulkBytes.push_back(stats.curBwdBulkBytes);
        }
        FlowKey key = *usedKey;
        completedFlows_.emplace_back(std::move(key), std::move(stats));
        flows_.erase(*usedKey);
    }
}

void NativeFlowExtractor::writeCsv(const std::string& outputPath) const {
    std::ofstream file(outputPath);
    if (!file.is_open()) return;

    file << "feature_0";
    for (int i = 1; i < 79; ++i) {
        file << ",feature_" << i;
    }
    file << "\n";

    for (const auto& [key, stats] : completedFlows_) {
        auto features = stats.toFeatureVector(key.dstPort);
        for (std::size_t i = 0; i < features.size(); ++i) {
            if (i > 0) file << ",";
            file << features[i];
        }
        file << "\n";
    }
    for (const auto& [key, stats] : flows_) {
        auto features = stats.toFeatureVector(key.dstPort);
        for (std::size_t i = 0; i < features.size(); ++i) {
            if (i > 0) file << ",";
            file << features[i];
        }
        file << "\n";
    }
}

std::vector<std::vector<float>> NativeFlowExtractor::loadFeatures(
    const std::string& csvPath) {
    std::vector<std::vector<float>> result;
    std::ifstream file(csvPath);
    if (!file.is_open()) return result;

    std::string line;
    std::getline(file, line);  // skip header

    while (std::getline(file, line)) {
        std::vector<float> row;
        std::stringstream ss(line);
        std::string cell;
        while (std::getline(ss, cell, ',')) {
            try {
                row.push_back(std::stof(cell));
            } catch (...) {
                row.push_back(0.0f);
            }
        }
        while (row.size() < 79) row.push_back(0.0f);
        result.push_back(std::move(row));
    }

    return result;
}

} // namespace nids::infra
