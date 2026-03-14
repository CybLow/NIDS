#include "infra/flow/NativeFlowExtractor.h"

#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IcmpLayer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/VlanLayer.h>

#include <pcapplusplus/SystemUtils.h>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <concepts>
#include <numeric>
#include <ranges>

namespace nids::infra {

namespace {

// Standard IP protocol numbers
constexpr std::uint8_t kIpProtoIcmp = 1;
constexpr std::uint8_t kIpProtoTcp = 6;
constexpr std::uint8_t kIpProtoUdp = 17;

// TCP flag bitmasks (RFC 793)
constexpr std::uint8_t kTcpFin = 0x01;
constexpr std::uint8_t kTcpSyn = 0x02;
constexpr std::uint8_t kTcpRst = 0x04;
constexpr std::uint8_t kTcpPsh = 0x08;
constexpr std::uint8_t kTcpAck = 0x10;
constexpr std::uint8_t kTcpUrg = 0x20;
constexpr std::uint8_t kTcpCwr = 0x80;
constexpr std::uint8_t kTcpEce = 0x40;

constexpr std::int64_t kIdleThresholdUs =
    5'000'000; // 5 seconds (standard idle threshold)
constexpr std::int64_t kDefaultFlowTimeoutUs = 600'000'000; // 600 seconds

template <std::ranges::sized_range Container>
  requires std::is_arithmetic_v<std::ranges::range_value_t<Container>>
double mean(const Container &c) {
  if (c.empty())
    return 0.0;
  double sum =
      std::accumulate(c.begin(), c.end(), 0.0, [](double acc, auto val) {
        return acc + static_cast<double>(val);
      });
  return sum / static_cast<double>(c.size());
}

template <std::ranges::sized_range Container>
  requires std::is_arithmetic_v<std::ranges::range_value_t<Container>>
double stddev(const Container &c) {
  if (c.size() <= 1)
    return 0.0;
  double m = mean(c);
  double accum = std::transform_reduce(
      c.begin(), c.end(), 0.0, std::plus<>{}, [m](auto val) {
        double d = static_cast<double>(val) - m;
        return d * d;
      });
  return std::sqrt(accum / static_cast<double>(c.size() - 1));
}

template <std::ranges::sized_range Container>
  requires std::is_arithmetic_v<std::ranges::range_value_t<Container>>
double variance(const Container &c) {
  if (c.size() <= 1)
    return 0.0;
  double m = mean(c);
  double accum = std::transform_reduce(
      c.begin(), c.end(), 0.0, std::plus<>{}, [m](auto val) {
        double d = static_cast<double>(val) - m;
        return d * d;
      });
  return accum / static_cast<double>(c.size());
}

void pushLengthStats(std::vector<float> &features,
                     const std::vector<std::uint32_t> &lengths) {
  if (lengths.empty()) {
    features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f});
  } else {
    features.push_back(static_cast<float>(std::ranges::max(lengths)));
    features.push_back(static_cast<float>(std::ranges::min(lengths)));
    features.push_back(static_cast<float>(mean(lengths)));
    features.push_back(static_cast<float>(stddev(lengths)));
  }
}

void pushIatStats(std::vector<float> &features,
                  const std::vector<std::int64_t> &iats) {
  if (iats.empty()) {
    features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f, 0.0f});
  } else {
    double totalUs = std::accumulate(
        iats.begin(), iats.end(), 0.0,
        [](double acc, auto val) { return acc + static_cast<double>(val); });
    features.push_back(static_cast<float>(totalUs));
    features.push_back(static_cast<float>(mean(iats)));
    features.push_back(static_cast<float>(stddev(iats)));
    features.push_back(static_cast<float>(std::ranges::max(iats)));
    features.push_back(static_cast<float>(std::ranges::min(iats)));
  }
}

/// Push a rate = count / durationSec if duration > 0, else push 0.
void pushRate(std::vector<float> &features, double count, double durationUs) {
  features.push_back(
      durationUs > 0 ? static_cast<float>(count / (durationUs / 1e6)) : 0.0f);
}

/// Push min/max/mean/std/variance stats for a uint32 container, or 5 zeros if
/// empty.
void pushFullLengthStats(std::vector<float> &features,
                         const std::vector<std::uint32_t> &lengths) {
  if (lengths.empty()) {
    features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f, 0.0f});
  } else {
    features.push_back(static_cast<float>(std::ranges::min(lengths)));
    features.push_back(static_cast<float>(std::ranges::max(lengths)));
    features.push_back(static_cast<float>(mean(lengths)));
    features.push_back(static_cast<float>(stddev(lengths)));
    features.push_back(static_cast<float>(variance(lengths)));
  }
}

/// Push 4 period stats (mean, std, max, min) or 4 zeros if empty.
void pushPeriodStats(std::vector<float> &features,
                     const std::vector<std::int64_t> &periods) {
  if (periods.empty()) {
    features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f});
  } else {
    features.push_back(static_cast<float>(mean(periods)));
    features.push_back(static_cast<float>(stddev(periods)));
    features.push_back(static_cast<float>(std::ranges::max(periods)));
    features.push_back(static_cast<float>(std::ranges::min(periods)));
  }
}

/// Push bulk statistics (avg bytes/bulk, avg packets/bulk, bulk rate) or 3
/// zeros if empty.
void pushBulkStats(std::vector<float> &features,
                   const std::vector<std::uint32_t> &bulkBytes,
                   const std::vector<std::uint32_t> &bulkPackets,
                   double durationUs) {
  if (bulkBytes.empty()) {
    features.insert(features.end(), {0.0f, 0.0f, 0.0f});
  } else {
    features.push_back(static_cast<float>(mean(bulkBytes)));
    features.push_back(static_cast<float>(mean(bulkPackets)));
    double totalBulkBytes = std::accumulate(
        bulkBytes.begin(), bulkBytes.end(), 0.0,
        [](double acc, auto val) { return acc + static_cast<double>(val); });
    features.push_back(
        durationUs > 0 ? static_cast<float>(totalBulkBytes / (durationUs / 1e6))
                       : 0.0f);
  }
}

/// Push a safe ratio = numerator / denominator, or 0 if denominator is 0.
void pushRatio(std::vector<float> &features, double numerator,
               double denominator) {
  features.push_back(
      denominator > 0 ? static_cast<float>(numerator / denominator) : 0.0f);
}

/// Build a FlowInfo metadata record from a flow key and accumulated stats.
nids::core::FlowInfo buildFlowInfo(const FlowKey &key, const FlowStats &stats) {
  nids::core::FlowInfo info;
  info.srcIp = key.srcIp;
  info.dstIp = key.dstIp;
  info.srcPort = key.srcPort;
  info.dstPort = key.dstPort;
  info.protocol = key.protocol;

  info.totalFwdPackets = stats.totalFwdPackets;
  info.totalBwdPackets = stats.totalBwdPackets;

  auto durationUs = static_cast<double>(stats.lastTimeUs - stats.startTimeUs);
  info.flowDurationUs = durationUs;

  if (durationUs > 0.0) {
    double durationSec = durationUs / 1'000'000.0;
    info.fwdPacketsPerSecond =
        static_cast<double>(stats.totalFwdPackets) / durationSec;
    info.bwdPacketsPerSecond =
        static_cast<double>(stats.totalBwdPackets) / durationSec;
  }

  info.synFlagCount = stats.synCount;
  info.ackFlagCount = stats.ackCount;
  info.rstFlagCount = stats.rstCount;
  info.finFlagCount = stats.finCount;

  auto totalPackets = stats.totalFwdPackets + stats.totalBwdPackets;
  auto totalBytes = stats.totalFwdBytes + stats.totalBwdBytes;
  if (totalPackets > 0) {
    info.avgPacketSize =
        static_cast<double>(totalBytes) / static_cast<double>(totalPackets);
  }

  return info;
}

} // anonymous namespace

const std::vector<std::string> &flowFeatureNames() {
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
  assert(names.size() == static_cast<std::size_t>(kFlowFeatureCount) &&
         "flowFeatureNames() size must match kFlowFeatureCount");
  return names;
}

NativeFlowExtractor::NativeFlowExtractor()
    : flowTimeoutUs_(kDefaultFlowTimeoutUs) {}

void NativeFlowExtractor::setFlowTimeout(std::int64_t timeoutUs) {
  flowTimeoutUs_ = timeoutUs;
}

std::vector<float> FlowStats::toFeatureVector(std::uint16_t dstPort) const {
  std::vector<float> features;
  features.reserve(kFlowFeatureCount);

  auto durationUs = static_cast<double>(lastTimeUs - startTimeUs);
  if (durationUs < 0)
    durationUs = 0;

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
  pushRate(features, static_cast<double>(totalFwdBytes + totalBwdBytes),
           durationUs);
  pushRate(features, static_cast<double>(totalFwdPackets + totalBwdPackets),
           durationUs);
  // 16-19: Flow IAT Mean, Std, Max, Min
  pushPeriodStats(features, flowIatUs);
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
  pushRate(features, static_cast<double>(totalFwdPackets), durationUs);
  pushRate(features, static_cast<double>(totalBwdPackets), durationUs);
  // 38-42: Packet Length Min, Max, Mean, Std, Variance (all packets)
  pushFullLengthStats(features, allPacketLengths);
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
  pushRatio(features, static_cast<double>(totalBwdPackets),
            static_cast<double>(totalFwdPackets));
  // 52: Average Packet Size
  std::uint64_t totalPackets = totalFwdPackets + totalBwdPackets;
  std::uint64_t totalBytes = totalFwdBytes + totalBwdBytes;
  pushRatio(features, static_cast<double>(totalBytes),
            static_cast<double>(totalPackets));
  // 53-54: Fwd Segment Size Avg, Bwd Segment Size Avg
  pushRatio(features, static_cast<double>(totalFwdBytes - fwdHeaderBytes),
            static_cast<double>(totalFwdPackets));
  pushRatio(features, static_cast<double>(totalBwdBytes - bwdHeaderBytes),
            static_cast<double>(totalBwdPackets));
  // 55-57: Fwd Bytes/Bulk Avg, Fwd Packet/Bulk Avg, Fwd Bulk Rate Avg
  pushBulkStats(features, fwdBulkBytes, fwdBulkPackets, durationUs);
  // 58-60: Bwd Bytes/Bulk Avg, Bwd Packet/Bulk Avg, Bwd Bulk Rate Avg
  pushBulkStats(features, bwdBulkBytes, bwdBulkPackets, durationUs);
  // 61-64: Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow
  // Bwd Bytes
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
  pushPeriodStats(features, activePeriodsUs);
  // 73-76: Idle Mean, Std, Max, Min
  pushPeriodStats(features, idlePeriodsUs);

  assert(features.size() == static_cast<std::size_t>(kFlowFeatureCount) &&
         "toFeatureVector() output size must match kFlowFeatureCount");
  return features;
}

std::vector<std::vector<float>>
NativeFlowExtractor::extractFeatures(const std::string &pcapPath) {
  pcpp::PcapFileReaderDevice reader(pcapPath);
  if (!reader.open()) {
    spdlog::error("Cannot open pcap file: {}", pcapPath);
    return {};
  }

  flows_.clear();
  completedFlows_.clear();
  pcpp::RawPacket rawPacket;

  while (reader.getNextPacket(rawPacket)) {
    auto ts = rawPacket.getPacketTimeStamp();
    std::int64_t tsUs = static_cast<std::int64_t>(ts.tv_sec) * 1'000'000 +
                        static_cast<std::int64_t>(ts.tv_nsec) / 1'000;
    processPacket(rawPacket, tsUs);
  }

  finalizeBulks();
  buildFlowMetadata();
  return buildFeatureVectors();
}

void NativeFlowExtractor::finalizeBulks() {
  for (auto &[key, stats] : flows_) {
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

bool NativeFlowExtractor::parsePacketHeaders(pcpp::Packet &packet,
                                             ParsedPacket &pkt) {
  // PcapPlusPlus automatically handles VLAN (802.1Q) tag parsing
  auto *ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
  if (!ipLayer)
    return false;

  pkt.srcIp = ipLayer->getSrcIPv4Address().toString();
  pkt.dstIp = ipLayer->getDstIPv4Address().toString();
  pkt.ipIhl = ipLayer->getHeaderLen();
  pkt.protocol = ipLayer->getIPv4Header()->protocol;
  pkt.totalPacketLen = pcpp::netToHost16(ipLayer->getIPv4Header()->totalLength);

  if (pkt.protocol == kIpProtoTcp) {
    auto *tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcpLayer)
      return false;
    pkt.srcPort = tcpLayer->getSrcPort();
    pkt.dstPort = tcpLayer->getDstPort();
    pkt.transportHeaderLen = tcpLayer->getHeaderLen();
    if (pkt.transportHeaderLen < 20)
      pkt.transportHeaderLen = 20;

    // Extract TCP flags as a bitmask for flow stats
    auto *tcpHdr = tcpLayer->getTcpHeader();
    std::uint8_t flags = 0;
    if (tcpHdr->finFlag)
      flags |= kTcpFin;
    if (tcpHdr->synFlag)
      flags |= kTcpSyn;
    if (tcpHdr->rstFlag)
      flags |= kTcpRst;
    if (tcpHdr->pshFlag)
      flags |= kTcpPsh;
    if (tcpHdr->ackFlag)
      flags |= kTcpAck;
    if (tcpHdr->urgFlag)
      flags |= kTcpUrg;
    if (tcpHdr->cwrFlag)
      flags |= kTcpCwr;
    if (tcpHdr->eceFlag)
      flags |= kTcpEce;
    pkt.tcpFlags = flags;
    pkt.tcpWindow = pcpp::netToHost16(tcpHdr->windowSize);
  } else if (pkt.protocol == kIpProtoUdp) {
    auto *udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (!udpLayer)
      return false;
    pkt.srcPort = udpLayer->getSrcPort();
    pkt.dstPort = udpLayer->getDstPort();
    pkt.transportHeaderLen = 8;
  } else if (pkt.protocol == kIpProtoIcmp) {
    auto *icmpLayer = packet.getLayerOfType<pcpp::IcmpLayer>();
    if (!icmpLayer)
      return false;
    pkt.srcPort = icmpLayer->getIcmpHeader()->type;
    pkt.dstPort = 0;
    pkt.transportHeaderLen = 8;
  } else {
    return false; // Unsupported protocol
  }

  pkt.headerBytes = pkt.ipIhl + pkt.transportHeaderLen;
  pkt.payloadSize = pkt.totalPacketLen > pkt.headerBytes
                        ? pkt.totalPacketLen - pkt.headerBytes
                        : 0;
  return true;
}

void NativeFlowExtractor::processPacket(pcpp::RawPacket &rawPacket,
                                        std::int64_t timestampUs) {
  pcpp::Packet parsedPacket(&rawPacket);
  ParsedPacket pkt;
  if (!parsePacketHeaders(parsedPacket, pkt))
    return;

  FlowKey keyFwd{.srcIp = pkt.srcIp,
                 .dstIp = pkt.dstIp,
                 .srcPort = pkt.srcPort,
                 .dstPort = pkt.dstPort,
                 .protocol = pkt.protocol};
  FlowKey keyBwd{.srcIp = pkt.dstIp,
                 .dstIp = pkt.srcIp,
                 .srcPort = pkt.dstPort,
                 .dstPort = pkt.srcPort,
                 .protocol = pkt.protocol};

  auto [activeKey, isForward] = resolveFlow(keyFwd, keyBwd, timestampUs);

  FlowStats &stats = flows_[activeKey];
  if (stats.startTimeUs == 0) {
    stats.startTimeUs = timestampUs;
  }

  std::int64_t prevLastTimeUs = stats.lastTimeUs;
  std::int64_t flowGapUs =
      (prevLastTimeUs > 0) ? (timestampUs - prevLastTimeUs) : 0;
  if (flowGapUs > 0)
    stats.flowIatUs.push_back(flowGapUs);
  stats.lastTimeUs = timestampUs;

  updateDirectionStats(stats, pkt, timestampUs, isForward);
  stats.allPacketLengths.push_back(pkt.totalPacketLen);

  bool tcpFinOrRst = false;
  if (pkt.protocol == kIpProtoTcp) {
    tcpFinOrRst = (pkt.tcpFlags & (kTcpFin | kTcpRst)) != 0;
    updateTcpFlags(stats, pkt, isForward);
  }

  updateBulkTracking(stats, pkt.totalPacketLen, isForward);
  updateActiveIdle(stats, timestampUs, prevLastTimeUs, flowGapUs);

  if (tcpFinOrRst) {
    completeFlow(activeKey, stats);
    flows_.erase(activeKey);
    return;
  }

  // Max-flow-size splitting: prevent mega-flows from collapsing into a single
  // sample.
  auto totalPkts = stats.totalFwdPackets + stats.totalBwdPackets;
  if (totalPkts >= kMaxFlowPackets) {
    completeFlow(activeKey, stats);
    flows_[activeKey] = FlowStats{}; // Start new flow for same 5-tuple
  }
}

NativeFlowExtractor::FlowLookupResult
NativeFlowExtractor::resolveFlow(const FlowKey &keyFwd, const FlowKey &keyBwd,
                                 std::int64_t timestampUs) {
  // Evict timed-out flows
  if (auto it = flows_.find(keyFwd);
      it != flows_.end() &&
      timestampUs - it->second.lastTimeUs > flowTimeoutUs_) {
    completedFlows_.emplace_back(keyFwd, std::move(it->second));
    flows_.erase(it);
  }
  if (auto it = flows_.find(keyBwd);
      it != flows_.end() &&
      timestampUs - it->second.lastTimeUs > flowTimeoutUs_) {
    completedFlows_.emplace_back(keyBwd, std::move(it->second));
    flows_.erase(it);
  }

  // Determine direction
  if (flows_.contains(keyFwd)) {
    return {keyFwd, true};
  }
  if (flows_.contains(keyBwd)) {
    return {keyBwd, false};
  }
  return {keyFwd, true}; // New flow
}

void NativeFlowExtractor::updateDirectionStats(FlowStats &stats,
                                               const ParsedPacket &pkt,
                                               std::int64_t timestampUs,
                                               bool isForward) {
  if (isForward) {
    stats.totalFwdPackets++;
    stats.totalFwdBytes += pkt.totalPacketLen;
    stats.fwdPacketLengths.push_back(pkt.totalPacketLen);
    stats.fwdHeaderBytes += pkt.headerBytes;
    if (stats.lastFwdTimeUs >= 0) {
      stats.fwdIatUs.push_back(timestampUs - stats.lastFwdTimeUs);
    }
    stats.lastFwdTimeUs = timestampUs;
  } else {
    stats.totalBwdPackets++;
    stats.totalBwdBytes += pkt.totalPacketLen;
    stats.bwdPacketLengths.push_back(pkt.totalPacketLen);
    stats.bwdHeaderBytes += pkt.headerBytes;
    if (stats.lastBwdTimeUs >= 0) {
      std::int64_t iat = timestampUs - stats.lastBwdTimeUs;
      stats.bwdIatUs.push_back(iat);
      stats.flowIatUs.push_back(iat);
    }
    stats.lastBwdTimeUs = timestampUs;
  }
}

void NativeFlowExtractor::countGlobalTcpFlags(FlowStats &stats,
                                              std::uint8_t flags) {
  // Each flag maps to a counter — use a table to avoid 8 separate branches.
  struct FlagMapping {
    std::uint8_t mask;
    std::uint32_t FlowStats::*counter;
  };
  static constexpr std::array<FlagMapping, 8> kFlagMap = {{
      {kTcpFin, &FlowStats::finCount},
      {kTcpSyn, &FlowStats::synCount},
      {kTcpRst, &FlowStats::rstCount},
      {kTcpPsh, &FlowStats::pshCount},
      {kTcpAck, &FlowStats::ackCount},
      {kTcpUrg, &FlowStats::urgCount},
      {kTcpCwr, &FlowStats::cwrCount},
      {kTcpEce, &FlowStats::eceCount},
  }};

  for (const auto &[mask, counter] : kFlagMap) {
    if (flags & mask)
      ++(stats.*counter);
  }
}

void NativeFlowExtractor::updateFwdTcpState(FlowStats &stats,
                                            std::uint8_t flags,
                                            std::uint16_t win,
                                            std::uint32_t payloadSize) {
  if (flags & kTcpPsh)
    stats.fwdPshFlags++;
  if (flags & kTcpUrg)
    stats.fwdUrgFlags++;
  if (stats.fwdInitWinBytes == 0)
    stats.fwdInitWinBytes = win;
  if (payloadSize > 0) {
    stats.actDataPktFwd++;
    if (stats.minSegSizeForward == 0 || payloadSize < stats.minSegSizeForward) {
      stats.minSegSizeForward = payloadSize;
    }
  }
}

void NativeFlowExtractor::updateBwdTcpState(FlowStats &stats,
                                            std::uint8_t flags,
                                            std::uint16_t win) {
  if (flags & kTcpPsh)
    stats.bwdPshFlags++;
  if (flags & kTcpUrg)
    stats.bwdUrgFlags++;
  if (stats.bwdInitWinBytes == 0)
    stats.bwdInitWinBytes = win;
}

void NativeFlowExtractor::updateTcpFlags(FlowStats &stats,
                                         const ParsedPacket &pkt,
                                         bool isForward) {
  if (isForward) {
    updateFwdTcpState(stats, pkt.tcpFlags, pkt.tcpWindow, pkt.payloadSize);
  } else {
    updateBwdTcpState(stats, pkt.tcpFlags, pkt.tcpWindow);
  }

  countGlobalTcpFlags(stats, pkt.tcpFlags);
}

void NativeFlowExtractor::updateBulkTracking(FlowStats &stats,
                                             std::uint32_t packetLen,
                                             bool isForward) {
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
}

void NativeFlowExtractor::updateActiveIdle(FlowStats &stats,
                                           std::int64_t timestampUs,
                                           std::int64_t prevLastTimeUs,
                                           std::int64_t flowGapUs) {
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
}

void NativeFlowExtractor::completeFlow(const FlowKey &key, FlowStats &stats) {
  if (stats.curFwdBulkPkts >= 2) {
    stats.fwdBulkPackets.push_back(stats.curFwdBulkPkts);
    stats.fwdBulkBytes.push_back(stats.curFwdBulkBytes);
  }
  if (stats.curBwdBulkPkts >= 2) {
    stats.bwdBulkPackets.push_back(stats.curBwdBulkPkts);
    stats.bwdBulkBytes.push_back(stats.curBwdBulkBytes);
  }
  completedFlows_.emplace_back(key, std::move(stats));
}

const std::vector<nids::core::FlowInfo> &
NativeFlowExtractor::flowMetadata() const noexcept {
  return flowMetadata_;
}

void NativeFlowExtractor::buildFlowMetadata() {
  flowMetadata_.clear();
  flowMetadata_.reserve(completedFlows_.size() + flows_.size());

  for (const auto &[key, stats] : completedFlows_) {
    flowMetadata_.push_back(buildFlowInfo(key, stats));
  }
  for (const auto &[key, stats] : flows_) {
    flowMetadata_.push_back(buildFlowInfo(key, stats));
  }
}

std::vector<std::vector<float>>
NativeFlowExtractor::buildFeatureVectors() const {
  std::vector<std::vector<float>> result;
  result.reserve(completedFlows_.size() + flows_.size());

  for (const auto &[key, stats] : completedFlows_) {
    result.push_back(stats.toFeatureVector(key.dstPort));
  }
  for (const auto &[key, stats] : flows_) {
    result.push_back(stats.toFeatureVector(key.dstPort));
  }

  return result;
}

} // namespace nids::infra
