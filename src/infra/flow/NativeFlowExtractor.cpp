#include "infra/flow/NativeFlowExtractor.h"
#include "infra/capture/PcapHandle.h"
#include "infra/platform/NetworkHeaders.h"

#include <pcap.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <concepts>
#include <numeric>
#include <ranges>
// Note: std::ranges::fold_left (C++23) is not available under C++20.
// std::accumulate is used for reductions until the project adopts C++23.

namespace nids::infra {

namespace {

using nids::platform::EthernetHeader;
using nids::platform::getEtherType;
using nids::platform::getIpDstStr;
using nids::platform::getIpIhl;
using nids::platform::getIpProtocol;
using nids::platform::getIpSrcStr;
using nids::platform::getIpTotalLength;
using nids::platform::getTcpDataOffset;
using nids::platform::getTcpDstPort;
using nids::platform::getTcpFlags;
using nids::platform::getTcpSrcPort;
using nids::platform::getTcpWindow;
using nids::platform::getUdpDstPort;
using nids::platform::getUdpSrcPort;
using nids::platform::IcmpHeader;
using nids::platform::IPv4Header;
using nids::platform::kEthernetHeaderSize;
using nids::platform::kEtherTypeIPv4;
using nids::platform::kIcmpHeaderSize;
using nids::platform::kIpProtoIcmp;
using nids::platform::kIpProtoTcp;
using nids::platform::kIpProtoUdp;
using nids::platform::kTcpAck;
using nids::platform::kTcpCwr;
using nids::platform::kTcpEce;
using nids::platform::kTcpFin;
using nids::platform::kTcpPsh;
using nids::platform::kTcpRst;
using nids::platform::kTcpSyn;
using nids::platform::kTcpUrg;
using nids::platform::TcpHeader;
using nids::platform::UdpHeader;
constexpr std::int64_t kIdleThresholdUs =
    5'000'000; // 5 seconds (standard idle threshold)
constexpr std::int64_t kDefaultFlowTimeoutUs = 600'000'000; // 600 seconds
constexpr std::uint16_t kEtherTypeVlan = 0x8100;

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
  char errbuf[PCAP_ERRBUF_SIZE];
  auto handle = makePcapHandle(pcap_open_offline(pcapPath.c_str(), errbuf));
  if (!handle) {
    spdlog::error("Cannot open pcap file: {}", errbuf);
    return {};
  }

  flows_.clear();
  completedFlows_.clear();
  struct pcap_pkthdr *header;
  const unsigned char *data;

  while (pcap_next_ex(handle.get(), &header, &data) > 0) {
    std::int64_t tsUs = static_cast<std::int64_t>(header->ts.tv_sec) * 1000000 +
                        header->ts.tv_usec;
    processPacket(data, header->caplen, tsUs);
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

void NativeFlowExtractor::processPacket(const std::uint8_t *data,
                                        std::uint32_t len,
                                        std::int64_t timestampUs) {
  ParsedPacket pkt;
  if (!parsePacketHeaders(data, len, pkt))
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
    auto *tcp =
        reinterpret_cast<const TcpHeader *>(pkt.transportHeader); // NOSONAR
    std::uint8_t flags = getTcpFlags(tcp);
    tcpFinOrRst = (flags & (kTcpFin | kTcpRst)) != 0;
    updateTcpFlags(stats, pkt.transportHeader - pkt.ipIhl, pkt.ipIhl,
                   pkt.payloadSize, isForward);
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

bool NativeFlowExtractor::parseEthernetAndIp(
    const std::uint8_t *data, std::uint32_t len, ParsedPacket &pkt,
    const std::uint8_t *&transportStart, std::uint32_t &remainingLen) {
  if (len < static_cast<std::uint32_t>(kEthernetHeaderSize))
    return false;

  auto *eth = reinterpret_cast<const EthernetHeader *>(data); // NOSONAR
  std::uint16_t etherType = getEtherType(eth);
  const std::uint8_t *payload = data + kEthernetHeaderSize;
  std::uint32_t payloadLen =
      len - static_cast<std::uint32_t>(kEthernetHeaderSize);

  if (etherType == kEtherTypeVlan && payloadLen >= 4) {
    etherType = (static_cast<std::uint16_t>(payload[2]) << 8) | payload[3];
    payload += 4;
    payloadLen -= 4;
  }

  if (etherType != kEtherTypeIPv4 || payloadLen < 20)
    return false;

  auto *ip = reinterpret_cast<const IPv4Header *>(payload);
  pkt.ipIhl = getIpIhl(ip);
  pkt.protocol = getIpProtocol(ip);
  std::uint32_t ipTotalLen = getIpTotalLength(ip);
  if (payloadLen < pkt.ipIhl || ipTotalLen < pkt.ipIhl)
    return false;

  pkt.srcIp = getIpSrcStr(ip);
  pkt.dstIp = getIpDstStr(ip);
  pkt.totalPacketLen = ipTotalLen;
  transportStart = payload + pkt.ipIhl;
  remainingLen = payloadLen;
  return true;
}

bool NativeFlowExtractor::parseTransportHeader(
    ParsedPacket &pkt, const std::uint8_t *transportStart,
    std::uint32_t payloadLen) {
  if (pkt.protocol == kIpProtoTcp) {
    if (payloadLen < pkt.ipIhl + 20u)
      return false;
    auto *tcp = reinterpret_cast<const TcpHeader *>(transportStart);
    pkt.srcPort = getTcpSrcPort(tcp);
    pkt.dstPort = getTcpDstPort(tcp);
    pkt.transportHeaderLen = getTcpDataOffset(tcp);
    if (pkt.transportHeaderLen < 20)
      pkt.transportHeaderLen = 20;
    pkt.transportHeader = transportStart;
  } else if (pkt.protocol == kIpProtoUdp) {
    if (payloadLen < pkt.ipIhl + 8u)
      return false;
    auto *udp = reinterpret_cast<const UdpHeader *>(transportStart);
    pkt.srcPort = getUdpSrcPort(udp);
    pkt.dstPort = getUdpDstPort(udp);
    pkt.transportHeaderLen = 8;
    pkt.transportHeader = transportStart;
  } else if (pkt.protocol == kIpProtoIcmp) {
    if (payloadLen < pkt.ipIhl + static_cast<std::uint32_t>(kIcmpHeaderSize))
      return false;
    auto *icmp = reinterpret_cast<const IcmpHeader *>(transportStart);
    pkt.srcPort = icmp->type;
    pkt.dstPort = 0;
    pkt.transportHeaderLen = static_cast<std::uint32_t>(kIcmpHeaderSize);
    pkt.transportHeader = transportStart;
  } else {
    return false; // Unsupported protocol
  }
  return true;
}

bool NativeFlowExtractor::parsePacketHeaders(const std::uint8_t *data,
                                             std::uint32_t len,
                                             ParsedPacket &pkt) {
  const std::uint8_t *transportStart = nullptr;
  std::uint32_t remainingLen = 0;

  if (!parseEthernetAndIp(data, len, pkt, transportStart, remainingLen))
    return false;
  if (!parseTransportHeader(pkt, transportStart, remainingLen))
    return false;

  pkt.headerBytes = pkt.ipIhl + pkt.transportHeaderLen;
  pkt.payloadSize = pkt.totalPacketLen > pkt.headerBytes
                        ? pkt.totalPacketLen - pkt.headerBytes
                        : 0;
  return true;
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
                                         const std::uint8_t *ipPayload,
                                         std::uint32_t ipIhl,
                                         std::uint32_t payloadSize,
                                         bool isForward) {
  auto *tcp = reinterpret_cast<const TcpHeader *>(ipPayload + ipIhl);
  std::uint8_t flags = getTcpFlags(tcp);
  std::uint16_t win = getTcpWindow(tcp);

  if (isForward) {
    updateFwdTcpState(stats, flags, win, payloadSize);
  } else {
    updateBwdTcpState(stats, flags, win);
  }

  countGlobalTcpFlags(stats, flags);
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
