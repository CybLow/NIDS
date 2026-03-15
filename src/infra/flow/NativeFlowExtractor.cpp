#include "infra/flow/NativeFlowExtractor.h"

#include "core/services/Configuration.h"

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

#include <array>
#include <cassert>
#include <cmath>
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

/// Interval between periodic sweeps during batch pcap processing.
/// Triggered when the packet timestamp has advanced by at least this amount
/// since the last sweep.  30 seconds balances memory savings against the
/// O(n) sweep cost.
constexpr std::int64_t kBatchSweepIntervalUs = 30'000'000; // 30 seconds

/// Interval between periodic sweeps during live capture.
/// Shorter than batch mode to provide more responsive flow detection —
/// idle flows are expired sooner, producing timely results for the UI.
/// 5 seconds is cheap: typical flow tables have <1000 entries, so
/// O(n) sweeps at this frequency are negligible.
constexpr std::int64_t kLiveSweepIntervalUs = 5'000'000; // 5 seconds

/// Push max, min, mean, std from an accumulator, or 4 zeros if empty.
void pushLengthStats(std::vector<float> &features,
                     const WelfordAccumulator &acc) {
  if (acc.n == 0) {
    features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f});
  } else {
    features.push_back(static_cast<float>(acc.max()));
    features.push_back(static_cast<float>(acc.min()));
    features.push_back(static_cast<float>(acc.mean()));
    features.push_back(static_cast<float>(acc.stddev()));
  }
}

/// Push total, mean, std, max, min from an accumulator, or 5 zeros if empty.
void pushIatStats(std::vector<float> &features,
                  const WelfordAccumulator &acc) {
  if (acc.n == 0) {
    features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f, 0.0f});
  } else {
    features.push_back(static_cast<float>(acc.sum()));
    features.push_back(static_cast<float>(acc.mean()));
    features.push_back(static_cast<float>(acc.stddev()));
    features.push_back(static_cast<float>(acc.max()));
    features.push_back(static_cast<float>(acc.min()));
  }
}

/// Push a rate = count / durationSec if duration > 0, else push 0.
void pushRate(std::vector<float> &features, double count, double durationUs) {
  features.push_back(
      durationUs > 0 ? static_cast<float>(count / (durationUs / 1e6)) : 0.0f);
}

/// Push min, max, mean, std, variance from an accumulator, or 5 zeros.
void pushFullLengthStats(std::vector<float> &features,
                         const WelfordAccumulator &acc) {
  if (acc.n == 0) {
    features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f, 0.0f});
  } else {
    features.push_back(static_cast<float>(acc.min()));
    features.push_back(static_cast<float>(acc.max()));
    features.push_back(static_cast<float>(acc.mean()));
    features.push_back(static_cast<float>(acc.stddev()));
    features.push_back(static_cast<float>(acc.populationVariance()));
  }
}

/// Push mean, std, max, min from an accumulator, or 4 zeros if empty.
void pushPeriodStats(std::vector<float> &features,
                     const WelfordAccumulator &acc) {
  if (acc.n == 0) {
    features.insert(features.end(), {0.0f, 0.0f, 0.0f, 0.0f});
  } else {
    features.push_back(static_cast<float>(acc.mean()));
    features.push_back(static_cast<float>(acc.stddev()));
    features.push_back(static_cast<float>(acc.max()));
    features.push_back(static_cast<float>(acc.min()));
  }
}

/// Push avg bytes/bulk, avg packets/bulk, bulk rate, or 3 zeros.
void pushBulkStats(std::vector<float> &features,
                   const WelfordAccumulator &bytesAcc,
                   const WelfordAccumulator &pktsAcc,
                   double durationUs) {
  if (bytesAcc.n == 0) {
    features.insert(features.end(), {0.0f, 0.0f, 0.0f});
  } else {
    features.push_back(static_cast<float>(bytesAcc.mean()));
    features.push_back(static_cast<float>(pktsAcc.mean()));
    features.push_back(
        durationUs > 0
            ? static_cast<float>(bytesAcc.sum() / (durationUs / 1e6))
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
    : flowTimeoutUs_(core::Configuration::instance().flowTimeoutUs()),
      maxFlowDurationUs_(core::Configuration::instance().maxFlowDurationUs()),
      idleThresholdUs_(core::Configuration::instance().idleThresholdUs()) {}

void NativeFlowExtractor::setFlowCompletionCallback(
    core::IFlowExtractor::FlowCompletionCallback cb) {
  flowCompletionCallback_ = std::move(cb);
}

void NativeFlowExtractor::setFlowTimeout(std::int64_t timeoutUs) {
  flowTimeoutUs_ = timeoutUs;
}

void NativeFlowExtractor::setMaxFlowDuration(std::int64_t durationUs) {
  maxFlowDurationUs_ = durationUs;
}

std::size_t NativeFlowExtractor::sweepExpiredFlows(std::int64_t nowUs) {
  std::size_t swept = 0;
  for (auto it = flows_.begin(); it != flows_.end();) {
    if (nowUs - it->second.lastTimeUs > flowTimeoutUs_) {
      ++diag_.flowsCompletedTimeout;
      completeFlow(it->first, it->second);
      it = flows_.erase(it);
      ++swept;
    } else {
      ++it;
    }
  }
  if (swept > 0) {
    spdlog::debug("sweepExpiredFlows: expired {} idle flows ({} active remain)",
                  swept, flows_.size());
  }
  return swept;
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
  pushLengthStats(features, fwdLengthAcc);
  // 10-13: Bwd Packet Length Max, Min, Mean, Std
  pushLengthStats(features, bwdLengthAcc);
  // 14-15: Flow Bytes/s, Flow Packets/s
  pushRate(features, static_cast<double>(totalFwdBytes + totalBwdBytes),
           durationUs);
  pushRate(features, static_cast<double>(totalFwdPackets + totalBwdPackets),
           durationUs);
  // 16-19: Flow IAT Mean, Std, Max, Min
  pushPeriodStats(features, flowIatAcc);
  // 20-24: Fwd IAT Total, Mean, Std, Max, Min
  pushIatStats(features, fwdIatAcc);
  // 25-29: Bwd IAT Total, Mean, Std, Max, Min
  pushIatStats(features, bwdIatAcc);
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
  pushFullLengthStats(features, allLengthAcc);
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
  pushBulkStats(features, fwdBulkBytesAcc, fwdBulkPktsAcc, durationUs);
  // 58-60: Bwd Bytes/Bulk Avg, Bwd Packet/Bulk Avg, Bwd Bulk Rate Avg
  pushBulkStats(features, bwdBulkBytesAcc, bwdBulkPktsAcc, durationUs);
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
  pushPeriodStats(features, activeAcc);
  // 73-76: Idle Mean, Std, Max, Min
  pushPeriodStats(features, idleAcc);

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

  reset();
  pcpp::RawPacket rawPacket;

  while (reader.getNextPacket(rawPacket)) {
    auto ts = rawPacket.getPacketTimeStamp();
    auto tsUs =
        std::int64_t{ts.tv_sec} * 1'000'000 + std::int64_t{ts.tv_nsec} / 1'000;
    processPacketInternal(rawPacket, tsUs);

    // Periodic sweep: expire idle flows every kBatchSweepIntervalUs.
    if (tsUs - lastSweepTimeUs_ >= kBatchSweepIntervalUs) {
      sweepExpiredFlows(tsUs);
      lastSweepTimeUs_ = tsUs;
    }
  }

  // Finalize remaining active flows: flush bulk stats, fire callbacks,
  // and move to completedFlows_ for batch feature vector construction.
  for (auto &[key, stats] : flows_) {
    completeFlow(key, stats);
  }
  flows_.clear();

  buildFlowMetadata();
  return buildFeatureVectors();
}

void NativeFlowExtractor::processPacket(const std::uint8_t *data,
                                        std::size_t length,
                                        std::int64_t timestampUs) {
  liveMode_ = true;
  ++diag_.packetsReceived;

  // Construct a timeval for PcapPlusPlus RawPacket.
  timespec ts{};
  ts.tv_sec = static_cast<time_t>(timestampUs / 1'000'000);
  ts.tv_nsec = static_cast<long>((timestampUs % 1'000'000) * 1'000);

  // RawPacket with deleteRawDataOnDestruct=false: we do not own the data.
  // The const_cast is required because PcapPlusPlus RawPacket stores a
  // non-const pointer internally, but does not modify the data when
  // deleteRawDataOnDestruct is false.
  pcpp::RawPacket rawPacket(
      const_cast<std::uint8_t *>(data),  // NOLINT(cppcoreguidelines-pro-type-const-cast)
      static_cast<int>(length), ts, false);

  processPacketInternal(rawPacket, timestampUs);

  // Periodic sweep: expire idle flows every kLiveSweepIntervalUs.
  if (timestampUs - lastSweepTimeUs_ >= kLiveSweepIntervalUs) {
    ++diag_.sweepCount;
    sweepExpiredFlows(timestampUs);
    lastSweepTimeUs_ = timestampUs;
  }
}

void NativeFlowExtractor::finalizeAllFlows() {
  spdlog::info("finalizeAllFlows: {} active flows remaining", flows_.size());
  diag_.flowsCompletedFinalize += flows_.size();
  for (auto &[key, stats] : flows_) {
    completeFlow(key, stats);
  }
  flows_.clear();
  logDiagnostics();
}

void NativeFlowExtractor::reset() {
  flows_.clear();
  completedFlows_.clear();
  flowMetadata_.clear();
  lastSweepTimeUs_ = 0;
  liveMode_ = false;
  diag_ = DiagCounters{};
}

void NativeFlowExtractor::logDiagnostics() const {
  auto totalCompleted = diag_.flowsCompletedFinRst +
                        diag_.flowsCompletedMaxPkts +
                        diag_.flowsCompletedTimeout +
                        diag_.flowsCompletedDuration +
                        diag_.flowsCompletedFinalize;

  spdlog::info("=== NativeFlowExtractor Diagnostics ===");
  spdlog::info("  Packets received:       {}", diag_.packetsReceived);
  spdlog::info("  Packets parsed (IPv4):  {}", diag_.packetsParsed);
  spdlog::info("  Packets skipped:        {}", diag_.packetsSkipped);
  spdlog::info("  Active flows remaining: {}", flows_.size());
  spdlog::info("  Total flows completed:  {}", totalCompleted);
  spdlog::info("    - TCP FIN/RST:        {}", diag_.flowsCompletedFinRst);
  spdlog::info("    - Max packets ({}):  {}", kMaxFlowPackets,
               diag_.flowsCompletedMaxPkts);
  spdlog::info("    - Idle timeout:       {}", diag_.flowsCompletedTimeout);
  spdlog::info("    - Duration split:     {}", diag_.flowsCompletedDuration);
  spdlog::info("    - Finalized at stop:  {}", diag_.flowsCompletedFinalize);
  spdlog::info("  Sweep passes:           {}", diag_.sweepCount);
  spdlog::info("  Max flow duration:      {}s", maxFlowDurationUs_ / 1'000'000);
  spdlog::info("=======================================");
}

// finalizeBulks() removed — replaced by completeFlow() loop in
// extractFeatures() and finalizeAllFlows().

/// Extract TCP flags from a TCP header into a bitmask.
[[nodiscard]] static std::uint8_t
extractTcpFlags(const pcpp::tcphdr *hdr) noexcept {
  std::uint8_t flags = 0;
  if (hdr->finFlag)
    flags |= kTcpFin;
  if (hdr->synFlag)
    flags |= kTcpSyn;
  if (hdr->rstFlag)
    flags |= kTcpRst;
  if (hdr->pshFlag)
    flags |= kTcpPsh;
  if (hdr->ackFlag)
    flags |= kTcpAck;
  if (hdr->urgFlag)
    flags |= kTcpUrg;
  if (hdr->cwrFlag)
    flags |= kTcpCwr;
  if (hdr->eceFlag)
    flags |= kTcpEce;
  return flags;
}

bool NativeFlowExtractor::parsePacketHeaders(const pcpp::Packet &packet,
                                             ParsedPacket &pkt) {
  // PcapPlusPlus automatically handles VLAN (802.1Q) tag parsing
  const auto *ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
  if (!ipLayer)
    return false;

  pkt.srcIp = ipLayer->getSrcIPv4Address().toString();
  pkt.dstIp = ipLayer->getDstIPv4Address().toString();
  pkt.ipIhl = static_cast<std::uint32_t>(ipLayer->getHeaderLen());
  pkt.protocol = ipLayer->getIPv4Header()->protocol;
  pkt.totalPacketLen = pcpp::netToHost16(ipLayer->getIPv4Header()->totalLength);

  if (pkt.protocol == kIpProtoTcp) {
    const auto *tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcpLayer)
      return false;
    pkt.srcPort = tcpLayer->getSrcPort();
    pkt.dstPort = tcpLayer->getDstPort();
    pkt.transportHeaderLen =
        static_cast<std::uint32_t>(tcpLayer->getHeaderLen());
    if (pkt.transportHeaderLen < 20)
      pkt.transportHeaderLen = 20;

    const auto *tcpHdr = tcpLayer->getTcpHeader();
    pkt.tcpFlags = extractTcpFlags(tcpHdr);
    pkt.tcpWindow = pcpp::netToHost16(tcpHdr->windowSize);
  } else if (pkt.protocol == kIpProtoUdp) {
    const auto *udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (!udpLayer)
      return false;
    pkt.srcPort = udpLayer->getSrcPort();
    pkt.dstPort = udpLayer->getDstPort();
    pkt.transportHeaderLen = 8;
  } else if (pkt.protocol == kIpProtoIcmp) {
    const auto *icmpLayer = packet.getLayerOfType<pcpp::IcmpLayer>();
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

void NativeFlowExtractor::processPacketInternal(pcpp::RawPacket &rawPacket,
                                                std::int64_t timestampUs) {
  pcpp::Packet parsedPacket(&rawPacket);
  ParsedPacket pkt;
  if (!parsePacketHeaders(parsedPacket, pkt)) {
    ++diag_.packetsSkipped;
    return;
  }
  ++diag_.packetsParsed;

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
    stats.flowIatAcc.update(static_cast<double>(flowGapUs));
  stats.lastTimeUs = timestampUs;

  updateDirectionStats(stats, pkt, timestampUs, isForward);
  stats.allLengthAcc.update(pkt.totalPacketLen);

  bool tcpFinOrRst = false;
  if (pkt.protocol == kIpProtoTcp) {
    tcpFinOrRst = (pkt.tcpFlags & (kTcpFin | kTcpRst)) != 0;
    updateTcpFlags(stats, pkt, isForward);
  }

  updateBulkTracking(stats, pkt.totalPacketLen, isForward);
  updateActiveIdle(stats, timestampUs, prevLastTimeUs, flowGapUs,
                   idleThresholdUs_);

  if (tcpFinOrRst) {
    ++diag_.flowsCompletedFinRst;
    completeFlow(activeKey, stats);
    flows_.erase(activeKey);
    return;
  }

  // Max-flow-size splitting: prevent mega-flows from collapsing into a single
  // sample.
  auto totalPkts = stats.totalFwdPackets + stats.totalBwdPackets;
  if (totalPkts >= kMaxFlowPackets) {
    ++diag_.flowsCompletedMaxPkts;
    completeFlow(activeKey, stats);
    // Restart flow for same 5-tuple.  Seed start/last timestamps so the
    // new flow isn't immediately expired by the next sweep.
    auto &fresh = (flows_[activeKey] = FlowStats{});
    fresh.startTimeUs = timestampUs;
    fresh.lastTimeUs = timestampUs;
    return;
  }

  // Time-window splitting (live mode only): long-lived connections (HTTP/2,
  // WebSocket, SSH, tunnels) must produce periodic ML verdicts rather than
  // accumulating indefinitely.  When a flow exceeds maxFlowDurationUs_,
  // complete it and restart with fresh stats.  This is critical for inline
  // IPS mode where blocking decisions must be made promptly.
  //
  // Disabled in batch mode (extractFeatures) where all flows are finalized
  // at end-of-file anyway.
  if (liveMode_ && maxFlowDurationUs_ > 0 &&
      (timestampUs - stats.startTimeUs) >= maxFlowDurationUs_) {
    ++diag_.flowsCompletedDuration;
    completeFlow(activeKey, stats);
    auto &fresh = (flows_[activeKey] = FlowStats{});
    fresh.startTimeUs = timestampUs;
    fresh.lastTimeUs = timestampUs;
  }
}

NativeFlowExtractor::FlowLookupResult
NativeFlowExtractor::resolveFlow(const FlowKey &keyFwd, const FlowKey &keyBwd,
                                 std::int64_t timestampUs) {
  // Evict timed-out flows — use completeFlow() so the flow completion
  // callback fires (required for live detection pipeline).
  if (auto it = flows_.find(keyFwd);
      it != flows_.end() &&
      timestampUs - it->second.lastTimeUs > flowTimeoutUs_) {
    ++diag_.flowsCompletedTimeout;
    completeFlow(it->first, it->second);
    flows_.erase(it);
  }
  if (auto it = flows_.find(keyBwd);
      it != flows_.end() &&
      timestampUs - it->second.lastTimeUs > flowTimeoutUs_) {
    ++diag_.flowsCompletedTimeout;
    completeFlow(it->first, it->second);
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
    stats.fwdLengthAcc.update(pkt.totalPacketLen);
    stats.fwdHeaderBytes += pkt.headerBytes;
    if (stats.lastFwdTimeUs >= 0) {
      stats.fwdIatAcc.update(
          static_cast<double>(timestampUs - stats.lastFwdTimeUs));
    }
    stats.lastFwdTimeUs = timestampUs;
  } else {
    stats.totalBwdPackets++;
    stats.totalBwdBytes += pkt.totalPacketLen;
    stats.bwdLengthAcc.update(pkt.totalPacketLen);
    stats.bwdHeaderBytes += pkt.headerBytes;
    if (stats.lastBwdTimeUs >= 0) {
      stats.bwdIatAcc.update(
          static_cast<double>(timestampUs - stats.lastBwdTimeUs));
      // NOTE: backward IAT is NOT added to flowIatAcc here.
      // The overall flow IAT is already tracked in processPacket()
      // as the gap between any two consecutive packets.
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
      stats.bwdBulkPktsAcc.update(stats.curBwdBulkPkts);
      stats.bwdBulkBytesAcc.update(stats.curBwdBulkBytes);
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
      stats.fwdBulkPktsAcc.update(stats.curFwdBulkPkts);
      stats.fwdBulkBytesAcc.update(stats.curFwdBulkBytes);
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
                                             std::int64_t flowGapUs,
                                             std::int64_t idleThresholdUs) {
  if (flowGapUs > idleThresholdUs && prevLastTimeUs > 0) {
    if (stats.lastActiveTimeUs >= 0) {
      stats.activeAcc.update(
          static_cast<double>(prevLastTimeUs - stats.lastActiveTimeUs));
    }
    stats.lastIdleTimeUs = prevLastTimeUs;
    stats.lastActiveTimeUs = -1;
  }
  if (stats.lastIdleTimeUs >= 0) {
    stats.idleAcc.update(
        static_cast<double>(timestampUs - stats.lastIdleTimeUs));
    stats.lastIdleTimeUs = -1;
  }
  stats.lastActiveTimeUs = timestampUs;
}

void NativeFlowExtractor::completeFlow(const FlowKey &key, FlowStats &stats) {
  if (stats.curFwdBulkPkts >= 2) {
    stats.fwdBulkPktsAcc.update(stats.curFwdBulkPkts);
    stats.fwdBulkBytesAcc.update(stats.curFwdBulkBytes);
  }
  if (stats.curBwdBulkPkts >= 2) {
    stats.bwdBulkPktsAcc.update(stats.curBwdBulkPkts);
    stats.bwdBulkBytesAcc.update(stats.curBwdBulkBytes);
  }

  if (flowCompletionCallback_) {
    flowCompletionCallback_(stats.toFeatureVector(key.dstPort),
                            buildFlowInfo(key, stats));
  }

  if (liveMode_) {
    // In live mode (processPacket path), results are delivered via callback.
    // Do NOT accumulate in completedFlows_ — that vector is only used
    // by batch-mode extractFeatures() / buildFeatureVectors().
    // Skipping this avoids unbounded memory growth in long-running daemons.
    return;
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
