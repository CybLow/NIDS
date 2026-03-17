#include "infra/flow/NativeFlowExtractor.h"

#include "core/model/ProtocolConstants.h"
#include "core/services/Configuration.h"

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/RawPacket.h>

#include <spdlog/spdlog.h>

#include <array>
#include <cassert>
#include <cmath>
#include <ranges>

namespace nids::infra {

namespace {

// Standard IP protocol numbers
// Use shared protocol constants from core/model/ProtocolConstants.h
using core::kIpProtoIcmp;
using core::kIpProtoTcp;
using core::kIpProtoUdp;

// TCP flag bitmasks — use shared constants from infra/parsing/PacketParser.h
using tcp_flags::kFin;
using tcp_flags::kSyn;
using tcp_flags::kRst;
using tcp_flags::kPsh;
using tcp_flags::kAck;
using tcp_flags::kUrg;
using tcp_flags::kCwr;
using tcp_flags::kEce;

/// Interval between periodic sweeps during batch pcap processing.
constexpr std::int64_t kBatchSweepIntervalUs = 30'000'000; // 30 seconds

/// Interval between periodic sweeps during live capture.
constexpr std::int64_t kLiveSweepIntervalUs = 5'000'000; // 5 seconds

/// Minimum consecutive same-direction packets to qualify as a "bulk transfer".
constexpr std::uint32_t kMinBulkPackets = 2;

} // anonymous namespace

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
      std::ignore = sweepExpiredFlows(tsUs);
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
    std::ignore = sweepExpiredFlows(timestampUs);
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

void NativeFlowExtractor::processPacketInternal(pcpp::RawPacket &rawPacket,
                                                std::int64_t timestampUs) {
  pcpp::Packet parsedPacket(&rawPacket);
  ParsedPacket pkt;
  if (!parsePacketHeaders(parsedPacket, pkt)) [[unlikely]] {
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
  if (pkt.protocol == kIpProtoTcp) [[likely]] {
    tcpFinOrRst = (pkt.tcpFlags & (kFin | kRst)) != 0;
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
    restartFlow(activeKey, stats, timestampUs);
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
    restartFlow(activeKey, stats, timestampUs);
  }
}

void NativeFlowExtractor::restartFlow(const FlowKey &key, FlowStats &stats,
                                      std::int64_t timestampUs) {
  completeFlow(key, stats);
  // Restart flow for same 5-tuple.  Seed start/last timestamps so the
  // new flow isn't immediately expired by the next sweep.
  auto &fresh = (flows_[key] = FlowStats{});
  fresh.startTimeUs = timestampUs;
  fresh.lastTimeUs = timestampUs;
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
      {kFin, &FlowStats::finCount},
      {kSyn, &FlowStats::synCount},
      {kRst, &FlowStats::rstCount},
      {kPsh, &FlowStats::pshCount},
      {kAck, &FlowStats::ackCount},
      {kUrg, &FlowStats::urgCount},
      {kCwr, &FlowStats::cwrCount},
      {kEce, &FlowStats::eceCount},
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
  if (flags & kPsh)
    stats.fwdPshFlags++;
  if (flags & kUrg)
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
  if (flags & kPsh)
    stats.bwdPshFlags++;
  if (flags & kUrg)
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
    if (!stats.lastPacketWasFwd && stats.curBwdBulkPkts >= kMinBulkPackets) {
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
    if (stats.lastPacketWasFwd && stats.curFwdBulkPkts >= kMinBulkPackets) {
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
  if (stats.curFwdBulkPkts >= kMinBulkPackets) {
    stats.fwdBulkPktsAcc.update(stats.curFwdBulkPkts);
    stats.fwdBulkBytesAcc.update(stats.curFwdBulkBytes);
  }
  if (stats.curBwdBulkPkts >= kMinBulkPackets) {
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

const std::vector<core::FlowInfo> &
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
