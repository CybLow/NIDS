#pragma once

// Native C++ flow feature extractor for LSNM2024-compatible flow analysis.
//
// Manages the lifecycle of bidirectional network flows: creation,
// packet accumulation, timeout/split expiry, and finalization.
//
// Flow identification (FlowKey) and statistics/feature construction
// (FlowStats) are in separate headers for SRP.

#include "core/services/IFlowExtractor.h"
#include "infra/flow/FlowKey.h"
#include "infra/flow/FlowStats.h"
#include "infra/parsing/PacketParser.h"

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace pcpp {
class RawPacket;
class Packet;
} // namespace pcpp

namespace nids::infra {

/// Maximum packets per flow before forced split.  Prevents mega-flows
/// (e.g. DDoS where millions of packets share a single 5-tuple) from
/// collapsing into a single sample.  Must match Python preprocessing.
inline constexpr std::uint64_t kMaxFlowPackets = 200;

/** Native C++ flow feature extractor producing LSNM2024-compatible 77-feature
 * vectors. */
class NativeFlowExtractor : public core::IFlowExtractor {
public:
  /** Construct the extractor with timeouts from Configuration::instance(). */
  NativeFlowExtractor();

  /// Register a callback for completed flows.  Pass nullptr to disable.
  void setFlowCompletionCallback(core::IFlowExtractor::FlowCompletionCallback cb) override;

  /**
   * Override the flow inactivity timeout.
   * @param timeoutUs  Timeout in microseconds; flows idle longer than this are
   * finalized.
   */
  void setFlowTimeout(std::int64_t timeoutUs);

  /**
   * Set the maximum flow duration for time-window splitting.
   *
   * Active flows whose age (lastTimeUs - startTimeUs) exceeds this limit
   * are completed and restarted with fresh stats.  This ensures long-lived
   * connections (HTTP/2, WebSocket, SSH) produce periodic ML verdicts
   * rather than accumulating indefinitely.
   *
   * Set to 0 to disable duration-based splitting (packet-count split still
   * applies via kMaxFlowPackets).
   *
   * @param durationUs  Maximum flow age in microseconds.  Default: 15 seconds
   *                    (from Configuration::maxFlowDurationUs()).
   */
  void setMaxFlowDuration(std::int64_t durationUs);

  /**
   * Sweep all active flows and expire those idle longer than flowTimeoutUs_.
   *
   * @param nowUs  Current time in microseconds (e.g., packet timestamp or
   *               wall-clock time).
   * @return       Number of flows expired by this sweep.
   *
   * In batch mode (extractFeatures), this is called periodically during pcap
   * processing.  In future live mode (Phase 8.6), an external timer can call
   * this to proactively expire idle flows.
   */
  std::size_t sweepExpiredFlows(std::int64_t nowUs);

  [[nodiscard]] std::vector<std::vector<float>>
  extractFeatures(const std::string &pcapPath) override;

  [[nodiscard]] const std::vector<core::FlowInfo> &
  flowMetadata() const noexcept override;

  /// Feed a single raw packet for live flow extraction.
  /// Includes periodic timeout sweeps (same interval as batch mode).
  void processPacket(const std::uint8_t *data, std::size_t length,
                     std::int64_t timestampUs) override;

  /// Finalize all remaining active flows and fire the completion callback.
  void finalizeAllFlows() override;

  /// Reset all internal state for a new capture session.
  void reset() override;

  /// Diagnostic counters for live detection pipeline analysis.
  struct DiagCounters {
    std::uint64_t packetsReceived = 0;   ///< Total calls to processPacket().
    std::uint64_t packetsParsed = 0;     ///< Packets that passed parsePacketHeaders().
    std::uint64_t packetsSkipped = 0;    ///< Packets rejected by parsePacketHeaders().
    std::uint64_t flowsCompletedFinRst = 0;  ///< Flows completed by TCP FIN/RST.
    std::uint64_t flowsCompletedMaxPkts = 0; ///< Flows completed by kMaxFlowPackets split.
    std::uint64_t flowsCompletedTimeout = 0; ///< Flows expired by idle timeout sweep.
    std::uint64_t flowsCompletedDuration = 0; ///< Flows split by max duration (time-window).
    std::uint64_t flowsCompletedFinalize = 0; ///< Flows finalized at shutdown.
    std::uint64_t sweepCount = 0;        ///< Number of sweep passes executed.
  };

  /// Access diagnostic counters (read-only snapshot).
  [[nodiscard]] const DiagCounters& diagCounters() const noexcept {
    return diag_;
  }

  /// Log a summary of diagnostic counters via spdlog.
  void logDiagnostics() const;

private:
  std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flows_;
  std::vector<std::pair<FlowKey, FlowStats>> completedFlows_;
  std::vector<core::FlowInfo> flowMetadata_; ///< Populated by extractFeatures()
  core::IFlowExtractor::FlowCompletionCallback flowCompletionCallback_;
  std::int64_t flowTimeoutUs_;      ///< Flow inactivity timeout (from Configuration).
  std::int64_t maxFlowDurationUs_;  ///< Max flow age before time-window split (0=disabled).
  std::int64_t idleThresholdUs_;    ///< Idle vs active period threshold (from Configuration).
  std::int64_t lastSweepTimeUs_ = 0; ///< Timestamp of the last periodic sweep.
  bool liveMode_ = false; ///< True when processPacket() has been called (live capture).
  DiagCounters diag_; ///< Diagnostic counters for pipeline analysis.

  /// Alias for the shared parsed packet struct from infra/parsing/.
  using ParsedPacket = ParsedFields;

  void processPacketInternal(pcpp::RawPacket &rawPacket, std::int64_t timestampUs);
  void
  buildFlowMetadata(); ///< Populate flowMetadata_ from completed + active flows

  /// Build feature vectors from completed + active flows (same order as
  /// flowMetadata_).
  [[nodiscard]] std::vector<std::vector<float>> buildFeatureVectors() const;

  /// Evict timed-out flows and resolve the active flow key and direction.
  struct FlowLookupResult {
    FlowKey activeKey;
    bool isForward = false;
  };
  FlowLookupResult resolveFlow(const FlowKey &keyFwd, const FlowKey &keyBwd,
                               std::int64_t timestampUs);

  /// Update per-direction packet statistics on a flow.
  static void updateDirectionStats(FlowStats &stats, const ParsedPacket &pkt,
                                   std::int64_t timestampUs, bool isForward);

  /// Update TCP flag counters using already-parsed flags from ParsedPacket.
  static void updateTcpFlags(FlowStats &stats, const ParsedPacket &pkt,
                             bool isForward);

  /// Increment all 8 global TCP flag counters via a data-driven table.
  static void countGlobalTcpFlags(FlowStats &stats, std::uint8_t flags);

  /// Update forward-direction TCP state (PSH/URG flags, init window, segment
  /// tracking).
  static void updateFwdTcpState(FlowStats &stats, std::uint8_t flags,
                                std::uint16_t win, std::uint32_t payloadSize);

  /// Update backward-direction TCP state (PSH/URG flags, init window).
  static void updateBwdTcpState(FlowStats &stats, std::uint8_t flags,
                                std::uint16_t win);

  /// Update bulk transfer tracking for the current packet direction.
  static void updateBulkTracking(FlowStats &stats, std::uint32_t packetLen,
                                 bool isForward);

  /// Update active/idle period tracking based on inter-packet gap.
  static void updateActiveIdle(FlowStats &stats, std::int64_t timestampUs,
                               std::int64_t prevLastTimeUs,
                               std::int64_t flowGapUs,
                               std::int64_t idleThresholdUs);

  /// Finalize bulk counters and move flow to completedFlows_.
  void completeFlow(const FlowKey &key, FlowStats &stats);
};

} // namespace nids::infra
