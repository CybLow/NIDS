#pragma once

// Native C++ flow feature extractor for LSNM2024-compatible flow analysis.
//
// Extracts 77 bidirectional flow features directly from pcap files.
// Features are computed per-flow and returned as in-memory feature vectors
// (no intermediate CSV).
//
// The feature set covers:
// - Flow duration, packet counts, byte counts (per direction)
// - Packet length statistics (min, max, mean, std) per direction
// - Inter-arrival time statistics per direction
// - TCP flag counts (FIN, SYN, RST, PSH, ACK, URG, CWR, ECE)
// - Header length, packet/byte rates
// - Bulk transfer metrics
// - Subflow metrics, active/idle time statistics
// - Initial TCP window sizes

#include "core/services/IFlowExtractor.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace pcpp {
class RawPacket;
class Packet;
} // namespace pcpp

namespace nids::infra {

/// Number of flow features produced by toFeatureVector().
inline constexpr int kFlowFeatureCount = 77;

/// Maximum packets per flow before forced split.  Prevents mega-flows
/// (e.g. DDoS where millions of packets share a single 5-tuple) from
/// collapsing into a single sample.  Must match Python preprocessing.
inline constexpr std::uint64_t kMaxFlowPackets = 200;

/// Returns the ordered list of feature column names matching toFeatureVector()
/// output.
[[nodiscard]] const std::vector<std::string> &flowFeatureNames();

/**
 * Online statistics accumulator using Welford's algorithm.
 *
 * Computes running mean, variance, standard deviation, min, max, and sum
 * in O(1) space per update.  Replaces per-packet vectors that previously
 * stored all values for offline statistics computation (~7 KB per flow).
 *
 * Reference: Welford, B.P. (1962), "Note on a method for calculating
 * corrected sums of squares and products", Technometrics 4(3):419-420.
 */
struct WelfordAccumulator {
  std::uint64_t n = 0;
  double mean_ = 0.0;
  double m2_ = 0.0;   ///< Sum of squared deviations from the running mean.
  double sum_ = 0.0;
  double min_ = std::numeric_limits<double>::max();
  double max_ = std::numeric_limits<double>::lowest();

  /** Feed a new observation. */
  void update(double x) noexcept {
    ++n;
    sum_ += x;
    if (n == 1) {
      min_ = max_ = x;
    } else {
      min_ = std::min(min_, x);
      max_ = std::max(max_, x);
    }
    double delta = x - mean_;
    mean_ += delta / static_cast<double>(n);
    double delta2 = x - mean_;
    m2_ += delta * delta2;
  }

  [[nodiscard]] double mean() const noexcept { return n > 0 ? mean_ : 0.0; }
  [[nodiscard]] double sum() const noexcept { return sum_; }
  [[nodiscard]] double min() const noexcept {
    return n > 0 ? min_ : 0.0;
  }
  [[nodiscard]] double max() const noexcept {
    return n > 0 ? max_ : 0.0;
  }

  /** Population variance (divide by N). */
  [[nodiscard]] double populationVariance() const noexcept {
    return n > 0 ? m2_ / static_cast<double>(n) : 0.0;
  }

  /** Sample variance (divide by N-1, Bessel's correction). */
  [[nodiscard]] double sampleVariance() const noexcept {
    return n > 1 ? m2_ / static_cast<double>(n - 1) : 0.0;
  }

  /** Sample standard deviation (sqrt of sample variance, N-1 denominator).
   *
   * Uses sample variance (Bessel's correction, divide by N-1) to match the
   * Python training pipeline (scripts/ml/preprocess.py _stddev() function).
   * The LSNM2024 model was trained with sample stddev — the C++ inference
   * extractor MUST use the same convention.
   */
  [[nodiscard]] double stddev() const noexcept {
    return std::sqrt(sampleVariance());
  }
};

/** Five-tuple flow key identifying a unique bidirectional network flow. */
struct FlowKey {
  /** Source IP address (dotted-decimal). */
  std::string srcIp;
  /** Destination IP address (dotted-decimal). */
  std::string dstIp;
  /** Source transport port. */
  std::uint16_t srcPort = 0;
  /** Destination transport port. */
  std::uint16_t dstPort = 0;
  /** IP protocol number (6=TCP, 17=UDP, 1=ICMP). */
  std::uint8_t protocol = 0;

  bool operator==(const FlowKey &other) const = default;
};

/// Hash functor for FlowKey, combining all five tuple fields.
struct FlowKeyHash {
  /** Compute a combined hash of all five tuple fields. */
  std::size_t operator()(const FlowKey &k) const noexcept {
    std::size_t h = std::hash<std::string>{}(k.srcIp);
    h ^= std::hash<std::string>{}(k.dstIp) + 0x9e3779b9 + (h << 6) + (h >> 2);
    h ^= std::hash<std::uint16_t>{}(k.srcPort) + 0x9e3779b9 + (h << 6) +
         (h >> 2);
    h ^= std::hash<std::uint16_t>{}(k.dstPort) + 0x9e3779b9 + (h << 6) +
         (h >> 2);
    h ^= std::hash<std::uint8_t>{}(k.protocol) + 0x9e3779b9 + (h << 6) +
         (h >> 2);
    return h;
  }
};

/** Accumulated per-flow statistics used to compute the 77-feature vector. */
struct FlowStats { // NOSONAR - 45 fields required by CIC-IDS2017 feature vector
                   // specification
  /** Flow start time in microseconds since epoch. */
  std::int64_t startTimeUs = 0;
  /** Timestamp of the last packet in either direction (microseconds). */
  std::int64_t lastTimeUs = 0;
  /** Total packets in the forward direction. */
  std::uint64_t totalFwdPackets = 0;
  /** Total packets in the backward direction. */
  std::uint64_t totalBwdPackets = 0;
  /** Total payload bytes in the forward direction. */
  std::uint64_t totalFwdBytes = 0;
  /** Total payload bytes in the backward direction. */
  std::uint64_t totalBwdBytes = 0;
  /** Running statistics for forward packet lengths. */
  WelfordAccumulator fwdLengthAcc;
  /** Running statistics for backward packet lengths. */
  WelfordAccumulator bwdLengthAcc;
  /** Running statistics for all packet lengths (both directions). */
  WelfordAccumulator allLengthAcc;
  /** Running statistics for flow-level inter-arrival times (microseconds). */
  WelfordAccumulator flowIatAcc;
  /** Running statistics for forward inter-arrival times (microseconds). */
  WelfordAccumulator fwdIatAcc;
  /** Running statistics for backward inter-arrival times (microseconds). */
  WelfordAccumulator bwdIatAcc;
  /** Timestamp of the last forward packet (-1 if none yet). */
  std::int64_t lastFwdTimeUs = -1;
  /** Timestamp of the last backward packet (-1 if none yet). */
  std::int64_t lastBwdTimeUs = -1;
  /** Count of forward packets with PSH flag set. */
  std::uint32_t fwdPshFlags = 0;
  /** Count of backward packets with PSH flag set. */
  std::uint32_t bwdPshFlags = 0;
  /** Count of forward packets with URG flag set. */
  std::uint32_t fwdUrgFlags = 0;
  /** Count of backward packets with URG flag set. */
  std::uint32_t bwdUrgFlags = 0;
  /** Total FIN flags observed in the flow. */
  std::uint32_t finCount = 0;
  /** Total SYN flags observed in the flow. */
  std::uint32_t synCount = 0;
  /** Total RST flags observed in the flow. */
  std::uint32_t rstCount = 0;
  /** Total PSH flags observed in the flow. */
  std::uint32_t pshCount = 0;
  /** Total ACK flags observed in the flow. */
  std::uint32_t ackCount = 0;
  /** Total URG flags observed in the flow. */
  std::uint32_t urgCount = 0;
  /** Total CWR flags observed in the flow. */
  std::uint32_t cwrCount = 0;
  /** Total ECE flags observed in the flow. */
  std::uint32_t eceCount = 0;
  /** Cumulative header bytes in the forward direction. */
  std::uint32_t fwdHeaderBytes = 0;
  /** Cumulative header bytes in the backward direction. */
  std::uint32_t bwdHeaderBytes = 0;
  /** Initial TCP window size in the forward direction. */
  std::uint32_t fwdInitWinBytes = 0;
  /** Initial TCP window size in the backward direction. */
  std::uint32_t bwdInitWinBytes = 0;
  /** Count of forward packets with payload > 0. */
  std::uint32_t actDataPktFwd = 0;
  /** Minimum segment size observed in the forward direction. */
  std::uint32_t minSegSizeForward = 0;
  /** Running statistics for active transfer period durations (microseconds). */
  WelfordAccumulator activeAcc;
  /** Running statistics for idle period durations (microseconds). */
  WelfordAccumulator idleAcc;
  /** End timestamp of the last active period (-1 if none). */
  std::int64_t lastActiveTimeUs = -1;
  /** Start timestamp of the last idle period (-1 if none). */
  std::int64_t lastIdleTimeUs = -1;
  /** Running statistics for completed forward bulk transfer byte counts. */
  WelfordAccumulator fwdBulkBytesAcc;
  /** Running statistics for completed backward bulk transfer byte counts. */
  WelfordAccumulator bwdBulkBytesAcc;
  /** Running statistics for completed forward bulk transfer packet counts. */
  WelfordAccumulator fwdBulkPktsAcc;
  /** Running statistics for completed backward bulk transfer packet counts. */
  WelfordAccumulator bwdBulkPktsAcc;

  /** Packets in the current forward bulk transfer. */
  std::uint32_t curFwdBulkPkts = 0;
  /** Bytes in the current forward bulk transfer. */
  std::uint32_t curFwdBulkBytes = 0;
  /** Packets in the current backward bulk transfer. */
  std::uint32_t curBwdBulkPkts = 0;
  /** Bytes in the current backward bulk transfer. */
  std::uint32_t curBwdBulkBytes = 0;
  /** Whether the most recent packet was in the forward direction. */
  bool lastPacketWasFwd = false;

  /// Convert accumulated stats to a flat feature vector of kFlowFeatureCount
  /// floats.
  [[nodiscard]] std::vector<float> toFeatureVector(std::uint16_t dstPort) const;
};

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

private:
  std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flows_;
  std::vector<std::pair<FlowKey, FlowStats>> completedFlows_;
  std::vector<core::FlowInfo> flowMetadata_; ///< Populated by extractFeatures()
  core::IFlowExtractor::FlowCompletionCallback flowCompletionCallback_;
  std::int64_t flowTimeoutUs_;      ///< Flow inactivity timeout (from Configuration).
  std::int64_t idleThresholdUs_;    ///< Idle vs active period threshold (from Configuration).
  std::int64_t lastSweepTimeUs_ = 0; ///< Timestamp of the last periodic sweep.
  bool liveMode_ = false; ///< True when processPacket() has been called (live capture).

  /// Parsed packet context passed between processPacket helpers.
  struct ParsedPacket {
    std::string srcIp;
    std::string dstIp;
    std::uint16_t srcPort = 0;
    std::uint16_t dstPort = 0;
    std::uint8_t protocol = 0;
    std::uint32_t headerBytes = 0;
    std::uint32_t totalPacketLen = 0;
    std::uint32_t payloadSize = 0;
    std::uint32_t transportHeaderLen = 0;
    std::uint32_t ipIhl = 0;
    std::uint8_t tcpFlags = 0;
    std::uint16_t tcpWindow = 0;
  };

  void processPacketInternal(pcpp::RawPacket &rawPacket, std::int64_t timestampUs);
  void
  buildFlowMetadata(); ///< Populate flowMetadata_ from completed + active flows

  /// Build feature vectors from completed + active flows (same order as
  /// flowMetadata_).
  [[nodiscard]] std::vector<std::vector<float>> buildFeatureVectors() const;

  /// Parse all layers from a PcapPlusPlus parsed packet into ParsedPacket.
  [[nodiscard]] static bool parsePacketHeaders(const pcpp::Packet &packet,
                                               ParsedPacket &pkt);

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
