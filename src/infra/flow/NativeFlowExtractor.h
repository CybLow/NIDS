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

/// Number of flow features produced by toFeatureVector().
inline constexpr int kFlowFeatureCount = 77;

/// Maximum packets per flow before forced split.  Prevents mega-flows
/// (e.g. DDoS where millions of packets share a single 5-tuple) from
/// collapsing into a single sample.  Must match Python preprocessing.
inline constexpr std::uint64_t kMaxFlowPackets = 200;

/// Returns the ordered list of feature column names matching toFeatureVector()
/// output.
[[nodiscard]] const std::vector<std::string> &flowFeatureNames();

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
  /** Per-packet lengths in the forward direction. */
  std::vector<std::uint32_t> fwdPacketLengths;
  /** Per-packet lengths in the backward direction. */
  std::vector<std::uint32_t> bwdPacketLengths;
  /** Per-packet lengths across both directions. */
  std::vector<std::uint32_t> allPacketLengths;
  /** Inter-arrival times for the entire flow (microseconds). */
  std::vector<std::int64_t> flowIatUs;
  /** Forward-direction inter-arrival times (microseconds). */
  std::vector<std::int64_t> fwdIatUs;
  /** Backward-direction inter-arrival times (microseconds). */
  std::vector<std::int64_t> bwdIatUs;
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
  /** Durations of active transfer periods (microseconds). */
  std::vector<std::int64_t> activePeriodsUs;
  /** Durations of idle periods (microseconds). */
  std::vector<std::int64_t> idlePeriodsUs;
  /** End timestamp of the last active period (-1 if none). */
  std::int64_t lastActiveTimeUs = -1;
  /** Start timestamp of the last idle period (-1 if none). */
  std::int64_t lastIdleTimeUs = -1;
  /** Byte counts of completed forward bulk transfers. */
  std::vector<std::uint32_t> fwdBulkBytes;
  /** Byte counts of completed backward bulk transfers. */
  std::vector<std::uint32_t> bwdBulkBytes;
  /** Packet counts of completed forward bulk transfers. */
  std::vector<std::uint32_t> fwdBulkPackets;
  /** Packet counts of completed backward bulk transfers. */
  std::vector<std::uint32_t> bwdBulkPackets;

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
  /** Construct the extractor with the default flow timeout from Configuration.
   */
  NativeFlowExtractor();

  /**
   * Override the flow inactivity timeout.
   * @param timeoutUs  Timeout in microseconds; flows idle longer than this are
   * finalized.
   */
  void setFlowTimeout(std::int64_t timeoutUs);

  [[nodiscard]] std::vector<std::vector<float>>
  extractFeatures(const std::string &pcapPath) override;

  [[nodiscard]] const std::vector<core::FlowInfo> &
  flowMetadata() const noexcept override;

private:
  std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flows_;
  std::vector<std::pair<FlowKey, FlowStats>> completedFlows_;
  std::vector<core::FlowInfo> flowMetadata_; ///< Populated by extractFeatures()
  std::int64_t flowTimeoutUs_ = 600'000'000; // 600 seconds default

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

  void processPacket(pcpp::RawPacket &rawPacket, std::int64_t timestampUs);
  void finalizeBulks();
  void
  buildFlowMetadata(); ///< Populate flowMetadata_ from completed + active flows

  /// Build feature vectors from completed + active flows (same order as
  /// flowMetadata_).
  [[nodiscard]] std::vector<std::vector<float>> buildFeatureVectors() const;

  /// Parse all layers from a PcapPlusPlus parsed packet into ParsedPacket.
  [[nodiscard]] static bool parsePacketHeaders(pcpp::Packet &packet,
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
                               std::int64_t flowGapUs);

  /// Finalize bulk counters and move flow to completedFlows_.
  void completeFlow(const FlowKey &key, FlowStats &stats);
};

} // namespace nids::infra
