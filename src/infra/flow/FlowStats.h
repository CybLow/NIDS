#pragma once

/// Per-flow accumulated statistics and feature vector construction.
///
/// FlowStats holds the ~45 counters/accumulators that track a single
/// bidirectional flow.  toFeatureVector() converts them into the
/// 77-float CIC-IDS2017-compatible feature vector consumed by the ML model.
///
/// Separated from NativeFlowExtractor to keep flow statistics and
/// feature construction (data) distinct from flow lifecycle management
/// (behavior).

#include "core/math/WelfordAccumulator.h"
#include "core/model/FlowConstants.h"
#include "core/model/FlowInfo.h"
#include "core/model/FlowKey.h"

#include <cstdint>
#include <string>
#include <vector>

namespace nids::infra {

using core::FlowKey;

/// Import WelfordAccumulator from core/ for convenience.
using core::WelfordAccumulator;

using core::kFlowFeatureCount;

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

/// Returns the ordered list of feature column names matching toFeatureVector()
/// output.
[[nodiscard]] const std::vector<std::string>& flowFeatureNames();

/// Build a FlowInfo metadata record from a flow key and accumulated stats.
[[nodiscard]] core::FlowInfo buildFlowInfo(const FlowKey& key,
                                                  const FlowStats& stats);

} // namespace nids::infra
