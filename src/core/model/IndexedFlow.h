#pragma once

/// IndexedFlow — a flow record retrieved from the flow index database.
///
/// Contains the original FlowInfo + DetectionResult fields plus database
/// metadata (row ID, PCAP file reference, indexing timestamp).

#include "core/model/AttackType.h"
#include "core/model/DetectionSource.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace nids::core {

struct IndexedFlow {
    /// Database row identifier.
    int64_t id = 0;

    /// Timestamp of the flow (microseconds since epoch).
    int64_t timestampUs = 0;

    /// 5-tuple.
    std::string srcIp;
    std::string dstIp;
    std::uint16_t srcPort = 0;
    std::uint16_t dstPort = 0;
    std::uint8_t protocol = 0;

    /// Traffic statistics.
    std::size_t packetCount = 0;
    std::size_t byteCount = 0;
    int64_t durationUs = 0;

    /// Detection results.
    AttackType verdict = AttackType::Benign;
    float mlConfidence = 0.0f;
    float combinedScore = 0.0f;
    DetectionSource detectionSource = DetectionSource::None;
    bool isFlagged = false;

    /// Threat intelligence matches (serialized JSON).
    std::string tiMatchesJson;

    /// Rule matches (serialized JSON).
    std::string ruleMatchesJson;

    /// PCAP file reference for packet-level drill-down.
    std::string pcapFile;
    std::size_t pcapOffset = 0;

    /// When this record was indexed (seconds since epoch).
    int64_t createdAt = 0;
};

/// Aggregated statistics over a set of flows.
struct FlowStatsSummary {
    std::size_t totalFlows = 0;
    std::size_t flaggedFlows = 0;
    std::size_t totalPackets = 0;
    std::size_t totalBytes = 0;
    float avgCombinedScore = 0.0f;
    float maxCombinedScore = 0.0f;
};

} // namespace nids::core
