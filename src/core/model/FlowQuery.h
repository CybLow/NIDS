#pragma once

/// Query model for searching indexed flow metadata.
///
/// Supports filtering by IP (exact or CIDR), port, protocol, time range,
/// detection verdict, and pagination. Used by IFlowIndex::query().

#include "core/model/AttackType.h"
#include "core/model/DetectionSource.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace nids::core {

struct FlowQuery {
    /// Time range (microseconds since epoch).
    std::optional<int64_t> startTimeUs;
    std::optional<int64_t> endTimeUs;

    /// IP filters (exact match or CIDR notation).
    std::optional<std::string> srcIp;
    std::optional<std::string> dstIp;
    std::optional<std::string> anyIp; ///< matches src OR dst

    /// Port filters.
    std::optional<std::uint16_t> srcPort;
    std::optional<std::uint16_t> dstPort;
    std::optional<std::uint16_t> anyPort;

    /// Protocol filter.
    std::optional<std::uint8_t> protocol;

    /// Detection filters.
    std::optional<AttackType> verdict;
    std::optional<bool> flaggedOnly;
    std::optional<float> minCombinedScore;
    std::optional<DetectionSource> detectionSource;

    /// Sorting and pagination.
    std::string orderBy = "timestamp_us DESC";
    std::size_t limit = 1000;
    std::size_t offset = 0;
};

} // namespace nids::core
