#pragma once

/// HuntResult — the output of a threat-hunting operation.
///
/// Aggregates matched flows, optional timeline, and summary statistics
/// from retroactive analysis, IOC search, or correlation queries.

#include "core/model/IndexedFlow.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace nids::core {

struct HuntResult {
    /// Human-readable description of the hunt that produced this result.
    std::string description;

    /// Flows that matched the hunt criteria.
    std::vector<IndexedFlow> matchedFlows;

    /// Total number of flows scanned (for progress/stats).
    std::size_t totalFlowsScanned = 0;

    /// Whether the hunt completed successfully (false if interrupted).
    bool completed = true;

    /// Error message if the hunt failed.
    std::string errorMessage;
};

/// IOC search query — search for specific indicators of compromise.
struct IocSearchQuery {
    std::vector<std::string> ips;     ///< IP addresses to search for
    std::vector<std::string> cidrs;   ///< CIDR ranges
    std::vector<std::uint16_t> ports; ///< Ports of interest

    std::optional<int64_t> startTimeUs;
    std::optional<int64_t> endTimeUs;

    bool searchSrcOnly = false;
    bool searchDstOnly = false;
};

/// Stored raw packet reference (for PCAP drill-down).
struct StoredPacket {
    int64_t timestampUs = 0;
    std::vector<std::uint8_t> data;
    std::string pcapFile;
    std::size_t offset = 0;
};

/// Metadata about a stored PCAP file in the ring buffer.
struct PcapFileInfo {
    std::string path;
    std::size_t sizeBytes = 0;
    int64_t startTimeUs = 0;
    int64_t endTimeUs = 0;
    std::size_t packetCount = 0;
};

} // namespace nids::core
