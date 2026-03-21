#pragma once

/// IHuntEngine — interface for threat-hunting operations.
///
/// Provides retroactive analysis, IOC search, flow correlation,
/// and timeline construction against historical flow data.

#include "core/model/AnomalyResult.h"
#include "core/model/HuntResult.h"
#include "core/model/IndexedFlow.h"
#include "core/model/TimelineEvent.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string_view>
#include <vector>

namespace nids::core {

class IHuntEngine {
public:
    virtual ~IHuntEngine() = default;

    /// Progress callback for long-running hunts.
    using ProgressCallback =
        std::function<void(float progress, std::string_view status)>;

    /// Re-analyze a stored PCAP file with the current detection stack.
    [[nodiscard]] virtual HuntResult retroactiveAnalysis(
        const std::filesystem::path& pcapFile) = 0;

    /// Search historical flows for specific IOCs.
    [[nodiscard]] virtual HuntResult iocSearch(
        const IocSearchQuery& query) = 0;

    /// Correlate flows involving a specific IP over a time window.
    [[nodiscard]] virtual HuntResult correlateByIp(
        std::string_view ip,
        int64_t startTimeUs,
        int64_t endTimeUs) = 0;

    /// Build a timeline from a set of indexed flows.
    [[nodiscard]] virtual Timeline buildTimeline(
        const std::vector<IndexedFlow>& flows) = 0;

    /// Detect statistical anomalies in a time window.
    [[nodiscard]] virtual std::vector<AnomalyResult> detectAnomalies(
        int64_t startTimeUs,
        int64_t endTimeUs) = 0;

    /// Set the progress callback for long-running operations.
    virtual void setProgressCallback(ProgressCallback cb) = 0;
};

} // namespace nids::core
