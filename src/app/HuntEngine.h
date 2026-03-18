#pragma once

/// HuntEngine — orchestrates retroactive threat-hunting operations.
///
/// Provides IOC search, flow correlation by IP, timeline construction,
/// and retroactive ML re-analysis of stored PCAPs.
/// Lives in the app/ layer; depends on core interfaces injected via ctor.

#include "core/services/IHuntEngine.h"

#include "core/services/IFlowIndex.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string_view>
#include <vector>

namespace nids::core {
class IFlowExtractor;
class IPacketAnalyzer;
class IFeatureNormalizer;
} // namespace nids::core

namespace nids::app {

class HybridDetectionService;

class HuntEngine final : public core::IHuntEngine {
public:
    HuntEngine(core::IFlowIndex& flowIndex,
               core::IFlowExtractor& extractor,
               core::IPacketAnalyzer& analyzer,
               core::IFeatureNormalizer& normalizer,
               HybridDetectionService& detector);

    [[nodiscard]] core::HuntResult retroactiveAnalysis(
        const std::filesystem::path& pcapFile) override;

    [[nodiscard]] core::HuntResult iocSearch(
        const core::IocSearchQuery& query) override;

    [[nodiscard]] core::HuntResult correlateByIp(
        std::string_view ip,
        int64_t startTimeUs,
        int64_t endTimeUs) override;

    [[nodiscard]] core::Timeline buildTimeline(
        const std::vector<core::IndexedFlow>& flows) override;

    [[nodiscard]] std::vector<core::AnomalyResult> detectAnomalies(
        int64_t startTimeUs,
        int64_t endTimeUs) override;

    void setProgressCallback(ProgressCallback cb) override;

private:
    core::IFlowIndex& flowIndex_;
    core::IFlowExtractor& extractor_;
    core::IPacketAnalyzer& analyzer_;
    core::IFeatureNormalizer& normalizer_;
    HybridDetectionService& detector_;
    ProgressCallback progressCb_;
};

} // namespace nids::app
