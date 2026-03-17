#include "app/HuntEngine.h"

#include "app/HybridDetectionService.h"
#include "core/model/AttackType.h"
#include "core/model/DetectionSource.h"
#include "core/model/FlowQuery.h"
#include "core/services/IFeatureNormalizer.h"
#include "core/services/IFlowExtractor.h"
#include "core/services/IPacketAnalyzer.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <ranges>
#include <unordered_set>
#include <utility>

namespace nids::app {

HuntEngine::HuntEngine(core::IFlowIndex& flowIndex,
                       core::IFlowExtractor& extractor,
                       core::IPacketAnalyzer& analyzer,
                       core::IFeatureNormalizer& normalizer,
                       HybridDetectionService& detector)
    : flowIndex_(flowIndex),
      extractor_(extractor),
      analyzer_(analyzer),
      normalizer_(normalizer),
      detector_(detector) {}

// ── retroactiveAnalysis() ───────────────────────────────────────────

core::HuntResult HuntEngine::retroactiveAnalysis(
    const std::filesystem::path& pcapFile) {

    core::HuntResult result;
    result.description = "Retroactive analysis of " + pcapFile.string();

    if (!std::filesystem::exists(pcapFile)) {
        result.completed = false;
        result.errorMessage = "PCAP file not found: " + pcapFile.string();
        return result;
    }

    if (progressCb_) {
        progressCb_(0.0f, "Extracting flows...");
    }

    // Extract features from the PCAP file.
    auto features = extractor_.extractFeatures(pcapFile);
    const auto& metadata = extractor_.flowMetadata();
    result.totalFlowsScanned = features.size();

    if (progressCb_) {
        progressCb_(0.3f, "Analyzing flows...");
    }

    // Run ML + hybrid detection on each flow.
    for (std::size_t i = 0; i < features.size(); ++i) {
        auto prediction = analyzer_.predictWithConfidence(features[i]);
        auto detection = detector_.evaluate(
            prediction, metadata[i].srcIp, metadata[i].dstIp, metadata[i]);

        if (detection.isFlagged()) {
            core::IndexedFlow indexed;
            indexed.timestampUs = static_cast<int64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());
            indexed.srcIp = metadata[i].srcIp;
            indexed.dstIp = metadata[i].dstIp;
            indexed.srcPort = metadata[i].srcPort;
            indexed.dstPort = metadata[i].dstPort;
            indexed.protocol = metadata[i].protocol;
            indexed.verdict = detection.finalVerdict;
            indexed.mlConfidence = detection.mlResult.confidence;
            indexed.combinedScore = detection.combinedScore;
            indexed.detectionSource = detection.detectionSource;
            indexed.isFlagged = true;
            indexed.pcapFile = pcapFile.string();
            result.matchedFlows.push_back(std::move(indexed));
        }

        if (progressCb_ && features.size() > 0) {
            const float progress = 0.3f + 0.7f *
                (static_cast<float>(i + 1) /
                 static_cast<float>(features.size()));
            progressCb_(progress, "Analyzing flow " +
                std::to_string(i + 1) + "/" +
                std::to_string(features.size()));
        }
    }

    spdlog::info("HuntEngine: retroactive analysis of '{}': {} flows, "
                 "{} flagged",
                 pcapFile.string(), result.totalFlowsScanned,
                 result.matchedFlows.size());
    return result;
}

// ── iocSearch() ─────────────────────────────────────────────────────

core::HuntResult HuntEngine::iocSearch(const core::IocSearchQuery& query) {
    core::HuntResult result;
    result.description = "IOC search";

    // Search for each IP in the index.
    for (const auto& ip : query.ips) {
        core::FlowQuery fq;
        fq.startTimeUs = query.startTimeUs;
        fq.endTimeUs = query.endTimeUs;

        if (query.searchSrcOnly) {
            fq.srcIp = ip;
        } else if (query.searchDstOnly) {
            fq.dstIp = ip;
        } else {
            fq.anyIp = ip;
        }

        auto flows = flowIndex_.query(fq);
        result.totalFlowsScanned += flows.size();
        for (auto& f : flows) {
            result.matchedFlows.push_back(std::move(f));
        }
    }

    // Search for each port.
    for (const auto port : query.ports) {
        core::FlowQuery fq;
        fq.startTimeUs = query.startTimeUs;
        fq.endTimeUs = query.endTimeUs;
        fq.anyPort = port;

        auto flows = flowIndex_.query(fq);
        result.totalFlowsScanned += flows.size();
        for (auto& f : flows) {
            result.matchedFlows.push_back(std::move(f));
        }
    }

    // Deduplicate by flow ID.
    std::unordered_set<int64_t> seen;
    std::erase_if(result.matchedFlows, [&seen](const auto& f) {
        return !seen.insert(f.id).second;
    });

    spdlog::info("HuntEngine: IOC search found {} matching flows",
                 result.matchedFlows.size());
    return result;
}

// ── correlateByIp() ─────────────────────────────────────────────────

core::HuntResult HuntEngine::correlateByIp(
    std::string_view ip, int64_t startTimeUs, int64_t endTimeUs) {

    core::FlowQuery fq;
    fq.anyIp = std::string(ip);
    fq.startTimeUs = startTimeUs;
    fq.endTimeUs = endTimeUs;
    fq.limit = 10000;

    core::HuntResult result;
    result.description = "Correlation for IP " + std::string(ip);
    result.matchedFlows = flowIndex_.query(fq);
    result.totalFlowsScanned = result.matchedFlows.size();

    spdlog::info("HuntEngine: correlation for IP '{}': {} flows in "
                 "time window",
                 ip, result.matchedFlows.size());
    return result;
}

// ── buildTimeline() ─────────────────────────────────────────────────

core::Timeline HuntEngine::buildTimeline(
    const std::vector<core::IndexedFlow>& flows) {

    core::Timeline timeline;
    if (flows.empty()) return timeline;

    // Sort by timestamp.
    auto sorted = flows;
    std::ranges::sort(sorted, {}, &core::IndexedFlow::timestampUs);

    timeline.startTimeUs = sorted.front().timestampUs;
    timeline.endTimeUs = sorted.back().timestampUs;

    std::unordered_set<std::string> ips;
    std::unordered_set<std::uint8_t> verdictsSeen;

    for (const auto& f : sorted) {
        core::TimelineEvent event;
        event.timestampUs = f.timestampUs;
        event.flow.srcIp = f.srcIp;
        event.flow.dstIp = f.dstIp;
        event.flow.srcPort = f.srcPort;
        event.flow.dstPort = f.dstPort;
        event.flow.protocol = f.protocol;
        event.detection.finalVerdict = f.verdict;
        event.detection.combinedScore = f.combinedScore;

        // Classify event type heuristically.
        if (ips.empty()) {
            event.type = core::EventType::FirstContact;
        } else if (f.verdict == core::AttackType::PortScanning) {
            event.type = core::EventType::Reconnaissance;
        } else if (f.isFlagged) {
            event.type = core::EventType::Exploitation;
        } else {
            event.type = core::EventType::FirstContact;
        }

        event.description = std::string{
            core::attackTypeToString(f.verdict)} +
            " from " + f.srcIp + " to " + f.dstIp;

        ips.insert(f.srcIp);
        ips.insert(f.dstIp);
        verdictsSeen.insert(std::to_underlying(f.verdict));

        timeline.events.push_back(std::move(event));
    }

    timeline.involvedIps.assign(ips.begin(), ips.end());
    std::ranges::sort(timeline.involvedIps);

    for (auto v : verdictsSeen) {
        timeline.attackTypes.push_back(static_cast<core::AttackType>(v));
    }

    timeline.summary = std::to_string(sorted.size()) + " events involving " +
                       std::to_string(ips.size()) + " IPs";
    timeline.incidentId = "hunt-" + std::to_string(timeline.startTimeUs);

    return timeline;
}

// ── detectAnomalies() ───────────────────────────────────────────────

std::vector<core::AnomalyResult> HuntEngine::detectAnomalies(
    int64_t startTimeUs, int64_t endTimeUs) {

    core::FlowQuery fq;
    fq.startTimeUs = startTimeUs;
    fq.endTimeUs = endTimeUs;

    auto stats = flowIndex_.aggregate(fq);

    std::vector<core::AnomalyResult> anomalies;

    // Simple anomaly: flag if avg combined score is unusually high.
    if (stats.totalFlows > 0 && stats.avgCombinedScore > 0.5f) {
        core::AnomalyResult a;
        a.description = "Elevated average combined score in time window";
        a.type = core::AnomalyType::TrafficVolumeSpike;
        a.observedValue = stats.avgCombinedScore;
        a.baselineValue = 0.1; // expected normal baseline
        a.deviationSigma = (stats.avgCombinedScore - 0.1) / 0.1;
        anomalies.push_back(std::move(a));
    }

    // Flag if flagged flow ratio is high.
    if (stats.totalFlows > 10) {
        const double flaggedRatio =
            static_cast<double>(stats.flaggedFlows) /
            static_cast<double>(stats.totalFlows);
        if (flaggedRatio > 0.2) {
            core::AnomalyResult a;
            a.description = "High ratio of flagged flows";
            a.type = core::AnomalyType::TrafficVolumeSpike;
            a.observedValue = flaggedRatio;
            a.baselineValue = 0.05;
            a.deviationSigma = (flaggedRatio - 0.05) / 0.05;
            anomalies.push_back(std::move(a));
        }
    }

    return anomalies;
}

// ── setProgressCallback() ───────────────────────────────────────────

void HuntEngine::setProgressCallback(ProgressCallback cb) {
    progressCb_ = std::move(cb);
}

} // namespace nids::app
