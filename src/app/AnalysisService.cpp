#include "app/AnalysisService.h"
#include "app/HybridDetectionService.h"
#include "core/services/Configuration.h"
#include "core/services/IRuleEngine.h"

#include <spdlog/spdlog.h>

namespace nids::app {

namespace {

/// Convert a FlowInfo (from the extractor) to a FlowMetadata (for heuristic rules).
nids::core::FlowMetadata toFlowMetadata(const nids::core::FlowInfo& info) {
    nids::core::FlowMetadata meta;
    meta.srcIp = info.srcIp;
    meta.dstIp = info.dstIp;
    meta.srcPort = info.srcPort;
    meta.dstPort = info.dstPort;

    switch (info.protocol) {
        case 6:
            meta.protocol = "TCP";
            break;
        case 17:
            meta.protocol = "UDP";
            break;
        case 1:
            meta.protocol = "ICMP";
            break;
        default:
            meta.protocol = "OTHER";
            break;
    }

    meta.totalFwdPackets = info.totalFwdPackets;
    meta.totalBwdPackets = info.totalBwdPackets;
    meta.flowDurationUs = info.flowDurationUs;
    meta.fwdPacketsPerSecond = info.fwdPacketsPerSecond;
    meta.bwdPacketsPerSecond = info.bwdPacketsPerSecond;
    meta.synFlagCount = info.synFlagCount;
    meta.ackFlagCount = info.ackFlagCount;
    meta.rstFlagCount = info.rstFlagCount;
    meta.finFlagCount = info.finFlagCount;
    meta.avgPacketSize = info.avgPacketSize;

    return meta;
}

} // anonymous namespace

AnalysisService::AnalysisService(
    std::unique_ptr<nids::core::IPacketAnalyzer> analyzer,
    std::unique_ptr<nids::core::IFlowExtractor> extractor,
    std::unique_ptr<nids::core::IFeatureNormalizer> normalizer,
    QObject* parent)
    : QObject(parent)
    , analyzer_(std::move(analyzer))
    , extractor_(std::move(extractor))
    , normalizer_(std::move(normalizer)) {}

bool AnalysisService::loadModel(const std::string& modelPath) {
    return analyzer_->loadModel(modelPath);
}

bool AnalysisService::loadNormalization(const std::string& metadataPath) {
    return normalizer_->loadMetadata(metadataPath);
}

void AnalysisService::setHybridDetection(HybridDetectionService* service) noexcept {
    hybridService_ = service;
}

void AnalysisService::analyzeCapture(const std::string& pcapPath,
                                       nids::core::CaptureSession& session) {
    emit analysisStarted();

    spdlog::info("Extracting and analyzing flow features from '{}' (streaming mode)",
                 pcapPath);
    spdlog::info("Hybrid detection: {}",
                 hybridService_ != nullptr ? "enabled" : "disabled");

    // Counter for assigning sequential indices to completed flows.
    std::size_t flowIndex = 0;

    // Set up streaming callback: each completed flow is immediately normalized,
    // classified, and stored in the session — no batch accumulation needed.
    extractor_->setFlowCompletionCallback(
        [this, &session, &flowIndex](std::vector<float>&& features,
                                     core::FlowInfo&& info) {
            auto idx = flowIndex++;
            auto normalized = normalizer_->normalize(features);

            if (hybridService_ != nullptr) {
                auto mlResult = analyzer_->predictWithConfidence(normalized);
                auto flowMeta = toFlowMetadata(info);
                auto detection = hybridService_->evaluate(
                    mlResult, info.srcIp, info.dstIp, flowMeta);
                session.setDetectionResult(idx, detection);
            } else {
                auto attackType = analyzer_->predict(normalized);
                core::DetectionResult mlOnlyResult;
                mlOnlyResult.finalVerdict = attackType;
                mlOnlyResult.detectionSource = core::DetectionSource::MlOnly;
                session.setDetectionResult(idx, mlOnlyResult);
            }

            emit analysisProgress(static_cast<int>(idx + 1), 0);
        });

    // extractFeatures() fires the callback for each completed flow during
    // processing.  The returned vectors serve as a fallback for extractors that
    // do not invoke the callback (e.g., mocks or alternative implementations).
    auto allFeatures = extractor_->extractFeatures(pcapPath);

    // Clear callback to release captured references.
    extractor_->setFlowCompletionCallback(nullptr);

    if (allFeatures.empty() && flowIndex == 0) {
        spdlog::warn("No flows extracted from '{}' (empty capture or extraction failure)",
                     pcapPath);
    }

    // Fallback: if the extractor did not invoke the callback (flowIndex == 0),
    // process all flows from the batch result (backward-compatible path).
    bool usedBatchFallback = false;
    if (flowIndex == 0 && !allFeatures.empty()) {
        usedBatchFallback = true;
        spdlog::debug("Streaming callback was not invoked — falling back to batch analysis");
        const auto& metadata = extractor_->flowMetadata();
        auto total = static_cast<int>(allFeatures.size());

        for (int i = 0; i < total; ++i) {
            auto idx = static_cast<std::size_t>(i);
            auto normalized = normalizer_->normalize(allFeatures[idx]);

            if (hybridService_ != nullptr) {
                auto mlResult = analyzer_->predictWithConfidence(normalized);
                if (idx < metadata.size()) {
                    auto flowMeta = toFlowMetadata(metadata[idx]);
                    auto detection = hybridService_->evaluate(
                        mlResult, metadata[idx].srcIp, metadata[idx].dstIp, flowMeta);
                    session.setDetectionResult(idx, detection);
                } else {
                    auto detection = hybridService_->evaluate(mlResult, "", "");
                    session.setDetectionResult(idx, detection);
                }
            } else {
                auto attackType = analyzer_->predict(normalized);
                core::DetectionResult mlOnlyResult;
                mlOnlyResult.finalVerdict = attackType;
                mlOnlyResult.detectionSource = core::DetectionSource::MlOnly;
                session.setDetectionResult(idx, mlOnlyResult);
            }

            emit analysisProgress(i + 1, total);
        }

        flowIndex = allFeatures.size();
    }

    auto total = static_cast<int>(flowIndex);

    // For the streaming path, emit a final progress signal with the correct total
    // now that all flows have been processed.  The batch fallback already emits
    // correct (current, total) pairs, so skip the extra signal to avoid duplicates.
    if (!usedBatchFallback && total > 0) {
        emit analysisProgress(total, total);
    }

    spdlog::info("Analysis complete: {} flows processed", total);
    emit analysisFinished();
}

const std::vector<nids::core::FlowInfo>& AnalysisService::lastFlowMetadata() const noexcept {
    return extractor_->flowMetadata();
}

} // namespace nids::app
