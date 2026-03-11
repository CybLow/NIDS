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

    spdlog::info("Extracting flow features from '{}'", pcapPath);

    auto allFeatures = extractor_->extractFeatures(pcapPath);
    if (allFeatures.empty()) {
        spdlog::warn("No flows extracted from '{}' (empty capture or extraction failure)", pcapPath);
        // Not necessarily an error -- empty captures produce zero flows.
        // Only emit analysisError if the pcap could not be opened at all,
        // but extractFeatures() returning empty is ambiguous. Log and proceed.
    }

    const auto& metadata = extractor_->flowMetadata();
    int total = static_cast<int>(allFeatures.size());

    spdlog::info("Analyzing {} flows (hybrid detection: {})",
                 total, hybridService_ != nullptr ? "enabled" : "disabled");

    for (int i = 0; i < total; ++i) {
        auto idx = static_cast<std::size_t>(i);

        // Normalize features before prediction to match training data distribution.
        // If normalization metadata was not loaded, the normalizer returns raw features
        // with a warning (graceful degradation).
        auto normalized = normalizer_->normalize(allFeatures[idx]);

        if (hybridService_ != nullptr) {
            // Full hybrid detection: ML + TI + heuristic rules
            auto mlResult = analyzer_->predictWithConfidence(normalized);

            // Build flow metadata for heuristic rules (if available)
            if (idx < metadata.size()) {
                auto flowMeta = toFlowMetadata(metadata[idx]);
                auto detection = hybridService_->evaluate(
                    mlResult, metadata[idx].srcIp, metadata[idx].dstIp, flowMeta);
                session.setDetectionResult(idx, detection);
            } else {
                // No metadata available -- ML + TI only
                auto detection = hybridService_->evaluate(mlResult, "", "");
                session.setDetectionResult(idx, detection);
            }
        } else {
            // ML-only fallback (no hybrid service configured)
            auto attackType = analyzer_->predict(normalized);
            core::DetectionResult mlOnlyResult;
            mlOnlyResult.finalVerdict = attackType;
            mlOnlyResult.detectionSource = core::DetectionSource::MlOnly;
            session.setDetectionResult(idx, mlOnlyResult);
        }

        // cppcheck-suppress shadowFunction  // Qt signal emission, not a shadowing variable
        emit analysisProgress(i + 1, total);
    }

    spdlog::info("Analysis complete: {} flows processed", total);
    emit analysisFinished();
}

const std::vector<nids::core::FlowInfo>& AnalysisService::lastFlowMetadata() const noexcept {
    return extractor_->flowMetadata();
}

} // namespace nids::app
