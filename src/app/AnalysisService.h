#pragma once

#include "core/model/CaptureSession.h"
#include "core/model/AttackType.h"
#include "core/services/IPacketAnalyzer.h"
#include "core/services/IFlowExtractor.h"
#include "core/services/IFeatureNormalizer.h"

#include <QObject>

#include <memory>
#include <string>

namespace nids::app {

class HybridDetectionService;  // forward declaration

/** Service that orchestrates ML-based packet/flow analysis. */
class AnalysisService : public QObject {
    Q_OBJECT

public:
    /** Construct with injected analyzer, flow extractor, and feature normalizer. */
    explicit AnalysisService(std::unique_ptr<nids::core::IPacketAnalyzer> analyzer,
                             std::unique_ptr<nids::core::IFlowExtractor> extractor,
                             std::unique_ptr<nids::core::IFeatureNormalizer> normalizer,
                             QObject* parent = nullptr);

    /** Load the ONNX model from the given path. Returns false on failure. */
    [[nodiscard]] bool loadModel(const std::string& modelPath);

    /// Load normalization parameters from model metadata JSON.
    /// Must be called before analyzeCapture() for correct predictions.
    [[nodiscard]] bool loadNormalization(const std::string& metadataPath);

    /// Set the hybrid detection service for multi-layer analysis.
    /// The caller retains ownership (non-owning pointer).
    /// If not set, analysis falls back to ML-only mode.
    void setHybridDetection(HybridDetectionService* service) noexcept;

    /**
     * Run ML analysis on a pcap file, populating the session with detection results.
     * @param pcapPath  Path to the pcap file to analyze.
     * @param session   Capture session to populate with results.
     */
    void analyzeCapture(const std::string& pcapPath,
                        nids::core::CaptureSession& session);

    /// Returns per-flow metadata from the most recent analyzeCapture() call.
    /// Indexed in the same order as detection results in the CaptureSession.
    [[nodiscard]] const std::vector<nids::core::FlowInfo>& lastFlowMetadata() const noexcept;

signals:
    /** Emitted when analysis begins. */
    void analysisStarted();
    /** Emitted to report progress (current flow out of total). */
    void analysisProgress(int current, int total);
    /** Emitted when analysis completes successfully. */
    void analysisFinished();
    /** Emitted when an error occurs during analysis. */
    void analysisError(const QString& message);

private:
    std::unique_ptr<nids::core::IPacketAnalyzer> analyzer_;
    std::unique_ptr<nids::core::IFlowExtractor> extractor_;
    std::unique_ptr<nids::core::IFeatureNormalizer> normalizer_;
    HybridDetectionService* hybridService_ = nullptr;  // non-owning
};

} // namespace nids::app
