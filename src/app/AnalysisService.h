#pragma once

#include "core/model/CaptureSession.h"
#include "core/model/AttackType.h"
#include "core/services/IPacketAnalyzer.h"
#include "core/services/IFlowExtractor.h"
#include "infra/analysis/FeatureNormalizer.h"

#include <QObject>

#include <memory>
#include <string>

namespace nids::app {

class HybridDetectionService;  // forward declaration

class AnalysisService : public QObject {
    Q_OBJECT

public:
    explicit AnalysisService(std::unique_ptr<nids::core::IPacketAnalyzer> analyzer,
                             std::unique_ptr<nids::core::IFlowExtractor> extractor,
                             QObject* parent = nullptr);

    [[nodiscard]] bool loadModel(const std::string& modelPath);

    /// Load normalization parameters from model metadata JSON.
    /// Must be called before analyzeCapture() for correct predictions.
    [[nodiscard]] bool loadNormalization(const std::string& metadataPath);

    /// Set the hybrid detection service for multi-layer analysis.
    /// The caller retains ownership (non-owning pointer).
    /// If not set, analysis falls back to ML-only mode.
    void setHybridDetection(HybridDetectionService* service) noexcept;

    void analyzeCapture(const std::string& pcapPath,
                        nids::core::CaptureSession& session);

signals:
    void analysisStarted();
    void analysisProgress(int current, int total);
    void analysisFinished();
    void analysisError(const QString& message);

private:
    std::unique_ptr<nids::core::IPacketAnalyzer> analyzer_;
    std::unique_ptr<nids::core::IFlowExtractor> extractor_;
    nids::infra::FeatureNormalizer normalizer_;
    HybridDetectionService* hybridService_ = nullptr;  // non-owning
};

} // namespace nids::app
