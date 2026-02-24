#include "app/AnalysisService.h"

#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

namespace nids::app {

AnalysisService::AnalysisService(
    std::unique_ptr<nids::core::IPacketAnalyzer> analyzer,
    std::unique_ptr<nids::core::IFlowExtractor> extractor,
    QObject* parent)
    : QObject(parent)
    , analyzer_(std::move(analyzer))
    , extractor_(std::move(extractor)) {}

bool AnalysisService::loadModel(const std::string& modelPath) {
    return analyzer_->loadModel(modelPath);
}

void AnalysisService::analyzeCapture(const std::string& pcapPath,
                                      nids::core::CaptureSession& session) {
    emit analysisStarted();

    std::string csvPath = "analysis_features.csv";

    if (!extractor_->extractFlows(pcapPath, csvPath)) {
        emit analysisError("Failed to extract flow features from capture");
        return;
    }

    auto allFeatures = extractor_->loadFeatures(csvPath);
    int total = static_cast<int>(allFeatures.size());

    for (int i = 0; i < total; ++i) {
        auto attackType = analyzer_->predict(allFeatures[static_cast<std::size_t>(i)]);
        session.setAnalysisResult(static_cast<std::size_t>(i), attackType);
        emit analysisProgress(i + 1, total);
    }

    std::error_code ec;
    fs::remove(csvPath, ec);

    emit analysisFinished();
}

} // namespace nids::app
