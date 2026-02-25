#include "app/AnalysisService.h"
#include "core/services/Configuration.h"

#include <spdlog/spdlog.h>

#include <filesystem>

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

    auto csvPath = (nids::core::Configuration::instance().tempDirectory()
                    / "nids_analysis_features.csv").string();

    spdlog::info("Extracting flow features from '{}'", pcapPath);

    if (!extractor_->extractFlows(pcapPath, csvPath)) {
        spdlog::error("Failed to extract flow features from '{}'", pcapPath);
        emit analysisError("Failed to extract flow features from capture");
        emit analysisFinished();
        return;
    }

    auto allFeatures = extractor_->loadFeatures(csvPath);
    int total = static_cast<int>(allFeatures.size());

    spdlog::info("Analyzing {} flows", total);

    for (int i = 0; i < total; ++i) {
        auto attackType = analyzer_->predict(allFeatures[static_cast<std::size_t>(i)]);
        session.setAnalysisResult(static_cast<std::size_t>(i), attackType);
        emit analysisProgress(i + 1, total);
    }

    // Clean up temporary CSV
    std::error_code ec;
    if (!fs::remove(csvPath, ec) && ec) {
        spdlog::warn("Failed to remove temporary CSV '{}': {}", csvPath, ec.message());
    }

    spdlog::info("Analysis complete: {} flows processed", total);
    emit analysisFinished();
}

} // namespace nids::app
