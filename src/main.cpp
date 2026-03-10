#include "core/services/Configuration.h"
#include "infra/platform/SocketInit.h"
#include "infra/capture/PcapCapture.h"
#include "infra/analysis/AnalyzerFactory.h"
#include "infra/flow/NativeFlowExtractor.h"
#include "infra/threat/ThreatIntelProvider.h"
#include "infra/rules/HeuristicRuleEngine.h"
#include "app/CaptureController.h"
#include "app/AnalysisService.h"
#include "app/HybridDetectionService.h"
#include "ui/MainWindow.h"

#include <QApplication>

#include <spdlog/spdlog.h>

#include <memory>

int main(int argc, char* argv[]) {
    spdlog::set_level(spdlog::level::info);

    nids::platform::NetworkInitGuard networkGuard;
    if (!networkGuard.isInitialized()) {
        spdlog::critical("Failed to initialize networking");
        return 1;
    }

    auto& config = nids::core::Configuration::instance();

    QApplication app(argc, argv);

    qRegisterMetaType<nids::core::PacketInfo>("nids::core::PacketInfo");

    auto capture = std::make_unique<nids::infra::PcapCapture>();
    auto controller = std::make_unique<nids::app::CaptureController>(std::move(capture));

    auto analyzer = nids::infra::createAnalyzer();
    if (!analyzer->loadModel(config.modelPath().string())) {
        spdlog::warn("ML model not loaded from '{}' -- analysis will be unavailable",
                     config.modelPath().string());
    }

    // -- Threat Intelligence --
    auto threatIntel = std::make_unique<nids::infra::ThreatIntelProvider>();
    auto tiDir = config.threatIntelDirectory().string();
    if (std::filesystem::is_directory(tiDir)) {
        auto loaded = threatIntel->loadFeeds(tiDir);
        spdlog::info("Loaded {} threat intelligence entries from {} feed(s)",
                     loaded, threatIntel->feedCount());
    } else {
        spdlog::info("Threat intelligence directory '{}' not found -- "
                     "TI lookups will return no matches", tiDir);
    }

    // -- Heuristic Rule Engine --
    auto ruleEngine = std::make_unique<nids::infra::HeuristicRuleEngine>();
    spdlog::info("Heuristic rule engine initialized with {} rules",
                 ruleEngine->ruleCount());

    // -- Hybrid Detection Service --
    auto hybridService = std::make_unique<nids::app::HybridDetectionService>(
        threatIntel.get(), ruleEngine.get());
    hybridService->setWeights({
        .ml = config.weightMl(),
        .threatIntel = config.weightThreatIntel(),
        .heuristic = config.weightHeuristic()
    });
    hybridService->setConfidenceThreshold(config.mlConfidenceThreshold());

    // -- Analysis Service --
    auto flowExtractor = std::make_unique<nids::infra::NativeFlowExtractor>();
    auto analysisService = std::make_unique<nids::app::AnalysisService>(
        std::move(analyzer), std::move(flowExtractor));

    // Load normalization parameters so inference receives data in the same
    // format the model was trained on (StandardScaler + clip).
    if (!analysisService->loadNormalization(config.modelMetadataPath().string())) {
        spdlog::warn("Feature normalization metadata not loaded from '{}' -- "
                     "predictions may be inaccurate",
                     config.modelMetadataPath().string());
    }

    // Wire hybrid detection into the analysis pipeline
    analysisService->setHybridDetection(hybridService.get());

    nids::ui::MainWindow window(std::move(controller), std::move(analysisService));
    window.show();

    return app.exec();
}
