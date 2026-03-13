#include "core/services/Configuration.h"
#include "infra/config/ConfigLoader.h"
#include "infra/platform/SocketInit.h"
#include "infra/capture/PcapCapture.h"
#include "infra/analysis/AnalyzerFactory.h"
#include "infra/analysis/FeatureNormalizer.h"
#include "infra/flow/NativeFlowExtractor.h"
#include "infra/threat/ThreatIntelProvider.h"
#include "infra/rules/HeuristicRuleEngine.h"
#include "app/CaptureController.h"
#include "app/AnalysisService.h"
#include "app/HybridDetectionService.h"
#include "ui/MainWindow.h"

#include <QApplication>

#include <spdlog/spdlog.h>

#include <filesystem>
#include <memory>
#include <string_view>

namespace {

/// Parse --config <path> from command-line arguments.
/// Returns the config file path, or empty if not specified.
std::filesystem::path parseConfigArg(int argc, char* argv[]) {
    for (int i = 1; i < argc - 1; ++i) {
        if (std::string_view{argv[i]} == "--config") {
            return argv[i + 1];
        }
    }
    return {};
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    spdlog::set_level(spdlog::level::info);

    nids::platform::NetworkInitGuard networkGuard;
    if (!networkGuard.isInitialized()) {
        spdlog::critical("Failed to initialize networking");
        return 1;
    }

    auto& config = nids::core::Configuration::instance();

    // Load config from JSON file if --config <path> is provided
    if (auto configPath = parseConfigArg(argc, argv);
        !configPath.empty() && !nids::infra::loadConfigFromFile(configPath, config)) {
        spdlog::critical("Failed to parse config file '{}'", configPath.string());
        return 1;
    }

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
    if (auto tiDir = config.threatIntelDirectory().string(); std::filesystem::is_directory(tiDir)) {
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
    auto featureNormalizer = std::make_unique<nids::infra::FeatureNormalizer>();
    auto analysisService = std::make_unique<nids::app::AnalysisService>(
        std::move(analyzer), std::move(flowExtractor), std::move(featureNormalizer));

    // Load normalization parameters so inference receives data in the same
    // format the model was trained on (StandardScaler + clip).
    if (!analysisService->loadNormalization(config.modelMetadataPath().string())) {
        spdlog::warn("Feature normalization metadata not loaded from '{}' -- "
                     "predictions may be inaccurate",
                     config.modelMetadataPath().string());
    }

    // Wire hybrid detection into the analysis pipeline
    analysisService->setHybridDetection(hybridService.get());

    nids::ui::MainWindow window(std::move(controller), std::move(analysisService),
                                 hybridService.get(), threatIntel.get(), ruleEngine.get());
    window.show();

    return QApplication::exec();
}
