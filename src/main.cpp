#include "app/AnalysisService.h"
#include "app/CaptureController.h"
#include "app/HybridDetectionService.h"
#include "app/LiveDetectionPipeline.h"
#include "core/model/CaptureSession.h"
#include "core/model/DetectionResult.h"
#include "core/services/Configuration.h"
#include "core/services/IFlowExtractor.h"
#include "infra/analysis/AnalyzerFactory.h"
#include "infra/analysis/FeatureNormalizer.h"
#include "infra/capture/PcapCapture.h"
#include "infra/config/ConfigLoader.h"
#include "infra/flow/NativeFlowExtractor.h"
#include "infra/output/ConsoleAlertSink.h"
#include "infra/platform/SocketInit.h"
#include "infra/rules/HeuristicRuleEngine.h"
#include "infra/threat/ThreatIntelProvider.h"
#include "ui/MainWindow.h"

#include <QApplication>

#include <spdlog/spdlog.h>

#include <atomic>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

namespace {

/// Parsed command-line arguments (pre-Qt).
struct CliArgs {
    std::filesystem::path configPath;
    std::string interface;
    std::string bpfFilter;
    bool headless = false;
    bool showHelp = false;
};

std::atomic<bool> gShutdownRequested{false};

void signalHandler(int /*signum*/) {
    gShutdownRequested.store(true);
}

CliArgs parseArgs(int argc, char* argv[]) {
    CliArgs args;
    for (int i = 1; i < argc; ++i) {
        auto arg = std::string_view{argv[i]};
        if (arg == "--config" && i + 1 < argc) {
            args.configPath = argv[++i];
        } else if (arg == "--interface" && i + 1 < argc) {
            args.interface = argv[++i];
        } else if (arg == "--bpf" && i + 1 < argc) {
            args.bpfFilter = argv[++i];
        } else if (arg == "--headless") {
            args.headless = true;
        } else if (arg == "--help" || arg == "-h") {
            args.showHelp = true;
        }
    }
    return args;
}

void printUsage(std::string_view progName) {
    std::cerr
        << "Usage: " << progName << " [options]\n"
        << "\n"
        << "Modes:\n"
        << "  (default)            Launch the Qt6 GUI\n"
        << "  --headless           Run as a console-only daemon (no GUI)\n"
        << "\n"
        << "Options:\n"
        << "  --interface <iface>  Network interface (required for --headless)\n"
        << "  --bpf <filter>       BPF filter expression\n"
        << "  --config <path>      JSON configuration file\n"
        << "  --help, -h           Show this help message\n"
        << "\n"
        << "For gRPC server mode, use the nids-server binary instead.\n";
}

/// Run in headless mode: capture + live detection + console output.
/// Returns process exit code.
int runHeadless(const CliArgs& args,
                nids::core::Configuration& config) {
    // -- Signal handling --
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    // -- ML Analyzer --
    auto analyzer = nids::infra::createAnalyzer();
    if (!analyzer->loadModel(config.modelPath().string())) {
        spdlog::warn("ML model not loaded from '{}' -- analysis unavailable",
                     config.modelPath().string());
    }

    // -- Threat Intelligence --
    auto threatIntel = std::make_unique<nids::infra::ThreatIntelProvider>();
    if (auto tiDir = config.threatIntelDirectory().string();
        std::filesystem::is_directory(tiDir)) {
        auto loaded = threatIntel->loadFeeds(tiDir);
        spdlog::info("Loaded {} threat intelligence entries from {} feed(s)",
                     loaded, threatIntel->feedCount());
    }

    // -- Heuristic Rule Engine --
    auto ruleEngine = std::make_unique<nids::infra::HeuristicRuleEngine>();
    spdlog::info("Heuristic rule engine initialized with {} rules",
                 ruleEngine->ruleCount());

    // -- Hybrid Detection Service --
    auto hybridService = std::make_unique<nids::app::HybridDetectionService>(
        threatIntel.get(), ruleEngine.get());
    hybridService->setWeights({.ml = config.weightMl(),
                               .threatIntel = config.weightThreatIntel(),
                               .heuristic = config.weightHeuristic()});
    hybridService->setConfidenceThreshold(config.mlConfidenceThreshold());

    // -- Flow Extractor + Normalizer --
    auto flowExtractor = std::make_unique<nids::infra::NativeFlowExtractor>();
    flowExtractor->setFlowTimeout(config.liveFlowTimeoutUs());
    flowExtractor->setMaxFlowDuration(config.maxFlowDurationUs());

    auto normalizer = std::make_unique<nids::infra::FeatureNormalizer>();
    if (!normalizer->loadMetadata(config.modelMetadataPath().string())) {
        spdlog::warn("Feature normalization metadata not loaded -- "
                     "predictions may be inaccurate");
    }

    // -- Packet Capture --
    auto capture = std::make_unique<nids::infra::PcapCapture>();
    if (!capture->initialize(args.interface, args.bpfFilter)) {
        spdlog::critical("Failed to initialize capture on '{}'",
                         args.interface);
        return 1;
    }

    // -- Pipeline --
    nids::core::CaptureSession session;
    auto pipeline = std::make_unique<nids::app::LiveDetectionPipeline>(
        *flowExtractor, *analyzer, *normalizer, session);
    pipeline->setHybridDetection(hybridService.get());

    auto consoleSink = std::make_unique<nids::infra::ConsoleAlertSink>(
        nids::infra::ConsoleFilter::Flagged);
    pipeline->addOutputSink(consoleSink.get());

    capture->setRawPacketCallback(
        [&pipeline](const std::uint8_t* data, std::size_t length,
                    std::int64_t timestampUs) {
            pipeline->feedPacket(data, length, timestampUs);
        });

    spdlog::info("Starting headless capture on '{}' (Ctrl+C to stop)",
                 args.interface);
    pipeline->start();
    capture->startCapture("");

    while (!gShutdownRequested.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    spdlog::info("Shutdown requested -- stopping capture");
    const auto flowsDetected = pipeline->flowsDetected();
    const auto droppedFlows = pipeline->droppedFlows();
    capture->stopCapture();
    pipeline->stop();

    spdlog::info("Session complete: {} flows detected, {} dropped",
                 flowsDetected, droppedFlows);
    return 0;
}

/// Run in GUI mode: Qt application with MainWindow.
int runGui(int argc, char* argv[],
           nids::core::Configuration& config) {
    QApplication app(argc, argv);

    qRegisterMetaType<nids::core::PacketInfo>("nids::core::PacketInfo");
    qRegisterMetaType<nids::core::DetectionResult>(
        "nids::core::DetectionResult");
    qRegisterMetaType<nids::core::FlowInfo>("nids::core::FlowInfo");

    auto capture = std::make_unique<nids::infra::PcapCapture>();
    auto controller =
        std::make_unique<nids::app::CaptureController>(std::move(capture));

    auto analyzer = nids::infra::createAnalyzer();
    if (!analyzer->loadModel(config.modelPath().string())) {
        spdlog::warn(
            "ML model not loaded from '{}' -- analysis will be unavailable",
            config.modelPath().string());
    }

    // -- Threat Intelligence --
    auto threatIntel = std::make_unique<nids::infra::ThreatIntelProvider>();
    if (auto tiDir = config.threatIntelDirectory().string();
        std::filesystem::is_directory(tiDir)) {
        auto loaded = threatIntel->loadFeeds(tiDir);
        spdlog::info("Loaded {} threat intelligence entries from {} feed(s)",
                     loaded, threatIntel->feedCount());
    } else {
        spdlog::info("Threat intelligence directory '{}' not found -- "
                     "TI lookups will return no matches",
                     tiDir);
    }

    // -- Heuristic Rule Engine --
    auto ruleEngine = std::make_unique<nids::infra::HeuristicRuleEngine>();
    spdlog::info("Heuristic rule engine initialized with {} rules",
                 ruleEngine->ruleCount());

    // -- Hybrid Detection Service --
    auto hybridService = std::make_unique<nids::app::HybridDetectionService>(
        threatIntel.get(), ruleEngine.get());
    hybridService->setWeights({.ml = config.weightMl(),
                               .threatIntel = config.weightThreatIntel(),
                               .heuristic = config.weightHeuristic()});
    hybridService->setConfidenceThreshold(config.mlConfidenceThreshold());

    // -- Analysis Service --
    auto flowExtractor = std::make_unique<nids::infra::NativeFlowExtractor>();
    auto featureNormalizer =
        std::make_unique<nids::infra::FeatureNormalizer>();
    auto analysisService = std::make_unique<nids::app::AnalysisService>(
        std::move(analyzer), std::move(flowExtractor),
        std::move(featureNormalizer));

    if (!analysisService->loadNormalization(
            config.modelMetadataPath().string())) {
        spdlog::warn("Feature normalization metadata not loaded from '{}' -- "
                     "predictions may be inaccurate",
                     config.modelMetadataPath().string());
    }

    analysisService->setHybridDetection(hybridService.get());

    // -- Live Detection Pipeline --
    auto liveFlowExtractor =
        std::make_unique<nids::infra::NativeFlowExtractor>();
    liveFlowExtractor->setFlowTimeout(config.liveFlowTimeoutUs());
    liveFlowExtractor->setMaxFlowDuration(config.maxFlowDurationUs());
    auto liveNormalizer = std::make_unique<nids::infra::FeatureNormalizer>();
    if (!liveNormalizer->loadMetadata(config.modelMetadataPath().string())) {
        spdlog::warn("Live detection normalizer metadata not loaded -- "
                     "live predictions may be inaccurate");
    }

    auto liveAnalyzer = nids::infra::createAnalyzer();
    if (!liveAnalyzer->loadModel(config.modelPath().string())) {
        spdlog::warn("Live detection ML model not loaded -- "
                     "live analysis will be unavailable");
    }

    auto pipeline = std::make_unique<nids::app::LiveDetectionPipeline>(
        *liveFlowExtractor, *liveAnalyzer, *liveNormalizer,
        controller->session());
    pipeline->setHybridDetection(hybridService.get());
    controller->enableLiveDetection(pipeline.get());

    nids::ui::MainWindow window(std::move(controller),
                                std::move(analysisService),
                                hybridService.get(), threatIntel.get(),
                                ruleEngine.get());
    window.show();

    return QApplication::exec();
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    spdlog::set_level(spdlog::level::info);

    auto args = parseArgs(argc, argv);

    if (args.showHelp) {
        printUsage(argv[0]);
        return 0;
    }

    // -- Network init --
    nids::platform::NetworkInitGuard networkGuard;
    if (!networkGuard.isInitialized()) {
        spdlog::critical("Failed to initialize networking");
        return 1;
    }

    // -- Configuration --
    auto& config = nids::core::Configuration::instance();
    if (!args.configPath.empty() &&
        !nids::infra::loadConfigFromFile(args.configPath, config)) {
        spdlog::critical("Failed to parse config file '{}'",
                         args.configPath.string());
        return 1;
    }

    // -- Mode selection --
    if (args.headless) {
        if (args.interface.empty()) {
            std::cerr << "Error: --headless requires --interface <iface>\n\n";
            printUsage(argv[0]);
            return 1;
        }
        return runHeadless(args, config);
    }

    return runGui(argc, argv, config);
}
