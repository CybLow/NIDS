/// Headless NIDS daemon entry point.
///
/// Runs the ML-based intrusion detection pipeline without a GUI.
/// Uses PcapCapture + LiveDetectionPipeline + HybridDetectionService.
///
/// Usage:
///   nids-server --interface eth0 [--config config.json] [--bpf "tcp"]
///
/// Signals: SIGINT / SIGTERM trigger graceful shutdown.

#include "app/HybridDetectionService.h"
#include "app/LiveDetectionPipeline.h"
#include "core/model/CaptureSession.h"
#include "core/model/DetectionResult.h"
#include "core/services/Configuration.h"
#include "infra/analysis/AnalyzerFactory.h"
#include "infra/analysis/FeatureNormalizer.h"
#include "infra/capture/PcapCapture.h"
#include "infra/config/ConfigLoader.h"
#include "infra/flow/NativeFlowExtractor.h"
#include "infra/output/ConsoleAlertSink.h"
#include "infra/platform/SocketInit.h"
#include "infra/rules/HeuristicRuleEngine.h"
#include "infra/threat/ThreatIntelProvider.h"

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

std::atomic<bool> gShutdownRequested{false};

void signalHandler(int /*signum*/) {
    gShutdownRequested.store(true);
}

struct CliArgs {
    std::filesystem::path configPath;
    std::string interface;
    std::string bpfFilter;
};

void printUsage(std::string_view progName) {
    std::cerr << "Usage: " << progName
              << " --interface <iface> [--config <path>] [--bpf <filter>]\n"
              << "\n"
              << "Options:\n"
              << "  --interface <iface>  Network interface to capture on (required)\n"
              << "  --config <path>      JSON configuration file\n"
              << "  --bpf <filter>       BPF filter expression\n"
              << "  --help               Show this help message\n";
}

CliArgs parseArgs(int argc, char* argv[]) {
    CliArgs args;
    for (int i = 1; i < argc; ++i) {
        auto arg = std::string_view{argv[i]};
        if (arg == "--interface" && i + 1 < argc) {
            args.interface = argv[++i];
        } else if (arg == "--config" && i + 1 < argc) {
            args.configPath = argv[++i];
        } else if (arg == "--bpf" && i + 1 < argc) {
            args.bpfFilter = argv[++i];
        } else if (arg == "--help") {
            printUsage(argv[0]);
            std::exit(0);
        }
    }
    return args;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    spdlog::set_level(spdlog::level::info);

    auto args = parseArgs(argc, argv);
    if (args.interface.empty()) {
        printUsage(argv[0]);
        return 1;
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
    auto normalizer = std::make_unique<nids::infra::FeatureNormalizer>();
    if (!normalizer->loadMetadata(config.modelMetadataPath().string())) {
        spdlog::warn("Feature normalization metadata not loaded -- "
                     "predictions may be inaccurate");
    }

    // -- Capture Session + Pipeline --
    nids::core::CaptureSession session;
    auto pipeline = std::make_unique<nids::app::LiveDetectionPipeline>(
        *flowExtractor, *analyzer, *normalizer, session);
    pipeline->setHybridDetection(hybridService.get());

    // -- Output Sinks --
    // Console sink logs flagged (attack) flows to stderr via spdlog.
    // Additional sinks (JSON file, syslog, gRPC stream) can be added here.
    auto consoleSink = std::make_unique<nids::infra::ConsoleAlertSink>(
        nids::infra::ConsoleFilter::Flagged);
    pipeline->addOutputSink(consoleSink.get());

    // -- Packet Capture --
    auto capture = std::make_unique<nids::infra::PcapCapture>();
    if (!capture->initialize(args.interface, args.bpfFilter)) {
        spdlog::critical("Failed to initialize capture on '{}'",
                         args.interface);
        return 1;
    }

    // Wire raw packets into the live detection pipeline.
    capture->setRawPacketCallback(
        [&pipeline](const std::uint8_t* data, std::size_t length,
                    std::int64_t timestampUs) {
            pipeline->feedPacket(data, length, timestampUs);
        });

    // -- Start --
    spdlog::info("Starting capture on interface '{}' (Ctrl+C to stop)",
                 args.interface);
    pipeline->start();
    capture->startCapture("");

    // Block until shutdown signal.
    while (!gShutdownRequested.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // -- Graceful shutdown --
    spdlog::info("Shutdown requested — stopping capture");
    capture->stopCapture();
    pipeline->stop();

    spdlog::info("Session complete: {} flows detected, {} dropped",
                 pipeline->flowsDetected(), pipeline->droppedFlows());

    return 0;
}
