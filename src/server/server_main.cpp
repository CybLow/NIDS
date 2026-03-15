/// Headless NIDS daemon entry point.
///
/// Runs the ML-based intrusion detection pipeline as a gRPC server.
/// Clients connect via gRPC to start/stop captures and stream detections.
///
/// Usage:
///   nids-server --interface eth0 [--config config.json] [--bpf "tcp"]
///               [--listen 0.0.0.0:50051] [--no-grpc]
///
/// Modes:
///   Default:    Start gRPC server, wait for client to start capture via RPC.
///   --no-grpc:  Start capture immediately (standalone, no gRPC server).
///
/// Signals: SIGINT / SIGTERM trigger graceful shutdown.

#include "server/NidsServer.h"

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

// gRPC 1.72.0 has use-after-poison false positives in its epoll/thread-pool
// internals (abseil StatusRep::SetPayload) when compiled with GCC 15 + ASan.
// Disable user-poisoning detection to avoid false aborts from gRPC's arena.
#if defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer)
extern "C" const char* __asan_default_options() {  // NOLINT
    return "allow_user_poisoning=0";
}
#endif

namespace {

std::atomic<bool> gShutdownRequested{false};

void signalHandler(int /*signum*/) {
    gShutdownRequested.store(true);
}

struct CliArgs {
    std::filesystem::path configPath;
    std::string interface;
    std::string bpfFilter;
    std::string listenAddress = "0.0.0.0:50051";
    bool noGrpc = false;
};

void printUsage(std::string_view progName) {
    std::cerr << "Usage: " << progName
              << " [--interface <iface>] [--config <path>] [--bpf <filter>]\n"
              << "       [--listen <addr:port>] [--no-grpc] [--help]\n"
              << "\n"
              << "Options:\n"
              << "  --interface <iface>  Network interface (required with --no-grpc)\n"
              << "  --config <path>      JSON configuration file\n"
              << "  --bpf <filter>       BPF filter expression\n"
              << "  --listen <addr>      gRPC listen address (default: 0.0.0.0:50051)\n"
              << "  --no-grpc            Run standalone without gRPC server\n"
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
        } else if (arg == "--listen" && i + 1 < argc) {
            args.listenAddress = argv[++i];
        } else if (arg == "--no-grpc") {
            args.noGrpc = true;
        } else if (arg == "--help") {
            printUsage(argv[0]);
            std::exit(0);
        }
    }
    return args;
}

/// Run in standalone mode (no gRPC, direct capture + console output).
int runStandalone(const CliArgs& args,
                  nids::infra::PcapCapture& capture,
                  nids::infra::NativeFlowExtractor& flowExtractor,
                  nids::core::IPacketAnalyzer& analyzer,
                  nids::core::IFeatureNormalizer& normalizer,
                  nids::app::HybridDetectionService& hybridService) {

    nids::core::CaptureSession session;
    auto pipeline = std::make_unique<nids::app::LiveDetectionPipeline>(
        flowExtractor, analyzer, normalizer, session);
    pipeline->setHybridDetection(&hybridService);

    auto consoleSink = std::make_unique<nids::infra::ConsoleAlertSink>(
        nids::infra::ConsoleFilter::Flagged);
    pipeline->addOutputSink(consoleSink.get());

    capture.setRawPacketCallback(
        [&pipeline](const std::uint8_t* data, std::size_t length,
                    std::int64_t timestampUs) {
            pipeline->feedPacket(data, length, timestampUs);
        });

    spdlog::info("Starting capture on '{}' (Ctrl+C to stop)", args.interface);
    pipeline->start();
    capture.startCapture("");

    while (!gShutdownRequested.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    spdlog::info("Shutdown requested — stopping capture");
    const auto flowsDetected = pipeline->flowsDetected();
    const auto droppedFlows = pipeline->droppedFlows();
    capture.stopCapture();
    pipeline->stop();

    spdlog::info("Session complete: {} flows detected, {} dropped",
                 flowsDetected, droppedFlows);
    return 0;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    spdlog::set_level(spdlog::level::info);

    auto args = parseArgs(argc, argv);

    // Standalone mode requires an interface
    if (args.noGrpc && args.interface.empty()) {
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
        spdlog::warn("ML model not loaded from '{}' — analysis unavailable",
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
        spdlog::warn("Feature normalization metadata not loaded — "
                     "predictions may be inaccurate");
    }

    // -- Packet Capture --
    auto capture = std::make_unique<nids::infra::PcapCapture>();

    // -- Mode selection --
    if (args.noGrpc) {
        // Standalone mode: initialize capture immediately
        if (!capture->initialize(args.interface, args.bpfFilter)) {
            spdlog::critical("Failed to initialize capture on '{}'",
                             args.interface);
            return 1;
        }
        return runStandalone(args, *capture, *flowExtractor, *analyzer,
                             *normalizer, *hybridService);
    }

    // -- gRPC server mode --
    // Pre-initialize capture if interface was specified via CLI
    if (!args.interface.empty()) {
        if (!capture->initialize(args.interface, args.bpfFilter)) {
            spdlog::critical("Failed to initialize capture on '{}'",
                             args.interface);
            return 1;
        }
    }

    // Create gRPC service implementation
    auto service = std::make_unique<nids::server::NidsServiceImpl>(
        *capture, *flowExtractor, *analyzer, *normalizer, *hybridService);

    // Create and start gRPC server
    nids::server::ServerConfig serverConfig{
        .listenAddress = args.listenAddress,
        .maxConcurrentSessions = 4,
    };
    nids::server::NidsServer grpcServer(serverConfig);
    grpcServer.setService(std::move(service));
    grpcServer.start();

    // If interface specified on CLI, auto-start capture via gRPC service
    // (clients can also start capture later via StartCapture RPC)

    // Block until shutdown signal
    while (!gShutdownRequested.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    spdlog::info("Shutdown requested — stopping gRPC server");
    grpcServer.stop();

    return 0;
}
