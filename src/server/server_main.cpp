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

#include "app/HeadlessCaptureRunner.h"
#include "app/PipelineFactory.h"
#include "core/services/Configuration.h"
#include "infra/capture/PcapCapture.h"
#include "infra/config/ConfigLoader.h"
#include "infra/output/ConsoleAlertSink.h"
#include "infra/platform/SignalHandler.h"
#include "infra/platform/SocketInit.h"

#include <spdlog/spdlog.h>

#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

#include "infra/platform/AsanOptions.h" // shared gRPC ASan workaround

namespace {

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

struct ParseResult {
    CliArgs args;
    bool showHelp = false;
};

ParseResult parseArgs(int argc, char* argv[]) {
    ParseResult result;
    for (int i = 1; i < argc; ++i) {
        auto arg = std::string_view{argv[i]};
        if (arg == "--interface" && i + 1 < argc) {
            result.args.interface = argv[++i];
        } else if (arg == "--config" && i + 1 < argc) {
            result.args.configPath = argv[++i];
        } else if (arg == "--bpf" && i + 1 < argc) {
            result.args.bpfFilter = argv[++i];
        } else if (arg == "--listen" && i + 1 < argc) {
            result.args.listenAddress = argv[++i];
        } else if (arg == "--no-grpc") {
            result.args.noGrpc = true;
        } else if (arg == "--help") {
            result.showHelp = true;
        }
    }
    return result;
}

/// Run in standalone mode (no gRPC, direct capture + console output).
int runStandalone(const CliArgs& args,
                  nids::core::IPacketCapture& capture,
                  nids::core::IFlowExtractor& flowExtractor,
                  nids::core::IPacketAnalyzer& analyzer,
                  nids::core::IFeatureNormalizer& normalizer,
                  nids::app::HybridDetectionService& hybridService) {

    auto consoleSink = std::make_unique<nids::infra::ConsoleAlertSink>(
        nids::infra::ConsoleFilter::Flagged);

    nids::app::HeadlessRunnerConfig config{
        .interfaceName = args.interface,
        .capture = &capture,
        .flowExtractor = &flowExtractor,
        .analyzer = &analyzer,
        .normalizer = &normalizer,
        .hybridService = &hybridService,
        .sinks = {consoleSink.get()},
        .shutdownRequested = [] {
            return nids::infra::platform::gShutdownRequested.load();
        },
    };
    return nids::app::runHeadlessCapture(config);
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    spdlog::set_level(spdlog::level::info);

    auto [args, showHelp] = parseArgs(argc, argv);

    if (showHelp) {
        printUsage(argv[0]);
        return 0;
    }

    // Standalone mode requires an interface
    if (args.noGrpc && args.interface.empty()) {
        printUsage(argv[0]);
        return 1;
    }

    // -- Network init --
    nids::infra::platform::NetworkInitGuard networkGuard;
    if (!networkGuard.isInitialized()) {
        spdlog::critical("Failed to initialize networking");
        return 1;
    }

    // -- Configuration --
    auto& config = nids::core::Configuration::instance();
    if (!args.configPath.empty()) {
        if (auto result = nids::infra::loadConfigFromFile(args.configPath, config);
            !result) {
            spdlog::critical("Failed to parse config file '{}': {}",
                             args.configPath.string(), result.error());
            return 1;
        }
    }

    // -- Signal handling --
    nids::infra::platform::installSignalHandlers();

    // -- Detection services (TI + rules + hybrid) --
    auto detection = nids::app::PipelineFactory::createDetectionServices(config);

    // -- ML services (analyzer + normalizer + flow extractor) --
    auto ml = nids::app::PipelineFactory::createLiveMlServices(config);

    // -- Packet Capture --
    auto capture = std::make_unique<nids::infra::PcapCapture>();

    // -- Mode selection --
    if (args.noGrpc) {
        // Standalone mode: initialize capture immediately
        if (auto result = capture->initialize(args.interface, args.bpfFilter);
            !result) {
            spdlog::critical("Failed to initialize capture on '{}': {}",
                             args.interface, result.error());
            return 1;
        }
        return runStandalone(args, *capture, *ml.flowExtractor, *ml.analyzer,
                             *ml.normalizer, *detection.hybridService);
    }

    // -- gRPC server mode --
    // Pre-initialize capture if interface was specified via CLI
    if (!args.interface.empty()) {
        if (auto result = capture->initialize(args.interface, args.bpfFilter);
            !result) {
            spdlog::critical("Failed to initialize capture on '{}': {}",
                             args.interface, result.error());
            return 1;
        }
    }

    // Create gRPC service implementation
    auto service = std::make_unique<nids::server::NidsServiceImpl>(
        *capture, *ml.flowExtractor, *ml.analyzer, *ml.normalizer,
        *detection.hybridService);

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
    while (!nids::infra::platform::gShutdownRequested.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    spdlog::info("Shutdown requested — stopping gRPC server");
    grpcServer.stop();

    return 0;
}
