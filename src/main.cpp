#include "app/AnalysisService.h"
#include "app/CaptureController.h"
#include "app/LiveDetectionPipeline.h"
#include "app/PipelineFactory.h"
#include "core/model/CaptureSession.h"
#include "core/model/DetectionResult.h"
#include "core/services/Configuration.h"
#include "core/services/IFlowExtractor.h"
#include "infra/capture/PcapCapture.h"
#include "infra/config/ConfigLoader.h"
#include "infra/output/ConsoleAlertSink.h"
#include "infra/platform/SignalHandler.h"
#include "infra/platform/SocketInit.h"
#include "ui/MainWindow.h"

#include <QApplication>

#include <spdlog/spdlog.h>

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
    nids::infra::platform::installSignalHandlers();

    // -- Detection services (TI + rules + hybrid) --
    auto detection = nids::app::PipelineFactory::createDetectionServices(config);

    // -- ML services (analyzer + normalizer + flow extractor) --
    auto ml = nids::app::PipelineFactory::createLiveMlServices(config);

    // -- Packet Capture --
    auto capture = std::make_unique<nids::infra::PcapCapture>();
    if (auto result = capture->initialize(args.interface, args.bpfFilter); !result) {
        spdlog::critical("Failed to initialize capture on '{}': {}",
                         args.interface, result.error());
        return 1;
    }

    // -- Pipeline --
    nids::core::CaptureSession session;
    auto pipeline = std::make_unique<nids::app::LiveDetectionPipeline>(
        *ml.flowExtractor, *ml.analyzer, *ml.normalizer, session);
    pipeline->setHybridDetection(detection.hybridService.get());

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

    while (!nids::infra::platform::gShutdownRequested.load()) {
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

    // -- Capture controller --
    auto capture = std::make_unique<nids::infra::PcapCapture>();
    auto controller =
        std::make_unique<nids::app::CaptureController>(std::move(capture));

    // -- Shared detection services (TI + rules + hybrid) --
    auto detection = nids::app::PipelineFactory::createDetectionServices(config);

    // -- Batch analysis service (owns its own analyzer + extractor + normalizer) --
    auto batchMl = nids::app::PipelineFactory::createMlServices(config);
    auto analysisService = std::make_unique<nids::app::AnalysisService>(
        std::move(batchMl.analyzer), std::move(batchMl.flowExtractor),
        std::move(batchMl.normalizer));
    if (auto result = analysisService->loadNormalization(
            config.modelMetadataPath().string()); !result) {
        spdlog::warn("Feature normalization metadata not loaded from '{}': {}",
                     config.modelMetadataPath().string(), result.error());
    }
    analysisService->setHybridDetection(detection.hybridService.get());

    // -- Live detection pipeline (owns its own analyzer + extractor + normalizer) --
    auto liveMl = nids::app::PipelineFactory::createLiveMlServices(config);
    auto pipeline = std::make_unique<nids::app::LiveDetectionPipeline>(
        *liveMl.flowExtractor, *liveMl.analyzer, *liveMl.normalizer,
        controller->session());
    pipeline->setHybridDetection(detection.hybridService.get());
    controller->enableLiveDetection(pipeline.get());

    nids::ui::MainWindow window(std::move(controller),
                                std::move(analysisService),
                                detection.hybridService.get(),
                                detection.threatIntel.get(),
                                detection.ruleEngine.get());
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
