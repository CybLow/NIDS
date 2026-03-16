#include "app/HeadlessCaptureRunner.h"

#include "app/LiveDetectionPipeline.h"
#include "core/model/CaptureSession.h"

#include <spdlog/spdlog.h>

#include <chrono>
#include <thread>

namespace nids::app {

namespace {
/// Poll interval for the shutdown-requested flag.
constexpr auto kShutdownPollInterval = std::chrono::milliseconds(200);
} // namespace

int runHeadlessCapture(const HeadlessRunnerConfig& config) {
    // -- Session + pipeline --
    nids::core::CaptureSession session;
    auto pipeline = std::make_unique<LiveDetectionPipeline>(
        *config.flowExtractor, *config.analyzer, *config.normalizer, session);
    pipeline->setHybridDetection(config.hybridService);

    // -- Register output sinks --
    for (auto* sink : config.sinks) {
        pipeline->addOutputSink(sink);
    }

    // -- Wire raw packets into pipeline --
    config.capture->setRawPacketCallback(
        [&pipeline](const std::uint8_t* data, std::size_t length,
                    std::int64_t timestampUs) {
            pipeline->feedPacket(data, length, timestampUs);
        });

    // -- Start --
    spdlog::info("Starting capture on '{}' (Ctrl+C to stop)",
                 config.interfaceName);
    pipeline->start();
    config.capture->startCapture("");

    // -- Wait for shutdown --
    while (!config.shutdownRequested()) {
        std::this_thread::sleep_for(kShutdownPollInterval);
    }

    // -- Stop --
    spdlog::info("Shutdown requested -- stopping capture");
    const auto flowsDetected = pipeline->flowsDetected();
    const auto droppedFlows = pipeline->droppedFlows();
    config.capture->stopCapture();
    pipeline->stop();

    spdlog::info("Session complete: {} flows detected, {} dropped",
                 flowsDetected, droppedFlows);
    return 0;
}

} // namespace nids::app
