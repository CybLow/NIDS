#pragma once

/// Reusable headless capture runner for daemon and --headless modes.
///
/// Encapsulates the common pipeline-setup / capture-loop / shutdown
/// sequence shared by main.cpp --headless and server_main.cpp --no-grpc.
///
/// Pure C++23 — no Qt, no infra dependencies.  All platform-specific
/// concerns (signal handling, console output) are injected.

#include "app/HybridDetectionService.h"
#include "core/model/CaptureSession.h"
#include "core/services/IFeatureNormalizer.h"
#include "core/services/IFlowExtractor.h"
#include "core/services/IOutputSink.h"
#include "core/services/IPacketAnalyzer.h"
#include "core/services/IPacketCapture.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace nids::app {

class LiveDetectionPipeline;

/**
 * Configuration for the headless capture runner.
 *
 * All references/pointers are non-owning and must outlive the runner.
 */
struct HeadlessRunnerConfig {
    /// Network interface name (for logging).
    std::string interfaceName;

    /// Injected dependencies (non-owning).
    core::IPacketCapture* capture = nullptr;
    core::IFlowExtractor* flowExtractor = nullptr;
    core::IPacketAnalyzer* analyzer = nullptr;
    core::IFeatureNormalizer* normalizer = nullptr;
    HybridDetectionService* hybridService = nullptr;

    /// Optional output sinks (non-owning).  Added to the pipeline.
    std::vector<core::IOutputSink*> sinks;

    /// Predicate polled to determine when to stop.
    /// Returns true when shutdown has been requested.
    std::function<bool()> shutdownRequested;
};

/**
 * Run a headless capture loop: create pipeline, wire capture, wait for
 * shutdown, stop, and return an exit code.
 *
 * @return 0 on success, non-zero on error.
 */
[[nodiscard]] int runHeadlessCapture(const HeadlessRunnerConfig& config);

} // namespace nids::app
