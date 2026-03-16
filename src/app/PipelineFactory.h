#pragma once

/// Factory for constructing the ML detection pipeline service graph.
///
/// Eliminates the ~50-line near-identical service construction that was
/// duplicated in main.cpp (headless + GUI) and server_main.cpp.
///
/// Lives in app/ because it depends on core/ interfaces and orchestrates
/// infra/ implementations via factory functions.

#include "app/HybridDetectionService.h"
#include "core/services/Configuration.h"
#include "core/services/IFeatureNormalizer.h"
#include "core/services/IFlowExtractor.h"
#include "core/services/IPacketAnalyzer.h"
#include "core/services/IRuleEngine.h"
#include "core/services/IThreatIntelligence.h"

#include <memory>

namespace nids::app {

/**
 * Bundle of shared detection services (TI + rules + hybrid).
 *
 * These are constructed once per process and shared across all pipelines
 * (batch AnalysisService, live LiveDetectionPipeline, gRPC sessions).
 * The bundle owns the three services and exposes non-owning pointers.
 */
struct DetectionServices {
    std::unique_ptr<nids::core::IThreatIntelligence> threatIntel;
    std::unique_ptr<nids::core::IRuleEngine> ruleEngine;
    std::unique_ptr<HybridDetectionService> hybridService;
};

/**
 * Bundle of per-pipeline ML services (analyzer + normalizer + extractor).
 *
 * Each pipeline (batch or live) needs its own set because ONNX sessions
 * are not thread-safe and flow extractors maintain per-flow state.
 */
struct MlServices {
    std::unique_ptr<nids::core::IPacketAnalyzer> analyzer;
    std::unique_ptr<nids::core::IFeatureNormalizer> normalizer;
    std::unique_ptr<nids::core::IFlowExtractor> flowExtractor;
};

/**
 * Factory for constructing the detection pipeline service graph.
 *
 * Usage:
 *   auto& config = Configuration::instance();
 *   auto detection = PipelineFactory::createDetectionServices(config);
 *   auto ml = PipelineFactory::createMlServices(config);
 *   auto liveMl = PipelineFactory::createLiveMlServices(config);
 */
class PipelineFactory {
public:
    /// Create the shared detection services (TI, rules, hybrid).
    /// Loads TI feeds from the configured directory and sets hybrid weights.
    [[nodiscard]] static DetectionServices createDetectionServices(
        const nids::core::Configuration& config);

    /// Create a set of ML services for batch analysis.
    /// Does NOT set flow extractor timeouts (batch uses file timestamps).
    [[nodiscard]] static MlServices createMlServices(
        const nids::core::Configuration& config);

    /// Create a set of ML services configured for live capture.
    /// Sets flow extractor timeouts from config (live mode values).
    [[nodiscard]] static MlServices createLiveMlServices(
        const nids::core::Configuration& config);
};

} // namespace nids::app
