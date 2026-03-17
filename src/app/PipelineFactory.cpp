#include "app/PipelineFactory.h"
#include "infra/analysis/AnalyzerFactory.h"
#include "infra/analysis/FeatureNormalizer.h"
#include "infra/flow/NativeFlowExtractor.h"
#include "infra/rules/HeuristicRuleEngine.h"
#include "infra/threat/ThreatIntelProvider.h"

#include <spdlog/spdlog.h>

#include <filesystem>

namespace nids::app {

DetectionServices
PipelineFactory::createDetectionServices(const core::Configuration &config) {

  DetectionServices services;

  // -- Threat Intelligence --
  auto threatIntel = std::make_unique<infra::ThreatIntelProvider>();
  if (auto tiDir = config.threatIntelDirectory().string();
      std::filesystem::is_directory(tiDir)) {
    auto loaded = threatIntel->loadFeeds(tiDir);
    spdlog::info("Loaded {} threat intelligence entries from {} feed(s)",
                 loaded, threatIntel->feedCount());
  }
  services.threatIntel = std::move(threatIntel);

  // -- Heuristic Rule Engine --
  auto ruleEngine = std::make_unique<infra::HeuristicRuleEngine>();
  spdlog::info("Heuristic rule engine initialized with {} rules",
               ruleEngine->ruleCount());
  services.ruleEngine = std::move(ruleEngine);

  // -- Hybrid Detection Service --
  services.hybridService = std::make_unique<HybridDetectionService>(
      services.threatIntel.get(), services.ruleEngine.get());
  services.hybridService->setWeights({.ml = config.weightMl(),
                                      .threatIntel = config.weightThreatIntel(),
                                      .heuristic = config.weightHeuristic()});
  services.hybridService->setConfidenceThreshold(
      config.mlConfidenceThreshold());

  return services;
}

MlServices
PipelineFactory::createMlServices(const core::Configuration &config) {

  MlServices services;

  // -- ML Analyzer --
  services.analyzer = infra::createAnalyzer();
  if (auto result = services.analyzer->loadModel(config.modelPath().string());
      !result.has_value()) {
    spdlog::warn("ML model not loaded from '{}': {}",
                 config.modelPath().string(), result.error());
  }

  // -- Feature Normalizer --
  auto normalizer = std::make_unique<infra::FeatureNormalizer>();
  if (auto result =
          normalizer->loadMetadata(config.modelMetadataPath().string());
      !result.has_value()) {
    spdlog::warn("Feature normalization metadata not loaded: {}",
                 result.error());
  }
  services.normalizer = std::move(normalizer);

  // -- Flow Extractor (batch mode — no timeout overrides) --
  services.flowExtractor = std::make_unique<infra::NativeFlowExtractor>();

  return services;
}

MlServices
PipelineFactory::createLiveMlServices(const core::Configuration &config) {

  auto services = createMlServices(config);

  // Override flow extractor timeouts for live capture.
  services.flowExtractor->setFlowTimeout(config.liveFlowTimeoutUs());
  services.flowExtractor->setMaxFlowDuration(config.maxFlowDurationUs());

  return services;
}

} // namespace nids::app
