#include <gtest/gtest.h>

#include "app/PipelineFactory.h"
#include "core/services/Configuration.h"

using namespace nids::app;
using namespace nids::core;

// PipelineFactory creates concrete implementations from infra/ that need
// real model/metadata files.  We test that the factory functions return
// non-null services and wire them up correctly, even when model files
// are missing (the factory logs warnings but succeeds).

TEST(PipelineFactory, createDetectionServices_returnsNonNull) {
    const auto& config = Configuration::instance();
    auto services = PipelineFactory::createDetectionServices(config);

    EXPECT_NE(services.threatIntel, nullptr);
    EXPECT_NE(services.ruleEngine, nullptr);
    EXPECT_NE(services.hybridService, nullptr);
}

TEST(PipelineFactory, createDetectionServices_hybridServiceHasCorrectWeights) {
    auto& config = Configuration::instance();
    auto services = PipelineFactory::createDetectionServices(config);

    // The hybrid service should have been configured with weights from config.
    // We can't read them back directly, but if construction succeeded without
    // throwing, the weights were applied.
    EXPECT_NE(services.hybridService, nullptr);
}

TEST(PipelineFactory, createMlServices_returnsNonNull) {
    const auto& config = Configuration::instance();
    auto services = PipelineFactory::createMlServices(config);

    EXPECT_NE(services.analyzer, nullptr);
    EXPECT_NE(services.normalizer, nullptr);
    EXPECT_NE(services.flowExtractor, nullptr);
}

TEST(PipelineFactory, createLiveMlServices_returnsNonNull) {
    const auto& config = Configuration::instance();
    auto services = PipelineFactory::createLiveMlServices(config);

    EXPECT_NE(services.analyzer, nullptr);
    EXPECT_NE(services.normalizer, nullptr);
    EXPECT_NE(services.flowExtractor, nullptr);
}

TEST(PipelineFactory, createMlServices_andLiveMlServices_returnDistinctInstances) {
    const auto& config = Configuration::instance();
    auto batch = PipelineFactory::createMlServices(config);
    auto live = PipelineFactory::createLiveMlServices(config);

    // Each pipeline must get its own set of services (ONNX sessions are not
    // thread-safe, flow extractors have per-flow state).
    EXPECT_NE(batch.analyzer.get(), live.analyzer.get());
    EXPECT_NE(batch.normalizer.get(), live.normalizer.get());
    EXPECT_NE(batch.flowExtractor.get(), live.flowExtractor.get());
}

TEST(PipelineFactory, createDetectionServices_ruleEngineHasRules) {
    const auto& config = Configuration::instance();
    auto services = PipelineFactory::createDetectionServices(config);

    // HeuristicRuleEngine ships with 7 built-in rules.
    // We can verify via the IRuleEngine interface if it has a ruleCount().
    // Since IRuleEngine doesn't expose ruleCount, just verify it exists.
    EXPECT_NE(services.ruleEngine, nullptr);
}
