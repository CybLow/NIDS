#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "helpers/MockAnalyzer.h"
#include "helpers/MockFlowExtractor.h"
#include "helpers/MockNormalizer.h"
#include "helpers/MockOutputSink.h"
#include "helpers/TestHelpers.h"

#include "app/LiveDetectionPipeline.h"
#include "app/HybridDetectionService.h"
#include "core/model/CaptureSession.h"
#include "core/model/DetectionResult.h"
#include "core/model/PredictionResult.h"

#include <atomic>
#include <chrono>
#include <expected>
#include <span>
#include <thread>
#include <vector>

using namespace nids::core;
using namespace nids::app;
using nids::testing::MockAnalyzerWithConfidence;
using nids::testing::MockFlowExtractorFull;
using nids::testing::MockNormalizer;
using nids::testing::MockOutputSink;
using nids::testing::makeFlowInfo;
using nids::testing::makeBenignPrediction;
using nids::testing::waitFor;
using ::testing::_;
using ::testing::Return;
using ::testing::Invoke;

namespace {
constexpr int kFeatureCount = 77;
} // anonymous namespace

// ── Tests ────────────────────────────────────────────────────────────

TEST(LiveDetectionPipeline, isNotRunningAfterConstruction) {
    MockFlowExtractorFull extractor;
    MockAnalyzerWithConfidence analyzer;
    MockNormalizer normalizer;
    CaptureSession session;

    LiveDetectionPipeline pipeline(extractor, analyzer, normalizer, session);
    EXPECT_FALSE(pipeline.isRunning());
    EXPECT_EQ(pipeline.flowsDetected(), 0u);
    EXPECT_EQ(pipeline.droppedFlows(), 0u);
}

TEST(LiveDetectionPipeline, startAndStop_lifecycle) {
    MockFlowExtractorFull extractor;
    MockAnalyzerWithConfidence analyzer;
    MockNormalizer normalizer;
    CaptureSession session;

    extractor.captureCallback();
    EXPECT_CALL(extractor, reset()).Times(1);
    EXPECT_CALL(extractor, setFlowCompletionCallback(_)).Times(testing::AtLeast(1));
    EXPECT_CALL(extractor, finalizeAllFlows()).Times(1);

    // Normalizer pass-through for the worker.
    ON_CALL(normalizer, normalize(_)).WillByDefault(
        [](std::span<const float> f) { return std::vector<float>(f.begin(), f.end()); });

    LiveDetectionPipeline pipeline(extractor, analyzer, normalizer, session);
    pipeline.start();
    EXPECT_TRUE(pipeline.isRunning());

    pipeline.stop();
    EXPECT_FALSE(pipeline.isRunning());
}

TEST(LiveDetectionPipeline, startIsIdempotent) {
    MockFlowExtractorFull extractor;
    MockAnalyzerWithConfidence analyzer;
    MockNormalizer normalizer;
    CaptureSession session;

    extractor.captureCallback();
    // reset() should only be called once even if start() is called twice.
    EXPECT_CALL(extractor, reset()).Times(1);
    EXPECT_CALL(extractor, setFlowCompletionCallback(_)).Times(testing::AtLeast(1));
    EXPECT_CALL(extractor, finalizeAllFlows()).Times(1);

    ON_CALL(normalizer, normalize(_)).WillByDefault(
        [](std::span<const float> f) { return std::vector<float>(f.begin(), f.end()); });

    LiveDetectionPipeline pipeline(extractor, analyzer, normalizer, session);
    pipeline.start();
    pipeline.start(); // second start is a no-op
    EXPECT_TRUE(pipeline.isRunning());

    pipeline.stop();
}

TEST(LiveDetectionPipeline, stopIsIdempotent) {
    MockFlowExtractorFull extractor;
    MockAnalyzerWithConfidence analyzer;
    MockNormalizer normalizer;
    CaptureSession session;

    extractor.captureCallback();
    EXPECT_CALL(extractor, reset()).Times(1);
    EXPECT_CALL(extractor, setFlowCompletionCallback(_)).Times(testing::AtLeast(1));
    EXPECT_CALL(extractor, finalizeAllFlows()).Times(1);

    ON_CALL(normalizer, normalize(_)).WillByDefault(
        [](std::span<const float> f) { return std::vector<float>(f.begin(), f.end()); });

    LiveDetectionPipeline pipeline(extractor, analyzer, normalizer, session);
    pipeline.start();
    pipeline.stop();
    pipeline.stop(); // second stop is a no-op
    EXPECT_FALSE(pipeline.isRunning());
}

TEST(LiveDetectionPipeline, feedPacket_delegatesToExtractor) {
    MockFlowExtractorFull extractor;
    MockAnalyzerWithConfidence analyzer;
    MockNormalizer normalizer;
    CaptureSession session;

    extractor.captureCallback();
    EXPECT_CALL(extractor, reset()).Times(1);
    EXPECT_CALL(extractor, setFlowCompletionCallback(_)).Times(testing::AtLeast(1));
    EXPECT_CALL(extractor, finalizeAllFlows()).Times(1);

    // Expect processPacket to be called with the data we feed.
    std::uint8_t fakePacket[] = {0xDE, 0xAD, 0xBE, 0xEF};
    EXPECT_CALL(extractor, processPacket(fakePacket, 4, 1000000)).Times(1);

    ON_CALL(normalizer, normalize(_)).WillByDefault(
        [](std::span<const float> f) { return std::vector<float>(f.begin(), f.end()); });

    LiveDetectionPipeline pipeline(extractor, analyzer, normalizer, session);
    pipeline.start();
    pipeline.feedPacket(fakePacket, 4, 1000000);
    pipeline.stop();
}

TEST(LiveDetectionPipeline, flowCompletion_triggersDetection) {
    MockFlowExtractorFull extractor;
    MockAnalyzerWithConfidence analyzer;
    MockNormalizer normalizer;
    CaptureSession session;

    extractor.captureCallback();
    EXPECT_CALL(extractor, reset()).Times(1);
    EXPECT_CALL(extractor, setFlowCompletionCallback(_)).Times(testing::AtLeast(1));
    EXPECT_CALL(extractor, finalizeAllFlows()).Times(1);

    // Set up normalizer and analyzer to return a benign prediction.
    ON_CALL(normalizer, normalize(_)).WillByDefault(
        [](std::span<const float> f) { return std::vector<float>(f.begin(), f.end()); });
    ON_CALL(analyzer, predictWithConfidence(_)).WillByDefault(Return(makeBenignPrediction()));

    std::atomic<int> callbackCount{0};
    LiveDetectionPipeline pipeline(extractor, analyzer, normalizer, session);
    pipeline.setResultCallback(
        [&callbackCount](std::size_t, DetectionResult, FlowInfo) {
            callbackCount.fetch_add(1, std::memory_order_relaxed);
        });

    pipeline.start();

    // Simulate a completed flow by firing the flow completion callback
    // (which was captured by the mock extractor).
    std::vector<float> features(kFeatureCount, 0.5f);
    extractor.fireFlowCompletion(std::move(features), makeFlowInfo());

    // Wait for the worker to process the flow.
    EXPECT_TRUE(waitFor([&] { return callbackCount.load() >= 1; }));
    EXPECT_GE(pipeline.flowsDetected(), 1u);

    pipeline.stop();
}

TEST(LiveDetectionPipeline, destructorStopsPipeline) {
    MockFlowExtractorFull extractor;
    MockAnalyzerWithConfidence analyzer;
    MockNormalizer normalizer;
    CaptureSession session;

    extractor.captureCallback();
    EXPECT_CALL(extractor, reset()).Times(1);
    EXPECT_CALL(extractor, setFlowCompletionCallback(_)).Times(testing::AtLeast(1));
    EXPECT_CALL(extractor, finalizeAllFlows()).Times(1);

    ON_CALL(normalizer, normalize(_)).WillByDefault(
        [](std::span<const float> f) { return std::vector<float>(f.begin(), f.end()); });

    {
        LiveDetectionPipeline pipeline(extractor, analyzer, normalizer, session);
        pipeline.start();
        EXPECT_TRUE(pipeline.isRunning());
    }
    // Pipeline should be stopped by destructor — no hang, no crash.
}

TEST(LiveDetectionPipeline, outputSink_receivesFlowResults) {
    MockFlowExtractorFull extractor;
    MockAnalyzerWithConfidence analyzer;
    MockNormalizer normalizer;
    CaptureSession session;
    MockOutputSink sink;

    extractor.captureCallback();
    EXPECT_CALL(extractor, reset()).Times(1);
    EXPECT_CALL(extractor, setFlowCompletionCallback(_)).Times(testing::AtLeast(1));
    EXPECT_CALL(extractor, finalizeAllFlows()).Times(1);

    ON_CALL(normalizer, normalize(_)).WillByDefault(
        [](std::span<const float> f) { return std::vector<float>(f.begin(), f.end()); });
    ON_CALL(analyzer, predictWithConfidence(_)).WillByDefault(Return(makeBenignPrediction()));

    ON_CALL(sink, name()).WillByDefault(Return("MockSink"));
    EXPECT_CALL(sink, start()).WillOnce(Return(true));
    EXPECT_CALL(sink, stop()).Times(1);

    std::atomic<int> sinkCalls{0};
    EXPECT_CALL(sink, onFlowResult(_, _, _)).WillRepeatedly(
        Invoke([&sinkCalls](std::size_t, const DetectionResult&, const FlowInfo&) {
            sinkCalls.fetch_add(1, std::memory_order_relaxed);
        }));

    LiveDetectionPipeline pipeline(extractor, analyzer, normalizer, session);
    pipeline.addOutputSink(&sink);
    pipeline.start();

    std::vector<float> features(kFeatureCount, 0.5f);
    extractor.fireFlowCompletion(std::move(features), makeFlowInfo());

    EXPECT_TRUE(waitFor([&] { return sinkCalls.load() >= 1; }));

    pipeline.stop();
}
