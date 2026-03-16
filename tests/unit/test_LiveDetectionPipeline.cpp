#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "app/LiveDetectionPipeline.h"
#include "app/HybridDetectionService.h"
#include "core/model/CaptureSession.h"
#include "core/model/DetectionResult.h"
#include "core/model/PredictionResult.h"
#include "core/services/IFeatureNormalizer.h"
#include "core/services/IFlowExtractor.h"
#include "core/services/IOutputSink.h"
#include "core/services/IPacketAnalyzer.h"

#include <atomic>
#include <chrono>
#include <expected>
#include <span>
#include <thread>
#include <vector>

using namespace nids::core;
using namespace nids::app;
using ::testing::_;
using ::testing::Return;
using ::testing::Invoke;

// ── Mocks ────────────────────────────────────────────────────────────

class MockAnalyzerLDP : public IPacketAnalyzer {
public:
    MOCK_METHOD((std::expected<void, std::string>), loadModel,
                (const std::string&), (override));
    MOCK_METHOD(AttackType, predict, (std::span<const float>), (override));
    MOCK_METHOD(PredictionResult, predictWithConfidence,
                (std::span<const float>), (override));
    MOCK_METHOD(std::vector<PredictionResult>, predictBatch,
                (std::span<const float>, std::size_t), (override));
};

class MockNormalizerLDP : public IFeatureNormalizer {
public:
    MOCK_METHOD((std::expected<void, std::string>), loadMetadata,
                (const std::string&), (override));
    MOCK_METHOD(std::vector<float>, normalize, (std::span<const float>),
                (const, override));
    MOCK_METHOD(bool, isLoaded, (), (const, noexcept, override));
    MOCK_METHOD(std::size_t, featureCount, (), (const, noexcept, override));
};

class MockFlowExtractorLDP : public IFlowExtractor {
public:
    MOCK_METHOD(void, setFlowCompletionCallback, (FlowCompletionCallback), (override));
    MOCK_METHOD(std::vector<std::vector<float>>, extractFeatures,
                (const std::string&), (override));
    MOCK_METHOD((const std::vector<FlowInfo>&), flowMetadata, (),
                (const, noexcept, override));
    MOCK_METHOD(void, processPacket,
                (const std::uint8_t*, std::size_t, std::int64_t), (override));
    MOCK_METHOD(void, finalizeAllFlows, (), (override));
    MOCK_METHOD(void, reset, (), (override));

    // Capture the callback so we can fire it in tests.
    void captureCallback() {
        ON_CALL(*this, setFlowCompletionCallback(_))
            .WillByDefault(Invoke([this](FlowCompletionCallback cb) {
                callback_ = std::move(cb);
            }));
    }

    void fireFlowCompletion(std::vector<float>&& features, FlowInfo&& info) {
        if (callback_) {
            callback_(std::move(features), std::move(info));
        }
    }

private:
    FlowCompletionCallback callback_;
};

class MockOutputSinkLDP : public IOutputSink {
public:
    MOCK_METHOD(std::string_view, name, (), (const, noexcept, override));
    MOCK_METHOD(bool, start, (), (override));
    MOCK_METHOD(void, onFlowResult,
                (std::size_t, const DetectionResult&, const FlowInfo&), (override));
    MOCK_METHOD(void, stop, (), (override));
};

// ── Helpers ──────────────────────────────────────────────────────────

namespace {

constexpr int kFeatureCount = 77;

PredictionResult makeBenignPrediction() {
    PredictionResult pr;
    pr.classification = AttackType::Benign;
    pr.confidence = 0.95f;
    return pr;
}

FlowInfo makeFlowInfo(const std::string& srcIp = "10.0.0.1",
                      const std::string& dstIp = "10.0.0.2") {
    FlowInfo info;
    info.srcIp = srcIp;
    info.dstIp = dstIp;
    info.srcPort = 12345;
    info.dstPort = 80;
    info.protocol = 6;
    return info;
}

template <typename Pred>
bool waitFor(Pred pred, std::chrono::milliseconds timeout = std::chrono::milliseconds(2000)) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!pred()) {
        if (std::chrono::steady_clock::now() > deadline)
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return true;
}

} // anonymous namespace

// ── Tests ────────────────────────────────────────────────────────────

TEST(LiveDetectionPipeline, isNotRunningAfterConstruction) {
    MockFlowExtractorLDP extractor;
    MockAnalyzerLDP analyzer;
    MockNormalizerLDP normalizer;
    CaptureSession session;

    LiveDetectionPipeline pipeline(extractor, analyzer, normalizer, session);
    EXPECT_FALSE(pipeline.isRunning());
    EXPECT_EQ(pipeline.flowsDetected(), 0u);
    EXPECT_EQ(pipeline.droppedFlows(), 0u);
}

TEST(LiveDetectionPipeline, startAndStop_lifecycle) {
    MockFlowExtractorLDP extractor;
    MockAnalyzerLDP analyzer;
    MockNormalizerLDP normalizer;
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
    MockFlowExtractorLDP extractor;
    MockAnalyzerLDP analyzer;
    MockNormalizerLDP normalizer;
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
    MockFlowExtractorLDP extractor;
    MockAnalyzerLDP analyzer;
    MockNormalizerLDP normalizer;
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
    MockFlowExtractorLDP extractor;
    MockAnalyzerLDP analyzer;
    MockNormalizerLDP normalizer;
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
    MockFlowExtractorLDP extractor;
    MockAnalyzerLDP analyzer;
    MockNormalizerLDP normalizer;
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
    MockFlowExtractorLDP extractor;
    MockAnalyzerLDP analyzer;
    MockNormalizerLDP normalizer;
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
    MockFlowExtractorLDP extractor;
    MockAnalyzerLDP analyzer;
    MockNormalizerLDP normalizer;
    CaptureSession session;
    MockOutputSinkLDP sink;

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
