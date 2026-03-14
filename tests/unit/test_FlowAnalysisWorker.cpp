#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "app/FlowAnalysisWorker.h"
#include "app/HybridDetectionService.h"
#include "core/model/CaptureSession.h"
#include "core/model/DetectionResult.h"
#include "core/model/PredictionResult.h"
#include "core/services/BoundedQueue.h"
#include "core/services/IFeatureNormalizer.h"
#include "core/services/IPacketAnalyzer.h"

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

using namespace nids::core;
using namespace nids::app;
using ::testing::_;
using ::testing::Return;

// ── Mocks ────────────────────────────────────────────────────────────

class MockAnalyzerWorker : public IPacketAnalyzer {
public:
    MOCK_METHOD(bool, loadModel, (const std::string&), (override));
    MOCK_METHOD(AttackType, predict, (const std::vector<float>&), (override));
    MOCK_METHOD(PredictionResult, predictWithConfidence,
                (const std::vector<float>&), (override));
};

class MockNormalizerWorker : public IFeatureNormalizer {
public:
    MOCK_METHOD(bool, loadMetadata, (const std::string&), (override));
    MOCK_METHOD(std::vector<float>, normalize, (const std::vector<float>&),
                (const, override));
    MOCK_METHOD(bool, isLoaded, (), (const, noexcept, override));
    MOCK_METHOD(std::size_t, featureCount, (), (const, noexcept, override));

    /// Create a pass-through normalizer that returns features unchanged.
    static std::unique_ptr<MockNormalizerWorker> createPassThrough() {
        auto mock = std::make_unique<MockNormalizerWorker>();
        ON_CALL(*mock, normalize(_)).WillByDefault(
            [](const std::vector<float>& f) { return f; });
        return mock;
    }
};

// ── Helper ───────────────────────────────────────────────────────────

namespace {

constexpr std::size_t kQueueCapacity = 64;
constexpr int kFeatureCount = 77;

FlowWorkItem makeItem(float fillValue = 0.5f,
                      const std::string& srcIp = "10.0.0.1",
                      const std::string& dstIp = "10.0.0.2") {
    FlowWorkItem item;
    item.features.assign(kFeatureCount, fillValue);
    item.metadata.srcIp = srcIp;
    item.metadata.dstIp = dstIp;
    item.metadata.srcPort = 12345;
    item.metadata.dstPort = 80;
    item.metadata.protocol = 6;
    return item;
}

/// Wait for a condition with a timeout.  Returns true if condition was met.
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

TEST(FlowAnalysisWorker, processedCountStartsAtZero) {
    BoundedQueue<FlowWorkItem> queue(kQueueCapacity);
    MockAnalyzerWorker analyzer;
    auto normalizer = MockNormalizerWorker::createPassThrough();
    CaptureSession session;

    FlowAnalysisWorker worker(queue, analyzer, *normalizer, session);
    EXPECT_EQ(worker.processedCount(), 0u);
    EXPECT_FALSE(worker.isRunning());
}

TEST(FlowAnalysisWorker, startAndStopLifecycle) {
    BoundedQueue<FlowWorkItem> queue(kQueueCapacity);
    MockAnalyzerWorker analyzer;
    auto normalizer = MockNormalizerWorker::createPassThrough();
    CaptureSession session;

    EXPECT_CALL(analyzer, predict(_))
        .WillRepeatedly(Return(AttackType::Benign));

    FlowAnalysisWorker worker(queue, analyzer, *normalizer, session);

    worker.start();
    EXPECT_TRUE(worker.isRunning());

    // start() again is a no-op
    worker.start();
    EXPECT_TRUE(worker.isRunning());

    worker.stop();
    EXPECT_FALSE(worker.isRunning());

    // stop() again is safe
    worker.stop();
    EXPECT_FALSE(worker.isRunning());
}

TEST(FlowAnalysisWorker, processSingleItem_mlOnly) {
    BoundedQueue<FlowWorkItem> queue(kQueueCapacity);
    MockAnalyzerWorker analyzer;
    auto normalizer = MockNormalizerWorker::createPassThrough();
    CaptureSession session;

    EXPECT_CALL(analyzer, predict(_)).WillOnce(Return(AttackType::DdosIcmp));

    FlowAnalysisWorker worker(queue, analyzer, *normalizer, session);
    worker.start();

    queue.push(makeItem());
    queue.close();

    // Wait for worker to finish
    ASSERT_TRUE(waitFor([&] { return !worker.isRunning() || worker.processedCount() == 1; }));
    worker.stop();

    EXPECT_EQ(worker.processedCount(), 1u);
    EXPECT_EQ(session.getDetectionResult(0).finalVerdict, AttackType::DdosIcmp);
    EXPECT_EQ(session.getDetectionResult(0).detectionSource, DetectionSource::MlOnly);
}

TEST(FlowAnalysisWorker, processMultipleItems_mlOnly) {
    BoundedQueue<FlowWorkItem> queue(kQueueCapacity);
    MockAnalyzerWorker analyzer;
    auto normalizer = MockNormalizerWorker::createPassThrough();
    CaptureSession session;

    EXPECT_CALL(analyzer, predict(_))
        .WillOnce(Return(AttackType::Benign))
        .WillOnce(Return(AttackType::SshBruteForce))
        .WillOnce(Return(AttackType::PortScanning));

    FlowAnalysisWorker worker(queue, analyzer, *normalizer, session);
    worker.start();

    queue.push(makeItem(0.1f));
    queue.push(makeItem(0.5f));
    queue.push(makeItem(0.9f));
    queue.close();

    ASSERT_TRUE(waitFor([&] { return worker.processedCount() == 3; }));
    worker.stop();

    EXPECT_EQ(session.getDetectionResult(0).finalVerdict, AttackType::Benign);
    EXPECT_EQ(session.getDetectionResult(1).finalVerdict, AttackType::SshBruteForce);
    EXPECT_EQ(session.getDetectionResult(2).finalVerdict, AttackType::PortScanning);
}

TEST(FlowAnalysisWorker, hybridDetection_usesHybridService) {
    BoundedQueue<FlowWorkItem> queue(kQueueCapacity);
    MockAnalyzerWorker analyzer;
    auto normalizer = MockNormalizerWorker::createPassThrough();
    CaptureSession session;

    PredictionResult mlResult;
    mlResult.classification = AttackType::DdosUdp;
    mlResult.confidence = 0.92f;
    EXPECT_CALL(analyzer, predictWithConfidence(_)).WillOnce(Return(mlResult));
    // predict() should NOT be called when hybrid is active
    EXPECT_CALL(analyzer, predict(_)).Times(0);

    HybridDetectionService hybridService(nullptr, nullptr);

    FlowAnalysisWorker worker(queue, analyzer, *normalizer, session);
    worker.setHybridDetection(&hybridService);
    worker.start();

    queue.push(makeItem());
    queue.close();

    ASSERT_TRUE(waitFor([&] { return worker.processedCount() == 1; }));
    worker.stop();

    EXPECT_EQ(session.getDetectionResult(0).finalVerdict, AttackType::DdosUdp);
    EXPECT_EQ(session.getDetectionResult(0).detectionSource, DetectionSource::MlOnly);
}

TEST(FlowAnalysisWorker, resultCallback_invokedForEachFlow) {
    BoundedQueue<FlowWorkItem> queue(kQueueCapacity);
    MockAnalyzerWorker analyzer;
    auto normalizer = MockNormalizerWorker::createPassThrough();
    CaptureSession session;

    EXPECT_CALL(analyzer, predict(_))
        .WillOnce(Return(AttackType::Benign))
        .WillOnce(Return(AttackType::SynFlood));

    std::atomic<int> callbackCount{0};
    std::vector<std::pair<std::size_t, AttackType>> callbackResults;
    std::mutex callbackMutex;

    FlowAnalysisWorker worker(queue, analyzer, *normalizer, session);
    worker.setResultCallback(
        [&](std::size_t idx, DetectionResult result) {
            std::scoped_lock lock(callbackMutex);
            callbackResults.emplace_back(idx, result.finalVerdict);
            callbackCount.fetch_add(1, std::memory_order_relaxed);
        });
    worker.start();

    queue.push(makeItem(0.1f));
    queue.push(makeItem(0.9f));
    queue.close();

    ASSERT_TRUE(waitFor([&] { return callbackCount.load() == 2; }));
    worker.stop();

    std::scoped_lock lock(callbackMutex);
    ASSERT_EQ(callbackResults.size(), 2u);
    EXPECT_EQ(callbackResults[0].first, 0u);
    EXPECT_EQ(callbackResults[0].second, AttackType::Benign);
    EXPECT_EQ(callbackResults[1].first, 1u);
    EXPECT_EQ(callbackResults[1].second, AttackType::SynFlood);
}

TEST(FlowAnalysisWorker, normalizationIsApplied) {
    BoundedQueue<FlowWorkItem> queue(kQueueCapacity);
    MockAnalyzerWorker analyzer;
    MockNormalizerWorker normalizer;
    CaptureSession session;

    // Normalizer transforms features: multiply each by 2
    ON_CALL(normalizer, normalize(_)).WillByDefault(
        [](const std::vector<float>& f) {
            std::vector<float> result(f.size());
            std::ranges::transform(f, result.begin(),
                                   [](float v) { return v * 2.0f; });
            return result;
        });

    // Capture the features passed to predict to verify normalization happened
    std::vector<float> capturedFeatures;
    EXPECT_CALL(analyzer, predict(_)).WillOnce(
        [&capturedFeatures](const std::vector<float>& f) {
            capturedFeatures = f;
            return AttackType::Benign;
        });

    FlowAnalysisWorker worker(queue, analyzer, normalizer, session);
    worker.start();

    auto item = makeItem(1.0f);
    queue.push(std::move(item));
    queue.close();

    ASSERT_TRUE(waitFor([&] { return worker.processedCount() == 1; }));
    worker.stop();

    // All features should be 2.0 (1.0 * 2)
    ASSERT_EQ(capturedFeatures.size(), static_cast<std::size_t>(kFeatureCount));
    for (float v : capturedFeatures) {
        EXPECT_FLOAT_EQ(v, 2.0f);
    }
}

TEST(FlowAnalysisWorker, emptyQueue_closedImmediately) {
    BoundedQueue<FlowWorkItem> queue(kQueueCapacity);
    MockAnalyzerWorker analyzer;
    auto normalizer = MockNormalizerWorker::createPassThrough();
    CaptureSession session;

    // No predict calls expected
    EXPECT_CALL(analyzer, predict(_)).Times(0);

    FlowAnalysisWorker worker(queue, analyzer, *normalizer, session);
    worker.start();

    // Close immediately — worker should exit without processing anything
    queue.close();

    ASSERT_TRUE(waitFor([&] { return !worker.isRunning() || worker.processedCount() == 0; }));
    worker.stop();

    EXPECT_EQ(worker.processedCount(), 0u);
}

TEST(FlowAnalysisWorker, destructorJoinsThread) {
    BoundedQueue<FlowWorkItem> queue(kQueueCapacity);
    MockAnalyzerWorker analyzer;
    auto normalizer = MockNormalizerWorker::createPassThrough();
    CaptureSession session;

    EXPECT_CALL(analyzer, predict(_)).WillOnce(Return(AttackType::Benign));

    {
        FlowAnalysisWorker worker(queue, analyzer, *normalizer, session);
        worker.start();
        queue.push(makeItem());
        queue.close();
        // Destructor should join cleanly without hanging
    }

    // If we reach here without hanging, the destructor joined properly
    EXPECT_EQ(session.getDetectionResult(0).finalVerdict, AttackType::Benign);
}

TEST(FlowAnalysisWorker, concurrentProducer_manyItems) {
    constexpr std::size_t kItemCount = 100;
    BoundedQueue<FlowWorkItem> queue(16); // Small queue to test backpressure
    MockAnalyzerWorker analyzer;
    auto normalizer = MockNormalizerWorker::createPassThrough();
    CaptureSession session;

    EXPECT_CALL(analyzer, predict(_))
        .Times(static_cast<int>(kItemCount))
        .WillRepeatedly(Return(AttackType::Benign));

    FlowAnalysisWorker worker(queue, analyzer, *normalizer, session);
    worker.start();

    // Producer thread pushes items concurrently
    std::jthread producer([&queue] {
        for (std::size_t i = 0; i < kItemCount; ++i) {
            queue.push(makeItem(static_cast<float>(i) / static_cast<float>(kItemCount)));
        }
        queue.close();
    });

    producer.join();

    ASSERT_TRUE(waitFor([&] { return worker.processedCount() == kItemCount; },
                        std::chrono::milliseconds(5000)));
    worker.stop();

    EXPECT_EQ(worker.processedCount(), kItemCount);
    EXPECT_EQ(session.analysisResultCount(), kItemCount);
}

TEST(FlowAnalysisWorker, hybridDetection_protocolMapping) {
    BoundedQueue<FlowWorkItem> queue(kQueueCapacity);
    MockAnalyzerWorker analyzer;
    auto normalizer = MockNormalizerWorker::createPassThrough();
    CaptureSession session;

    PredictionResult mlResult;
    mlResult.classification = AttackType::IcmpFlood;
    mlResult.confidence = 0.85f;
    EXPECT_CALL(analyzer, predictWithConfidence(_))
        .Times(3)
        .WillRepeatedly(Return(mlResult));

    HybridDetectionService hybridService(nullptr, nullptr);

    FlowAnalysisWorker worker(queue, analyzer, *normalizer, session);
    worker.setHybridDetection(&hybridService);
    worker.start();

    // Push items with different protocols
    auto tcpItem = makeItem();
    tcpItem.metadata.protocol = 6;
    queue.push(std::move(tcpItem));

    auto udpItem = makeItem();
    udpItem.metadata.protocol = 17;
    queue.push(std::move(udpItem));

    auto icmpItem = makeItem();
    icmpItem.metadata.protocol = 1;
    queue.push(std::move(icmpItem));

    queue.close();

    ASSERT_TRUE(waitFor([&] { return worker.processedCount() == 3; }));
    worker.stop();

    // All should be classified as IcmpFlood
    for (std::size_t i = 0; i < 3; ++i) {
        EXPECT_EQ(session.getDetectionResult(i).finalVerdict, AttackType::IcmpFlood);
    }
}
