#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "app/AnalysisService.h"
#include "core/services/IPacketAnalyzer.h"
#include "core/services/IFlowExtractor.h"
#include "core/model/CaptureSession.h"
#include "infra/flow/NativeFlowExtractor.h"  // kFlowFeatureCount

#include <QCoreApplication>
#include <QSignalSpy>

using namespace nids::core;
using namespace nids::app;
using nids::infra::kFlowFeatureCount;
using ::testing::_;
using ::testing::Return;

// ── Mocks ────────────────────────────────────────────────────────────

class MockAnalyzer : public IPacketAnalyzer {
public:
    MOCK_METHOD(bool, loadModel, (const std::string&), (override));
    MOCK_METHOD(AttackType, predict, (const std::vector<float>&), (override));
};

class MockFlowExtractor : public IFlowExtractor {
public:
    MOCK_METHOD(std::vector<std::vector<float>>, extractFeatures, (const std::string&), (override));
    MOCK_METHOD(const std::vector<FlowInfo>&, flowMetadata, (), (const, noexcept, override));

private:
    // Default empty metadata returned by flowMetadata() when no expectation is set.
    std::vector<FlowInfo> emptyMetadata_;
};

// ── Fixture ──────────────────────────────────────────────────────────

class AnalysisServiceTest : public ::testing::Test {
protected:
    void SetUp() override {
        if (!QCoreApplication::instance()) {
            static int argc = 1;
            static char appName[] = "test";
            static char* argv[] = {appName, nullptr};
            app_ = std::make_unique<QCoreApplication>(argc, argv);
        }
    }

    std::unique_ptr<QCoreApplication> app_;
};

// ── Tests ────────────────────────────────────────────────────────────

TEST_F(AnalysisServiceTest, loadModel_delegatesToAnalyzer) {
    auto analyzer = std::make_unique<MockAnalyzer>();
    auto extractor = std::make_unique<MockFlowExtractor>();

    EXPECT_CALL(*analyzer, loadModel("model.onnx")).WillOnce(Return(true));

    AnalysisService service(std::move(analyzer), std::move(extractor));
    EXPECT_TRUE(service.loadModel("model.onnx"));
}

TEST_F(AnalysisServiceTest, loadModel_returnsFalseOnFailure) {
    auto analyzer = std::make_unique<MockAnalyzer>();
    auto extractor = std::make_unique<MockFlowExtractor>();

    EXPECT_CALL(*analyzer, loadModel(_)).WillOnce(Return(false));

    AnalysisService service(std::move(analyzer), std::move(extractor));
    EXPECT_FALSE(service.loadModel("/bad/path.onnx"));
}

TEST_F(AnalysisServiceTest, analyzeCapture_extractionFailure_emitsNoFlows) {
    auto analyzer = std::make_unique<MockAnalyzer>();
    auto extractor = std::make_unique<MockFlowExtractor>();

    // extractFeatures returns empty on failure
    EXPECT_CALL(*extractor, extractFeatures(_))
        .WillOnce(Return(std::vector<std::vector<float>>{}));
    // predict should never be called if no features
    EXPECT_CALL(*analyzer, predict(_)).Times(0);

    AnalysisService service(std::move(analyzer), std::move(extractor));

    QSignalSpy startedSpy(&service, &AnalysisService::analysisStarted);
    QSignalSpy finishedSpy(&service, &AnalysisService::analysisFinished);

    CaptureSession session;
    service.analyzeCapture("test.pcap", session);

    EXPECT_EQ(startedSpy.count(), 1);
    EXPECT_EQ(finishedSpy.count(), 1);
}

TEST_F(AnalysisServiceTest, analyzeCapture_success_classifiesAllFlows) {
    auto analyzer = std::make_unique<MockAnalyzer>();
    auto* analyzerPtr = analyzer.get();
    auto extractor = std::make_unique<MockFlowExtractor>();
    auto* extractorPtr = extractor.get();

    // Return 3 mock flow feature vectors
    std::vector<std::vector<float>> mockFeatures = {
        std::vector<float>(kFlowFeatureCount, 0.0f),
        std::vector<float>(kFlowFeatureCount, 0.5f),
        std::vector<float>(kFlowFeatureCount, 1.0f),
    };

    EXPECT_CALL(*extractorPtr, extractFeatures(_)).WillOnce(Return(mockFeatures));
    EXPECT_CALL(*analyzerPtr, predict(_))
        .WillOnce(Return(AttackType::Benign))
        .WillOnce(Return(AttackType::DdosIcmp))
        .WillOnce(Return(AttackType::SshBruteForce));

    AnalysisService service(std::move(analyzer), std::move(extractor));

    QSignalSpy startedSpy(&service, &AnalysisService::analysisStarted);
    QSignalSpy progressSpy(&service, &AnalysisService::analysisProgress);
    QSignalSpy finishedSpy(&service, &AnalysisService::analysisFinished);
    QSignalSpy errorSpy(&service, &AnalysisService::analysisError);

    CaptureSession session;
    service.analyzeCapture("test.pcap", session);

    EXPECT_EQ(startedSpy.count(), 1);
    EXPECT_EQ(finishedSpy.count(), 1);
    EXPECT_EQ(errorSpy.count(), 0);

    // Progress emitted once per flow
    EXPECT_EQ(progressSpy.count(), 3);
    // Verify progress values: (current, total)
    EXPECT_EQ(progressSpy.at(0).at(0).toInt(), 1);
    EXPECT_EQ(progressSpy.at(0).at(1).toInt(), 3);
    EXPECT_EQ(progressSpy.at(2).at(0).toInt(), 3);
    EXPECT_EQ(progressSpy.at(2).at(1).toInt(), 3);

    // Verify results stored in session (via DetectionResult API)
    EXPECT_EQ(session.getDetectionResult(0).finalVerdict, AttackType::Benign);
    EXPECT_EQ(session.getDetectionResult(1).finalVerdict, AttackType::DdosIcmp);
    EXPECT_EQ(session.getDetectionResult(2).finalVerdict, AttackType::SshBruteForce);
}

TEST_F(AnalysisServiceTest, analyzeCapture_emptyFeatures_finishesWithoutPrediction) {
    auto analyzer = std::make_unique<MockAnalyzer>();
    auto extractor = std::make_unique<MockFlowExtractor>();

    EXPECT_CALL(*extractor, extractFeatures(_))
        .WillOnce(Return(std::vector<std::vector<float>>{}));
    EXPECT_CALL(*analyzer, predict(_)).Times(0);

    AnalysisService service(std::move(analyzer), std::move(extractor));

    QSignalSpy finishedSpy(&service, &AnalysisService::analysisFinished);
    QSignalSpy errorSpy(&service, &AnalysisService::analysisError);
    QSignalSpy progressSpy(&service, &AnalysisService::analysisProgress);

    CaptureSession session;
    service.analyzeCapture("empty.pcap", session);

    EXPECT_EQ(finishedSpy.count(), 1);
    EXPECT_EQ(errorSpy.count(), 0);
    EXPECT_EQ(progressSpy.count(), 0);
}

TEST_F(AnalysisServiceTest, analyzeCapture_singleFlow_correctProgress) {
    auto analyzer = std::make_unique<MockAnalyzer>();
    auto extractor = std::make_unique<MockFlowExtractor>();

    std::vector<std::vector<float>> singleFlow = {
        std::vector<float>(kFlowFeatureCount, 0.42f),
    };

    EXPECT_CALL(*extractor, extractFeatures(_)).WillOnce(Return(singleFlow));
    EXPECT_CALL(*analyzer, predict(_)).WillOnce(Return(AttackType::PortScanning));

    AnalysisService service(std::move(analyzer), std::move(extractor));

    QSignalSpy progressSpy(&service, &AnalysisService::analysisProgress);

    CaptureSession session;
    service.analyzeCapture("single.pcap", session);

    ASSERT_EQ(progressSpy.count(), 1);
    EXPECT_EQ(progressSpy.at(0).at(0).toInt(), 1);
    EXPECT_EQ(progressSpy.at(0).at(1).toInt(), 1);
    EXPECT_EQ(session.getDetectionResult(0).finalVerdict, AttackType::PortScanning);
}
