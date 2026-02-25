#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "app/AnalysisService.h"
#include "core/services/IPacketAnalyzer.h"
#include "core/services/IFlowExtractor.h"
#include "core/model/CaptureSession.h"

#include <QCoreApplication>
#include <QSignalSpy>

using namespace nids::core;
using namespace nids::app;
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
    MOCK_METHOD(bool, extractFlows, (const std::string&, const std::string&), (override));
    MOCK_METHOD(std::vector<std::vector<float>>, loadFeatures, (const std::string&), (override));
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

TEST_F(AnalysisServiceTest, analyzeCapture_extractionFailure_emitsError) {
    auto analyzer = std::make_unique<MockAnalyzer>();
    auto extractor = std::make_unique<MockFlowExtractor>();

    EXPECT_CALL(*extractor, extractFlows(_, _)).WillOnce(Return(false));
    // predict should never be called if extraction fails
    EXPECT_CALL(*analyzer, predict(_)).Times(0);

    AnalysisService service(std::move(analyzer), std::move(extractor));

    QSignalSpy startedSpy(&service, &AnalysisService::analysisStarted);
    QSignalSpy errorSpy(&service, &AnalysisService::analysisError);
    QSignalSpy finishedSpy(&service, &AnalysisService::analysisFinished);

    CaptureSession session;
    service.analyzeCapture("test.pcap", session);

    EXPECT_EQ(startedSpy.count(), 1);
    EXPECT_EQ(errorSpy.count(), 1);
    EXPECT_EQ(finishedSpy.count(), 1);
    EXPECT_TRUE(errorSpy.first().at(0).toString().contains("extract"));
}

TEST_F(AnalysisServiceTest, analyzeCapture_success_classifiesAllFlows) {
    auto analyzer = std::make_unique<MockAnalyzer>();
    auto* analyzerPtr = analyzer.get();
    auto extractor = std::make_unique<MockFlowExtractor>();
    auto* extractorPtr = extractor.get();

    // Return 3 mock flow feature vectors
    std::vector<std::vector<float>> mockFeatures = {
        std::vector<float>(77, 0.0f),
        std::vector<float>(77, 0.5f),
        std::vector<float>(77, 1.0f),
    };

    EXPECT_CALL(*extractorPtr, extractFlows(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*extractorPtr, loadFeatures(_)).WillOnce(Return(mockFeatures));
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

    // Verify results stored in session
    EXPECT_EQ(session.getAnalysisResult(0), AttackType::Benign);
    EXPECT_EQ(session.getAnalysisResult(1), AttackType::DdosIcmp);
    EXPECT_EQ(session.getAnalysisResult(2), AttackType::SshBruteForce);
}

TEST_F(AnalysisServiceTest, analyzeCapture_emptyFeatures_finishesWithoutPrediction) {
    auto analyzer = std::make_unique<MockAnalyzer>();
    auto extractor = std::make_unique<MockFlowExtractor>();

    EXPECT_CALL(*extractor, extractFlows(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*extractor, loadFeatures(_))
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
        std::vector<float>(77, 0.42f),
    };

    EXPECT_CALL(*extractor, extractFlows(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*extractor, loadFeatures(_)).WillOnce(Return(singleFlow));
    EXPECT_CALL(*analyzer, predict(_)).WillOnce(Return(AttackType::PortScanning));

    AnalysisService service(std::move(analyzer), std::move(extractor));

    QSignalSpy progressSpy(&service, &AnalysisService::analysisProgress);

    CaptureSession session;
    service.analyzeCapture("single.pcap", session);

    ASSERT_EQ(progressSpy.count(), 1);
    EXPECT_EQ(progressSpy.at(0).at(0).toInt(), 1);
    EXPECT_EQ(progressSpy.at(0).at(1).toInt(), 1);
    EXPECT_EQ(session.getAnalysisResult(0), AttackType::PortScanning);
}
