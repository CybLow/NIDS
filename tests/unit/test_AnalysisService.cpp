#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "helpers/MockAnalyzer.h"
#include "helpers/MockFlowExtractor.h"
#include "helpers/MockNormalizer.h"

#include "app/AnalysisService.h"
#include "app/HybridDetectionService.h"
#include "core/model/CaptureSession.h"
#include "core/model/DetectionResult.h"
#include "core/model/PredictionResult.h"
#include "core/model/FlowConstants.h"

#include <expected>
#include <span>
#include <string>
#include <utility>
#include <vector>

using namespace nids::core;
using namespace nids::app;
using nids::core::kFlowFeatureCount;
using nids::testing::MockAnalyzer;
using nids::testing::MockAnalyzerWithConfidence;
using nids::testing::MockFlowExtractor;
using nids::testing::MockNormalizer;
using ::testing::_;
using ::testing::Return;

// ── Fixture ──────────────────────────────────────────────────────────

class AnalysisServiceTest : public ::testing::Test {
protected: // NOSONAR
};

// ── Tests ────────────────────────────────────────────────────────────

TEST_F(AnalysisServiceTest, loadModel_delegatesToAnalyzer) {
  auto analyzer = std::make_unique<MockAnalyzer>();
  auto extractor = std::make_unique<MockFlowExtractor>();

  EXPECT_CALL(*analyzer, loadModel("model.onnx"))
      .WillOnce(Return(std::expected<void, std::string>{}));

  AnalysisService service(std::move(analyzer), std::move(extractor),
                          MockNormalizer::createPassThrough());
  EXPECT_TRUE(service.loadModel("model.onnx").has_value());
}

TEST_F(AnalysisServiceTest, loadModel_returnsErrorOnFailure) {
  auto analyzer = std::make_unique<MockAnalyzer>();
  auto extractor = std::make_unique<MockFlowExtractor>();

  EXPECT_CALL(*analyzer, loadModel(_))
      .WillOnce(Return(std::unexpected<std::string>("load failed")));

  AnalysisService service(std::move(analyzer), std::move(extractor),
                          MockNormalizer::createPassThrough());
  EXPECT_FALSE(service.loadModel("/bad/path.onnx").has_value());
}

TEST_F(AnalysisServiceTest, loadNormalization_delegatesToNormalizer) {
  auto analyzer = std::make_unique<MockAnalyzer>();
  auto extractor = std::make_unique<MockFlowExtractor>();
  auto normalizer = std::make_unique<MockNormalizer>();

  EXPECT_CALL(*normalizer, loadMetadata("metadata.json"))
      .WillOnce(Return(std::expected<void, std::string>{}));

  AnalysisService service(std::move(analyzer), std::move(extractor),
                          std::move(normalizer));
  EXPECT_TRUE(service.loadNormalization("metadata.json").has_value());
}

TEST_F(AnalysisServiceTest, loadNormalization_returnsErrorOnFailure) {
  auto analyzer = std::make_unique<MockAnalyzer>();
  auto extractor = std::make_unique<MockFlowExtractor>();
  auto normalizer = std::make_unique<MockNormalizer>();

  EXPECT_CALL(*normalizer, loadMetadata(_))
      .WillOnce(Return(std::unexpected<std::string>("metadata load failed")));

  AnalysisService service(std::move(analyzer), std::move(extractor),
                          std::move(normalizer));
  EXPECT_FALSE(service.loadNormalization("/bad/path.json").has_value());
}

TEST_F(AnalysisServiceTest, lastFlowMetadata_emptyBeforeAnalysis) {
  auto analyzer = std::make_unique<MockAnalyzer>();
  auto extractor = std::make_unique<MockFlowExtractor>();

  AnalysisService service(std::move(analyzer), std::move(extractor),
                          MockNormalizer::createPassThrough());
  EXPECT_TRUE(service.lastFlowMetadata().empty());
}

TEST_F(AnalysisServiceTest, lastFlowMetadata_returnsExtractorMetadata) {
  auto analyzer = std::make_unique<MockAnalyzer>();
  auto extractor = std::make_unique<MockFlowExtractor>();
  const auto *extractorPtr = extractor.get();

  // Set up metadata to be returned
  std::vector<FlowInfo> metadata;
  FlowInfo info;
  info.srcIp = "10.0.0.1";
  info.dstIp = "10.0.0.2";
  info.srcPort = 12345;
  info.dstPort = 80;
  info.protocol = 6;
  metadata.push_back(info);

  ON_CALL(*extractorPtr, flowMetadata())
      .WillByDefault(::testing::ReturnRef(metadata));

  AnalysisService service(std::move(analyzer), std::move(extractor),
                          MockNormalizer::createPassThrough());

  const auto &result = service.lastFlowMetadata();
  ASSERT_EQ(result.size(), 1u);
  EXPECT_EQ(result[0].srcIp, "10.0.0.1");
  EXPECT_EQ(result[0].dstPort, 80);
}

// ── Hybrid detection path tests ──────────────────────────────────────

TEST_F(AnalysisServiceTest, analyzeCapture_hybridEnabled_usesHybridService) {
  auto analyzer = std::make_unique<MockAnalyzerWithConfidence>();
  auto *analyzerPtr = analyzer.get();
  auto extractor = std::make_unique<MockFlowExtractor>();
  auto *extractorPtr = extractor.get();

  // Return 1 flow
  std::vector<std::vector<float>> mockFeatures = {
      std::vector<float>(kFlowFeatureCount, 0.5f),
  };

  // Set up metadata so we exercise the hybrid detection path (idx <
  // metadata.size())
  std::vector<FlowInfo> metadata;
  FlowInfo info;
  info.srcIp = "192.168.1.10";
  info.dstIp = "10.0.0.1";
  info.srcPort = 45000;
  info.dstPort = 443;
  info.protocol = 6; // TCP
  info.totalFwdPackets = 10;
  info.totalBwdPackets = 5;
  info.flowDurationUs = 1000000.0;
  info.fwdPacketsPerSecond = 10.0;
  info.bwdPacketsPerSecond = 5.0;
  info.synFlagCount = 1;
  info.ackFlagCount = 15;
  info.rstFlagCount = 0;
  info.finFlagCount = 1;
  info.avgPacketSize = 500.0;
  metadata.push_back(info);

  EXPECT_CALL(*extractorPtr, extractFeatures(_)).WillOnce(Return(mockFeatures));
  ON_CALL(*extractorPtr, flowMetadata())
      .WillByDefault(::testing::ReturnRef(metadata));

  // predictWithConfidence should be called (not predict) when hybrid is active
  PredictionResult mlResult;
  mlResult.classification = AttackType::DdosIcmp;
  mlResult.confidence = 0.95f;
  EXPECT_CALL(*analyzerPtr, predictWithConfidence(_))
      .WillOnce(Return(mlResult));
  EXPECT_CALL(*analyzerPtr, predict(_)).Times(0);

  // Set up a real HybridDetectionService (no TI, no rules for simplicity)
  HybridDetectionService hybridService(nullptr, nullptr);

  AnalysisService service(std::move(analyzer), std::move(extractor),
                          MockNormalizer::createPassThrough());
  service.setHybridDetection(&hybridService);

  CaptureSession session;
  service.analyzeCapture("test.pcap", session);

  // Hybrid should detect the attack via ML
  EXPECT_EQ(session.getDetectionResult(0).finalVerdict, AttackType::DdosIcmp);
  EXPECT_EQ(session.getDetectionResult(0).detectionSource,
            DetectionSource::MlOnly);
}

TEST_F(AnalysisServiceTest,
       analyzeCapture_hybridEnabled_noMetadata_usesEmptyIps) {
  auto analyzer = std::make_unique<MockAnalyzerWithConfidence>();
  auto *analyzerPtr = analyzer.get();
  auto extractor = std::make_unique<MockFlowExtractor>();
  auto *extractorPtr = extractor.get();

  // Return 1 flow but NO metadata (metadata vector is empty)
  std::vector<std::vector<float>> mockFeatures = {
      std::vector<float>(kFlowFeatureCount, 0.5f),
  };

  // Empty metadata — this triggers the else branch (idx >= metadata.size())
  EXPECT_CALL(*extractorPtr, extractFeatures(_)).WillOnce(Return(mockFeatures));
  // Use default empty metadata from MockFlowExtractor constructor

  PredictionResult mlResult;
  mlResult.classification = AttackType::Benign;
  mlResult.confidence = 0.99f;
  EXPECT_CALL(*analyzerPtr, predictWithConfidence(_))
      .WillOnce(Return(mlResult));

  HybridDetectionService hybridService(nullptr, nullptr);

  AnalysisService service(std::move(analyzer), std::move(extractor),
                          MockNormalizer::createPassThrough());
  service.setHybridDetection(&hybridService);

  CaptureSession session;
  service.analyzeCapture("test.pcap", session);

  // Should still work, using the 3-arg evaluate overload with empty IPs
  EXPECT_EQ(session.getDetectionResult(0).finalVerdict, AttackType::Benign);
  EXPECT_EQ(session.getDetectionResult(0).detectionSource,
            DetectionSource::None);
}

TEST_F(AnalysisServiceTest, analyzeCapture_hybridWithTI_protocolMappingTcp) {
  auto analyzer = std::make_unique<MockAnalyzerWithConfidence>();
  auto *analyzerPtr = analyzer.get();
  auto extractor = std::make_unique<MockFlowExtractor>();
  auto *extractorPtr = extractor.get();

  std::vector<std::vector<float>> mockFeatures = {
      std::vector<float>(kFlowFeatureCount, 0.5f),
  };

  // Metadata with TCP protocol (6)
  std::vector<FlowInfo> metadata;
  FlowInfo info;
  info.srcIp = "192.168.1.10";
  info.dstIp = "10.0.0.1";
  info.protocol = 6; // TCP
  metadata.push_back(info);

  EXPECT_CALL(*extractorPtr, extractFeatures(_)).WillOnce(Return(mockFeatures));
  ON_CALL(*extractorPtr, flowMetadata())
      .WillByDefault(::testing::ReturnRef(metadata));

  PredictionResult mlResult;
  mlResult.classification = AttackType::SshBruteForce;
  mlResult.confidence = 0.85f;
  EXPECT_CALL(*analyzerPtr, predictWithConfidence(_))
      .WillOnce(Return(mlResult));

  HybridDetectionService hybridService(nullptr, nullptr);
  AnalysisService service(std::move(analyzer), std::move(extractor),
                          MockNormalizer::createPassThrough());
  service.setHybridDetection(&hybridService);

  CaptureSession session;
  service.analyzeCapture("test.pcap", session);

  EXPECT_EQ(session.getDetectionResult(0).finalVerdict,
            AttackType::SshBruteForce);
}

TEST_F(AnalysisServiceTest, analyzeCapture_hybridProtocolMappingUdp) {
  auto analyzer = std::make_unique<MockAnalyzerWithConfidence>();
  auto *analyzerPtr = analyzer.get();
  auto extractor = std::make_unique<MockFlowExtractor>();
  auto *extractorPtr = extractor.get();

  std::vector<std::vector<float>> mockFeatures = {
      std::vector<float>(kFlowFeatureCount, 0.5f),
  };

  // Metadata with UDP protocol (17)
  std::vector<FlowInfo> metadata;
  FlowInfo info;
  info.srcIp = "192.168.1.10";
  info.dstIp = "10.0.0.1";
  info.protocol = 17; // UDP
  metadata.push_back(info);

  EXPECT_CALL(*extractorPtr, extractFeatures(_)).WillOnce(Return(mockFeatures));
  ON_CALL(*extractorPtr, flowMetadata())
      .WillByDefault(::testing::ReturnRef(metadata));

  PredictionResult mlResult;
  mlResult.classification = AttackType::DdosUdp;
  mlResult.confidence = 0.9f;
  EXPECT_CALL(*analyzerPtr, predictWithConfidence(_))
      .WillOnce(Return(mlResult));

  HybridDetectionService hybridService(nullptr, nullptr);
  AnalysisService service(std::move(analyzer), std::move(extractor),
                          MockNormalizer::createPassThrough());
  service.setHybridDetection(&hybridService);

  CaptureSession session;
  service.analyzeCapture("test.pcap", session);

  EXPECT_EQ(session.getDetectionResult(0).finalVerdict, AttackType::DdosUdp);
}

TEST_F(AnalysisServiceTest, analyzeCapture_hybridProtocolMappingIcmp) {
  auto analyzer = std::make_unique<MockAnalyzerWithConfidence>();
  auto *analyzerPtr = analyzer.get();
  auto extractor = std::make_unique<MockFlowExtractor>();
  auto *extractorPtr = extractor.get();

  std::vector<std::vector<float>> mockFeatures = {
      std::vector<float>(kFlowFeatureCount, 0.5f),
  };

  // Metadata with ICMP protocol (1)
  std::vector<FlowInfo> metadata;
  FlowInfo info;
  info.srcIp = "192.168.1.10";
  info.dstIp = "10.0.0.1";
  info.protocol = 1; // ICMP
  metadata.push_back(info);

  EXPECT_CALL(*extractorPtr, extractFeatures(_)).WillOnce(Return(mockFeatures));
  ON_CALL(*extractorPtr, flowMetadata())
      .WillByDefault(::testing::ReturnRef(metadata));

  PredictionResult mlResult;
  mlResult.classification = AttackType::IcmpFlood;
  mlResult.confidence = 0.88f;
  EXPECT_CALL(*analyzerPtr, predictWithConfidence(_))
      .WillOnce(Return(mlResult));

  HybridDetectionService hybridService(nullptr, nullptr);
  AnalysisService service(std::move(analyzer), std::move(extractor),
                          MockNormalizer::createPassThrough());
  service.setHybridDetection(&hybridService);

  CaptureSession session;
  service.analyzeCapture("test.pcap", session);

  EXPECT_EQ(session.getDetectionResult(0).finalVerdict, AttackType::IcmpFlood);
}

TEST_F(AnalysisServiceTest, analyzeCapture_hybridProtocolMappingOther) {
  auto analyzer = std::make_unique<MockAnalyzerWithConfidence>();
  auto *analyzerPtr = analyzer.get();
  auto extractor = std::make_unique<MockFlowExtractor>();
  auto *extractorPtr = extractor.get();

  std::vector<std::vector<float>> mockFeatures = {
      std::vector<float>(kFlowFeatureCount, 0.5f),
  };

  // Metadata with unsupported protocol (47 = GRE)
  std::vector<FlowInfo> metadata;
  FlowInfo info;
  info.srcIp = "192.168.1.10";
  info.dstIp = "10.0.0.1";
  info.protocol = 47; // GRE → should map to "OTHER"
  metadata.push_back(info);

  EXPECT_CALL(*extractorPtr, extractFeatures(_)).WillOnce(Return(mockFeatures));
  ON_CALL(*extractorPtr, flowMetadata())
      .WillByDefault(::testing::ReturnRef(metadata));

  PredictionResult mlResult;
  mlResult.classification = AttackType::Benign;
  mlResult.confidence = 0.95f;
  EXPECT_CALL(*analyzerPtr, predictWithConfidence(_))
      .WillOnce(Return(mlResult));

  HybridDetectionService hybridService(nullptr, nullptr);
  AnalysisService service(std::move(analyzer), std::move(extractor),
                          MockNormalizer::createPassThrough());
  service.setHybridDetection(&hybridService);

  CaptureSession session;
  service.analyzeCapture("test.pcap", session);

  EXPECT_EQ(session.getDetectionResult(0).finalVerdict, AttackType::Benign);
}

TEST_F(AnalysisServiceTest, setHybridDetection_canBeCleared) {
  auto analyzer = std::make_unique<MockAnalyzer>();
  auto extractor = std::make_unique<MockFlowExtractor>();

  // Return 1 flow
  std::vector<std::vector<float>> mockFeatures = {
      std::vector<float>(kFlowFeatureCount, 0.5f),
  };

  EXPECT_CALL(*extractor, extractFeatures(_)).WillOnce(Return(mockFeatures));
  EXPECT_CALL(*analyzer, predict(_)).WillOnce(Return(AttackType::Benign));

  HybridDetectionService hybridService(nullptr, nullptr);

  AnalysisService service(std::move(analyzer), std::move(extractor),
                          MockNormalizer::createPassThrough());
  service.setHybridDetection(&hybridService);
  service.setHybridDetection(nullptr); // Clear hybrid → fall back to ML-only

  CaptureSession session;
  service.analyzeCapture("test.pcap", session);

  // Should use ML-only path (predict() not predictWithConfidence())
  EXPECT_EQ(session.getDetectionResult(0).finalVerdict, AttackType::Benign);
  EXPECT_EQ(session.getDetectionResult(0).detectionSource,
            DetectionSource::MlOnly);
}

TEST_F(AnalysisServiceTest, analyzeCapture_extractionFailure_emitsNoFlows) {
  auto analyzer = std::make_unique<MockAnalyzer>();
  auto extractor = std::make_unique<MockFlowExtractor>();

  // extractFeatures returns empty on failure
  EXPECT_CALL(*extractor, extractFeatures(_))
      .WillOnce(Return(std::vector<std::vector<float>>{}));
  // predict should never be called if no features
  EXPECT_CALL(*analyzer, predict(_)).Times(0);

  AnalysisService service(std::move(analyzer), std::move(extractor),
                          MockNormalizer::createPassThrough());

  int startedCount = 0;
  int finishedCount = 0;
  service.setStartedCallback([&]() { ++startedCount; });
  service.setFinishedCallback([&]() { ++finishedCount; });

  CaptureSession session;
  service.analyzeCapture("test.pcap", session);

  EXPECT_EQ(startedCount, 1);
  EXPECT_EQ(finishedCount, 1);
}

TEST_F(AnalysisServiceTest, analyzeCapture_success_classifiesAllFlows) {
  auto analyzer = std::make_unique<MockAnalyzer>();
  auto *analyzerPtr = analyzer.get();
  auto extractor = std::make_unique<MockFlowExtractor>();
  auto *extractorPtr = extractor.get();

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

  AnalysisService service(std::move(analyzer), std::move(extractor),
                          MockNormalizer::createPassThrough());

  int startedCount = 0;
  int finishedCount = 0;
  std::vector<std::string> errors;
  std::vector<std::pair<int, int>> progressCalls;

  service.setStartedCallback([&]() { ++startedCount; });
  service.setFinishedCallback([&]() { ++finishedCount; });
  service.setErrorCallback([&](const std::string &msg) { errors.push_back(msg); });
  service.setProgressCallback([&](int current, int total) {
    progressCalls.emplace_back(current, total);
  });

  CaptureSession session;
  service.analyzeCapture("test.pcap", session);

  EXPECT_EQ(startedCount, 1);
  EXPECT_EQ(finishedCount, 1);
  EXPECT_EQ(errors.size(), 0u);

  // Progress emitted per-flow from the worker (total unknown during pipeline:
  // (1,0), (2,0), (3,0)), plus a final summary callback (3,3).
  EXPECT_EQ(progressCalls.size(), 4u);
  EXPECT_EQ(progressCalls[0].first, 1);
  EXPECT_EQ(progressCalls[0].second, 0);
  EXPECT_EQ(progressCalls[2].first, 3);
  EXPECT_EQ(progressCalls[2].second, 0);
  // Final summary callback with known total
  EXPECT_EQ(progressCalls[3].first, 3);
  EXPECT_EQ(progressCalls[3].second, 3);

  // Verify results stored in session (via DetectionResult API)
  EXPECT_EQ(session.getDetectionResult(0).finalVerdict, AttackType::Benign);
  EXPECT_EQ(session.getDetectionResult(1).finalVerdict, AttackType::DdosIcmp);
  EXPECT_EQ(session.getDetectionResult(2).finalVerdict,
            AttackType::SshBruteForce);
}

TEST_F(AnalysisServiceTest,
       analyzeCapture_emptyFeatures_finishesWithoutPrediction) {
  auto analyzer = std::make_unique<MockAnalyzer>();
  auto extractor = std::make_unique<MockFlowExtractor>();

  EXPECT_CALL(*extractor, extractFeatures(_))
      .WillOnce(Return(std::vector<std::vector<float>>{}));
  EXPECT_CALL(*analyzer, predict(_)).Times(0);

  AnalysisService service(std::move(analyzer), std::move(extractor),
                          MockNormalizer::createPassThrough());

  int finishedCount = 0;
  std::vector<std::string> errors;
  std::vector<std::pair<int, int>> progressCalls;

  service.setFinishedCallback([&]() { ++finishedCount; });
  service.setErrorCallback([&](const std::string &msg) { errors.push_back(msg); });
  service.setProgressCallback([&](int current, int total) {
    progressCalls.emplace_back(current, total);
  });

  CaptureSession session;
  service.analyzeCapture("empty.pcap", session);

  EXPECT_EQ(finishedCount, 1);
  EXPECT_EQ(errors.size(), 0u);
  EXPECT_EQ(progressCalls.size(), 0u);
}

TEST_F(AnalysisServiceTest, analyzeCapture_singleFlow_correctProgress) {
  auto analyzer = std::make_unique<MockAnalyzer>();
  auto extractor = std::make_unique<MockFlowExtractor>();

  std::vector<std::vector<float>> singleFlow = {
      std::vector<float>(kFlowFeatureCount, 0.42f),
  };

  EXPECT_CALL(*extractor, extractFeatures(_)).WillOnce(Return(singleFlow));
  EXPECT_CALL(*analyzer, predict(_)).WillOnce(Return(AttackType::PortScanning));

  AnalysisService service(std::move(analyzer), std::move(extractor),
                          MockNormalizer::createPassThrough());

  std::vector<std::pair<int, int>> progressCalls;
  service.setProgressCallback([&](int current, int total) {
    progressCalls.emplace_back(current, total);
  });

  CaptureSession session;
  service.analyzeCapture("single.pcap", session);

  // Worker emits (1,0) then final summary (1,1).
  ASSERT_EQ(progressCalls.size(), 2u);
  EXPECT_EQ(progressCalls[0].first, 1);
  EXPECT_EQ(progressCalls[0].second, 0);
  EXPECT_EQ(progressCalls[1].first, 1);
  EXPECT_EQ(progressCalls[1].second, 1);
  EXPECT_EQ(session.getDetectionResult(0).finalVerdict,
            AttackType::PortScanning);
}
