#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "app/AnalysisService.h"
#include "app/CaptureController.h"
#include "core/model/AttackType.h"
#include "core/model/CaptureSession.h"
#include "core/services/IFeatureNormalizer.h"
#include "core/services/IFlowExtractor.h"
#include "core/services/IPacketAnalyzer.h"
#include "core/services/IPacketCapture.h"
#include "infra/flow/NativeFlowExtractor.h" // kFlowFeatureCount

#include <array>
#include <format>

#include <QCoreApplication>
#include <QSignalSpy>

using namespace nids::core;
using namespace nids::app;
using nids::infra::kFlowFeatureCount;
using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

// ── Mocks ────────────────────────────────────────────────────────────

class MockCapture : public IPacketCapture {
public:
  MOCK_METHOD(bool, initialize, (const std::string &, const std::string &),
              (override));
  MOCK_METHOD(void, startCapture, (const std::string &), (override));
  MOCK_METHOD(void, stopCapture, (), (override));
  MOCK_METHOD(bool, isCapturing, (), (const, override));
  MOCK_METHOD(void, setPacketCallback, (PacketCallback), (override));
  MOCK_METHOD(void, setErrorCallback, (ErrorCallback), (override));
  MOCK_METHOD(std::vector<std::string>, listInterfaces, (), (override));
};

class MockAnalyzer : public IPacketAnalyzer {
public:
  MOCK_METHOD(bool, loadModel, (const std::string &), (override));
  MOCK_METHOD(AttackType, predict, (const std::vector<float> &), (override));
};

class MockExtractor : public IFlowExtractor {
public:
  MockExtractor() {
    ON_CALL(*this, flowMetadata())
        .WillByDefault(::testing::ReturnRef(emptyMetadata_));
  }

  void setFlowCompletionCallback(FlowCompletionCallback /*cb*/) override {}
  void processPacket(const std::uint8_t* /*data*/, std::size_t /*length*/,
                     std::int64_t /*timestampUs*/) override {}
  void finalizeAllFlows() override {}
  void reset() override {}

  MOCK_METHOD(std::vector<std::vector<float>>, extractFeatures,
              (const std::string &), (override));
  MOCK_METHOD(const std::vector<FlowInfo> &, flowMetadata, (),
              (const, noexcept, override));

  std::vector<FlowInfo> emptyMetadata_;
};

/// Pass-through normalizer mock: returns features unchanged.
class MockNormalizer : public IFeatureNormalizer {
public:
  MOCK_METHOD(bool, loadMetadata, (const std::string &), (override));
  MOCK_METHOD(std::vector<float>, normalize, (const std::vector<float> &),
              (const, override));
  MOCK_METHOD(bool, isLoaded, (), (const, noexcept, override));
  MOCK_METHOD(std::size_t, featureCount, (), (const, noexcept, override));

  static std::unique_ptr<MockNormalizer> createPassThrough() {
    auto mock = std::make_unique<MockNormalizer>();
    ON_CALL(*mock, normalize(_)).WillByDefault([](const std::vector<float> &f) {
      return f;
    });
    return mock;
  }
};

// ── Fixture ──────────────────────────────────────────────────────────

class PipelineTest : public ::testing::Test {
protected: // NOSONAR
  void SetUp() override {
    if (!QCoreApplication::instance()) {
      static int argc = 1;
      static std::array<char, 5> appName = {'t', 'e', 's', 't', '\0'};
      static auto *appNamePtr = appName.data();
      app_ = std::make_unique<QCoreApplication>(argc, &appNamePtr);
    }
  }

  std::unique_ptr<QCoreApplication> app_;
};

// ── Integration: Capture -> Analysis Pipeline ────────────────────────

TEST_F(PipelineTest, captureAndAnalyze_endToEnd) {
  // Set up capture mock
  auto capture = std::make_unique<MockCapture>();
  auto *capturePtr = capture.get();
  IPacketCapture::PacketCallback packetCb;

  EXPECT_CALL(*capturePtr, setPacketCallback(_))
      .WillOnce(Invoke([&packetCb](IPacketCapture::PacketCallback cb) {
        packetCb = std::move(cb);
      }));
  EXPECT_CALL(*capturePtr, setErrorCallback(_));
  EXPECT_CALL(*capturePtr, isCapturing())
      .WillOnce(Return(false)) // startCapture guard
      .WillOnce(Return(true))  // stopCapture guard
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*capturePtr, initialize(_, _)).WillOnce(Return(true));
  EXPECT_CALL(*capturePtr, startCapture(_));
  EXPECT_CALL(*capturePtr, stopCapture());

  CaptureController controller(std::move(capture));

  // Start capture
  PacketFilter filter;
  filter.networkCard = "eth0";
  controller.startCapture(filter);

  // Simulate packets arriving
  for (int i = 0; i < 5; ++i) {
    PacketInfo pkt;
    pkt.protocol = "TCP";
    pkt.ipSource = std::format("192.168.1.{}", i + 1);
    pkt.ipDestination = "10.0.0.1";
    pkt.portSource = std::to_string(10000 + i);
    pkt.portDestination = "443";
    packetCb(pkt);
  }

  EXPECT_EQ(controller.session().packetCount(), 5u);

  // Stop capture
  controller.stopCapture();

  // Set up analysis mocks
  auto analyzer = std::make_unique<MockAnalyzer>();
  auto extractor = std::make_unique<MockExtractor>();

  std::vector<std::vector<float>> flows = {
      std::vector<float>(kFlowFeatureCount, 0.1f),
      std::vector<float>(kFlowFeatureCount, 0.9f),
  };

  EXPECT_CALL(*extractor, extractFeatures(_)).WillOnce(Return(flows));
  EXPECT_CALL(*analyzer, predict(_))
      .WillOnce(Return(AttackType::Benign))
      .WillOnce(Return(AttackType::SynFlood));

  AnalysisService analysisService(std::move(analyzer), std::move(extractor),
                                  MockNormalizer::createPassThrough());

  QSignalSpy startedSpy(&analysisService, &AnalysisService::analysisStarted);
  QSignalSpy finishedSpy(&analysisService, &AnalysisService::analysisFinished);

  // Run analysis on the captured session
  analysisService.analyzeCapture("dump.pcap", controller.session());

  EXPECT_EQ(startedSpy.count(), 1);
  EXPECT_EQ(finishedSpy.count(), 1);

  // Verify analysis results are stored in session (via DetectionResult API)
  EXPECT_EQ(controller.session().getDetectionResult(0).finalVerdict,
            AttackType::Benign);
  EXPECT_EQ(controller.session().getDetectionResult(1).finalVerdict,
            AttackType::SynFlood);
}

TEST_F(PipelineTest, captureFailure_doesNotProceedToAnalysis) {
  auto capture = std::make_unique<MockCapture>();
  auto *capturePtr = capture.get();

  EXPECT_CALL(*capturePtr, setPacketCallback(_));
  EXPECT_CALL(*capturePtr, setErrorCallback(_));
  EXPECT_CALL(*capturePtr, isCapturing()).WillRepeatedly(Return(false));
  EXPECT_CALL(*capturePtr, initialize(_, _)).WillOnce(Return(false));

  CaptureController controller(std::move(capture));
  QSignalSpy errorSpy(&controller, &CaptureController::captureError);

  PacketFilter filter;
  filter.networkCard = "bad_iface";
  controller.startCapture(filter);

  EXPECT_EQ(errorSpy.count(), 1);
  EXPECT_EQ(controller.session().packetCount(), 0u);
}

TEST_F(PipelineTest, analysisWithAllAttackTypes) {
  auto analyzer = std::make_unique<MockAnalyzer>();
  auto extractor = std::make_unique<MockExtractor>();

  // Create one flow per attack type
  std::vector<std::vector<float>> flows;
  for (int i = 0; i < kAttackTypeCount; ++i) {
    flows.emplace_back(kFlowFeatureCount,
                       static_cast<float>(i) / kAttackTypeCount);
  }

  int callIndex = 0;
  EXPECT_CALL(*extractor, extractFeatures(_)).WillOnce(Return(flows));
  EXPECT_CALL(*analyzer, predict(_))
      .Times(kAttackTypeCount)
      .WillRepeatedly(Invoke([&callIndex](const std::vector<float> &) {
        int idx = callIndex;
        ++callIndex;
        return attackTypeFromIndex(idx);
      }));

  AnalysisService service(std::move(analyzer), std::move(extractor),
                          MockNormalizer::createPassThrough());

  CaptureSession session;
  service.analyzeCapture("all_types.pcap", session);

  // Verify each attack type is correctly stored (via DetectionResult API)
  for (int i = 0; i < kAttackTypeCount; ++i) {
    EXPECT_EQ(
        session.getDetectionResult(static_cast<std::size_t>(i)).finalVerdict,
        attackTypeFromIndex(i))
        << "Mismatch at index " << i;
  }
}
