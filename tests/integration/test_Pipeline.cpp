#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "helpers/MockAnalyzer.h"
#include "helpers/MockFlowExtractor.h"
#include "helpers/MockNormalizer.h"
#include "helpers/MockPacketCapture.h"

#include "app/AnalysisService.h"
#include "app/CaptureController.h"
#include "core/model/AttackType.h"
#include "core/model/CaptureSession.h"
#include "core/model/ProtocolConstants.h"
#include "core/model/FlowConstants.h"

#include <expected>
#include <format>
#include <span>
#include <string>
#include <vector>

using namespace nids::core;
using namespace nids::app;
using nids::core::kFlowFeatureCount;
using nids::testing::MockAnalyzer;
using nids::testing::MockFlowExtractor;
using nids::testing::MockNormalizer;
using nids::testing::MockPacketCapture;
using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

// ── Integration: Capture -> Analysis Pipeline ────────────────────────

TEST(Pipeline, captureAndAnalyze_endToEnd) {
  // Set up capture mock
  auto capture = std::make_unique<MockPacketCapture>();
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
  EXPECT_CALL(*capturePtr, initialize(_, _))
      .WillOnce(Return(std::expected<void, std::string>{}));
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
    pkt.protocol = kIpProtoTcp;
    pkt.ipSource = std::format("192.168.1.{}", i + 1);
    pkt.ipDestination = "10.0.0.1";
    pkt.portSource = static_cast<std::uint16_t>(10000 + i);
    pkt.portDestination = 443;
    packetCb(pkt);
  }

  EXPECT_EQ(controller.session().packetCount(), 5u);

  // Stop capture
  controller.stopCapture();

  // Set up analysis mocks
  auto analyzer = std::make_unique<MockAnalyzer>();
  auto extractor = std::make_unique<MockFlowExtractor>();

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

  int startedCount = 0;
  int finishedCount = 0;
  analysisService.setStartedCallback([&]() { ++startedCount; });
  analysisService.setFinishedCallback([&]() { ++finishedCount; });

  // Run analysis on the captured session
  analysisService.analyzeCapture("dump.pcap", controller.session());

  EXPECT_EQ(startedCount, 1);
  EXPECT_EQ(finishedCount, 1);

  // Verify analysis results are stored in session (via DetectionResult API)
  EXPECT_EQ(controller.session().getDetectionResult(0).finalVerdict,
            AttackType::Benign);
  EXPECT_EQ(controller.session().getDetectionResult(1).finalVerdict,
            AttackType::SynFlood);
}

TEST(Pipeline, captureFailure_doesNotProceedToAnalysis) {
  auto capture = std::make_unique<MockPacketCapture>();
  auto *capturePtr = capture.get();

  EXPECT_CALL(*capturePtr, setPacketCallback(_));
  EXPECT_CALL(*capturePtr, setErrorCallback(_));
  EXPECT_CALL(*capturePtr, isCapturing()).WillRepeatedly(Return(false));
  EXPECT_CALL(*capturePtr, initialize(_, _))
      .WillOnce(Return(std::unexpected<std::string>("mock init failure")));

  CaptureController controller(std::move(capture));

  std::vector<std::string> errors;
  controller.setCaptureErrorCallback([&](const std::string &msg) {
    errors.push_back(msg);
  });

  PacketFilter filter;
  filter.networkCard = "bad_iface";
  controller.startCapture(filter);

  EXPECT_EQ(errors.size(), 1u);
  EXPECT_EQ(controller.session().packetCount(), 0u);
}

TEST(Pipeline, analysisWithAllAttackTypes) {
  auto analyzer = std::make_unique<MockAnalyzer>();
  auto extractor = std::make_unique<MockFlowExtractor>();

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
      .WillRepeatedly(Invoke([&callIndex](std::span<const float>) {
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
