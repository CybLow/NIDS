#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "helpers/MockPacketCapture.h"

#include "app/CaptureController.h"
#include "core/model/PacketFilter.h"
#include "core/model/ProtocolConstants.h"

#include <expected>
#include <string>
#include <vector>

using namespace nids::core;
using namespace nids::app;
using nids::testing::MockPacketCapture;
using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

// ── Fixture ──────────────────────────────────────────────────────────

class CaptureControllerTest : public ::testing::Test {
protected: // NOSONAR
};

// ── Tests ────────────────────────────────────────────────────────────

TEST_F(CaptureControllerTest, constructorSetsCallbacks) {
  auto mock = std::make_unique<MockPacketCapture>();
  EXPECT_CALL(*mock, setPacketCallback(_)).Times(1);
  EXPECT_CALL(*mock, setErrorCallback(_)).Times(1);

  CaptureController controller(std::move(mock));
}

TEST_F(CaptureControllerTest, startCapture_initFailure_emitsError) {
  auto mock = std::make_unique<MockPacketCapture>();
  auto *mockPtr = mock.get();

  EXPECT_CALL(*mockPtr, setPacketCallback(_));
  EXPECT_CALL(*mockPtr, setErrorCallback(_));
  EXPECT_CALL(*mockPtr, isCapturing()).WillRepeatedly(Return(false));
  EXPECT_CALL(*mockPtr, initialize(_, _))
      .WillOnce(Return(std::unexpected<std::string>("mock init failure")));
  // startCapture should NOT be called when init fails
  EXPECT_CALL(*mockPtr, startCapture(_)).Times(0);

  CaptureController controller(std::move(mock));

  std::vector<std::string> errors;
  controller.setCaptureErrorCallback(
      [&](const std::string &msg) { errors.push_back(msg); });

  PacketFilter filter;
  filter.networkCard = "eth0";
  controller.startCapture(filter);

  EXPECT_EQ(errors.size(), 1u);
  EXPECT_TRUE(errors[0].find("eth0") != std::string::npos);
}

TEST_F(CaptureControllerTest, startCapture_initSuccess_emitsStarted) {
  auto mock = std::make_unique<MockPacketCapture>();
  auto *mockPtr = mock.get();

  EXPECT_CALL(*mockPtr, setPacketCallback(_));
  EXPECT_CALL(*mockPtr, setErrorCallback(_));
  EXPECT_CALL(*mockPtr, isCapturing()).WillRepeatedly(Return(false));
  EXPECT_CALL(*mockPtr, initialize("eth0", _))
      .WillOnce(Return(std::expected<void, std::string>{}));
  EXPECT_CALL(*mockPtr, startCapture(_)).Times(1);

  CaptureController controller(std::move(mock));

  int startedCount = 0;
  controller.setCaptureStartedCallback([&]() { ++startedCount; });

  PacketFilter filter;
  filter.networkCard = "eth0";
  controller.startCapture(filter);

  EXPECT_EQ(startedCount, 1);
}

TEST_F(CaptureControllerTest, startCapture_alreadyCapturing_doesNothing) {
  auto mock = std::make_unique<MockPacketCapture>();
  auto *mockPtr = mock.get();

  EXPECT_CALL(*mockPtr, setPacketCallback(_));
  EXPECT_CALL(*mockPtr, setErrorCallback(_));
  EXPECT_CALL(*mockPtr, isCapturing()).WillRepeatedly(Return(true));
  // Neither initialize nor startCapture should be called
  EXPECT_CALL(*mockPtr, initialize(_, _)).Times(0);
  EXPECT_CALL(*mockPtr, startCapture(_)).Times(0);

  CaptureController controller(std::move(mock));

  PacketFilter filter;
  filter.networkCard = "eth0";
  controller.startCapture(filter);
}

TEST_F(CaptureControllerTest, stopCapture_whenCapturing_emitsStopped) {
  auto mock = std::make_unique<MockPacketCapture>();
  auto *mockPtr = mock.get();

  EXPECT_CALL(*mockPtr, setPacketCallback(_));
  EXPECT_CALL(*mockPtr, setErrorCallback(_));
  EXPECT_CALL(*mockPtr, isCapturing())
      .WillOnce(Return(true)) // guard in stopCapture()
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*mockPtr, stopCapture()).Times(1);

  CaptureController controller(std::move(mock));

  int stoppedCount = 0;
  controller.setCaptureStoppedCallback([&]() { ++stoppedCount; });

  controller.stopCapture();

  EXPECT_EQ(stoppedCount, 1);
}

TEST_F(CaptureControllerTest, stopCapture_whenNotCapturing_doesNothing) {
  auto mock = std::make_unique<MockPacketCapture>();
  auto *mockPtr = mock.get();

  EXPECT_CALL(*mockPtr, setPacketCallback(_));
  EXPECT_CALL(*mockPtr, setErrorCallback(_));
  EXPECT_CALL(*mockPtr, isCapturing()).WillRepeatedly(Return(false));
  EXPECT_CALL(*mockPtr, stopCapture()).Times(0);

  CaptureController controller(std::move(mock));

  int stoppedCount = 0;
  controller.setCaptureStoppedCallback([&]() { ++stoppedCount; });

  controller.stopCapture();
  EXPECT_EQ(stoppedCount, 0);
}

TEST_F(CaptureControllerTest, packetCallback_forwardsToSession) {
  auto mock = std::make_unique<MockPacketCapture>();
  auto *mockPtr = mock.get();

  IPacketCapture::PacketCallback storedCallback;
  EXPECT_CALL(*mockPtr, setPacketCallback(_))
      .WillOnce(Invoke([&storedCallback](IPacketCapture::PacketCallback cb) {
        storedCallback = std::move(cb);
      }));
  EXPECT_CALL(*mockPtr, setErrorCallback(_));

  CaptureController controller(std::move(mock));

  int packetCount = 0;
  controller.setPacketReceivedCallback(
      [&](const PacketInfo &) { ++packetCount; });

  // Simulate a packet arrival
  PacketInfo pkt;
  pkt.protocol = kIpProtoTcp;
  pkt.ipSource = "1.2.3.4";
  storedCallback(pkt);

  EXPECT_EQ(controller.session().packetCount(), 1u);
  EXPECT_EQ(controller.session().getPacket(0).protocol, kIpProtoTcp);
  EXPECT_EQ(packetCount, 1);
}

TEST_F(CaptureControllerTest, errorCallback_emitsCaptureError) {
  auto mock = std::make_unique<MockPacketCapture>();
  auto *mockPtr = mock.get();

  IPacketCapture::ErrorCallback storedErrorCb;
  EXPECT_CALL(*mockPtr, setPacketCallback(_));
  EXPECT_CALL(*mockPtr, setErrorCallback(_))
      .WillOnce(Invoke([&storedErrorCb](IPacketCapture::ErrorCallback cb) {
        storedErrorCb = std::move(cb);
      }));

  CaptureController controller(std::move(mock));

  std::vector<std::string> errors;
  controller.setCaptureErrorCallback(
      [&](const std::string &msg) { errors.push_back(msg); });

  storedErrorCb("pcap read error");

  EXPECT_EQ(errors.size(), 1u);
  EXPECT_EQ(errors[0], "pcap read error");
}

TEST_F(CaptureControllerTest, listInterfaces_delegatesToCapture) {
  auto mock = std::make_unique<MockPacketCapture>();
  auto *mockPtr = mock.get();

  EXPECT_CALL(*mockPtr, setPacketCallback(_));
  EXPECT_CALL(*mockPtr, setErrorCallback(_));
  EXPECT_CALL(*mockPtr, listInterfaces())
      .WillOnce(Return(std::vector<std::string>{"eth0", "lo", "wlan0"}));

  CaptureController controller(std::move(mock));
  auto interfaces = controller.listInterfaces();

  ASSERT_EQ(interfaces.size(), 3u);
  EXPECT_EQ(interfaces[0], "eth0");
  EXPECT_EQ(interfaces[1], "lo");
  EXPECT_EQ(interfaces[2], "wlan0");
}

TEST_F(CaptureControllerTest, session_initiallyEmpty) {
  auto mock = std::make_unique<MockPacketCapture>();
  EXPECT_CALL(*mock, setPacketCallback(_));
  EXPECT_CALL(*mock, setErrorCallback(_));

  CaptureController controller(std::move(mock));
  EXPECT_EQ(controller.session().packetCount(), 0u);
}

TEST_F(CaptureControllerTest, destructor_stopsCapture) {
  auto mock = std::make_unique<MockPacketCapture>();
  auto *mockPtr = mock.get();

  EXPECT_CALL(*mockPtr, setPacketCallback(_));
  EXPECT_CALL(*mockPtr, setErrorCallback(_));
  EXPECT_CALL(*mockPtr, isCapturing())
      .WillOnce(Return(true)) // destructor: if (isCapturing())
      .WillOnce(Return(true)) // stopCapture: if (!isCapturing()) guard
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*mockPtr, stopCapture()).Times(1);

  {
    CaptureController controller(std::move(mock));
  }
  // Destructor should have called stopCapture
}

TEST_F(CaptureControllerTest, enableLiveDetection_setsAndClears) {
  auto mock = std::make_unique<MockPacketCapture>();
  EXPECT_CALL(*mock, setPacketCallback(_));
  EXPECT_CALL(*mock, setErrorCallback(_));
  EXPECT_CALL(*mock, isCapturing()).WillRepeatedly(Return(false));

  CaptureController controller(std::move(mock));

  // isLiveDetectionActive should be false by default
  EXPECT_FALSE(controller.isLiveDetectionActive());

  // enableLiveDetection with a non-null pipeline pointer
  // We can't easily construct a LiveDetectionPipeline here, but we can
  // test the null case.
  controller.enableLiveDetection(nullptr);
  EXPECT_FALSE(controller.isLiveDetectionActive());
}

TEST_F(CaptureControllerTest, disableLiveDetection_whenNoPipeline_noOp) {
  auto mock = std::make_unique<MockPacketCapture>();
  EXPECT_CALL(*mock, setPacketCallback(_));
  EXPECT_CALL(*mock, setErrorCallback(_));

  CaptureController controller(std::move(mock));

  // disableLiveDetection with no pipeline set — should be a no-op.
  controller.disableLiveDetection();
  EXPECT_FALSE(controller.isLiveDetectionActive());
}

TEST_F(CaptureControllerTest, startCapture_withCustomDumpFile) {
  auto mock = std::make_unique<MockPacketCapture>();
  auto *mockPtr = mock.get();

  EXPECT_CALL(*mockPtr, setPacketCallback(_));
  EXPECT_CALL(*mockPtr, setErrorCallback(_));
  EXPECT_CALL(*mockPtr, isCapturing()).WillRepeatedly(Return(false));
  EXPECT_CALL(*mockPtr, initialize("eth0", _))
      .WillOnce(Return(std::expected<void, std::string>{}));
  // Should pass the custom dump file, not the config default.
  EXPECT_CALL(*mockPtr, startCapture("custom_dump.pcap")).Times(1);

  CaptureController controller(std::move(mock));

  PacketFilter filter;
  filter.networkCard = "eth0";
  controller.startCapture(filter, "custom_dump.pcap");
}

TEST_F(CaptureControllerTest, constSession_isAccessible) {
  auto mock = std::make_unique<MockPacketCapture>();
  EXPECT_CALL(*mock, setPacketCallback(_));
  EXPECT_CALL(*mock, setErrorCallback(_));

  CaptureController controller(std::move(mock));
  const auto &constController = controller;
  EXPECT_EQ(constController.session().packetCount(), 0u);
}

TEST_F(CaptureControllerTest, destructor_notCapturing_doesNotCallStop) {
  auto mock = std::make_unique<MockPacketCapture>();
  auto *mockPtr = mock.get();

  EXPECT_CALL(*mockPtr, setPacketCallback(_));
  EXPECT_CALL(*mockPtr, setErrorCallback(_));
  EXPECT_CALL(*mockPtr, isCapturing()).WillRepeatedly(Return(false));
  // stopCapture should NOT be called since we're not capturing.
  EXPECT_CALL(*mockPtr, stopCapture()).Times(0);

  {
    CaptureController controller(std::move(mock));
  }
}

TEST_F(CaptureControllerTest,
       startCapture_initFailure_noErrorCallback_noThrow) {
  auto mock = std::make_unique<MockPacketCapture>();
  auto *mockPtr = mock.get();

  EXPECT_CALL(*mockPtr, setPacketCallback(_));
  EXPECT_CALL(*mockPtr, setErrorCallback(_));
  EXPECT_CALL(*mockPtr, isCapturing()).WillRepeatedly(Return(false));
  EXPECT_CALL(*mockPtr, initialize(_, _))
      .WillOnce(Return(std::unexpected<std::string>("init fail")));

  CaptureController controller(std::move(mock));
  // Do NOT set error callback — test that null callback guard works.

  PacketFilter filter;
  filter.networkCard = "eth0";
  controller.startCapture(filter);
  // No crash = success.
}

TEST_F(CaptureControllerTest, stopCapture_emitsStoppedCallback) {
  auto mock = std::make_unique<MockPacketCapture>();
  auto *mockPtr = mock.get();

  EXPECT_CALL(*mockPtr, setPacketCallback(_));
  EXPECT_CALL(*mockPtr, setErrorCallback(_));
  EXPECT_CALL(*mockPtr, isCapturing())
      .WillOnce(Return(false)) // startCapture guard
      .WillOnce(Return(true))  // stopCapture guard
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*mockPtr, initialize(_, _))
      .WillOnce(Return(std::expected<void, std::string>{}));
  EXPECT_CALL(*mockPtr, startCapture(_)).Times(1);
  EXPECT_CALL(*mockPtr, stopCapture()).Times(1);

  CaptureController controller(std::move(mock));

  int startedCount = 0;
  int stoppedCount = 0;
  controller.setCaptureStartedCallback([&]() { ++startedCount; });
  controller.setCaptureStoppedCallback([&]() { ++stoppedCount; });

  PacketFilter filter;
  filter.networkCard = "eth0";
  controller.startCapture(filter);
  EXPECT_EQ(startedCount, 1);

  controller.stopCapture();
  EXPECT_EQ(stoppedCount, 1);
}
