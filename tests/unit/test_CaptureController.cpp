#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "app/CaptureController.h"
#include "core/services/IPacketCapture.h"
#include "core/services/PacketFilter.h"

#include <array>

#include <QCoreApplication>
#include <QSignalSpy>

using namespace nids::core;
using namespace nids::app;
using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

// ── Mock ─────────────────────────────────────────────────────────────

class MockPacketCapture : public IPacketCapture {
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

// ── Fixture ──────────────────────────────────────────────────────────

class CaptureControllerTest : public ::testing::Test {
protected: // NOSONAR
  void SetUp() override {
    // Ensure QCoreApplication exists for signal/slot processing
    if (!QCoreApplication::instance()) {
      static int argc = 1;
      static std::array<char, 5> appName = {'t', 'e', 's', 't', '\0'};
      static auto *appNamePtr = appName.data();
      app_ = std::make_unique<QCoreApplication>(argc, &appNamePtr);
    }
  }

  std::unique_ptr<QCoreApplication> app_;
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
  EXPECT_CALL(*mockPtr, initialize(_, _)).WillOnce(Return(false));
  // startCapture should NOT be called when init fails
  EXPECT_CALL(*mockPtr, startCapture(_)).Times(0);

  CaptureController controller(std::move(mock));
  QSignalSpy errorSpy(&controller, &CaptureController::captureError);

  PacketFilter filter;
  filter.networkCard = "eth0";
  controller.startCapture(filter);

  EXPECT_EQ(errorSpy.count(), 1);
  EXPECT_TRUE(errorSpy.first().at(0).toString().contains("eth0"));
}

TEST_F(CaptureControllerTest, startCapture_initSuccess_emitsStarted) {
  auto mock = std::make_unique<MockPacketCapture>();
  auto *mockPtr = mock.get();

  EXPECT_CALL(*mockPtr, setPacketCallback(_));
  EXPECT_CALL(*mockPtr, setErrorCallback(_));
  EXPECT_CALL(*mockPtr, isCapturing()).WillRepeatedly(Return(false));
  EXPECT_CALL(*mockPtr, initialize("eth0", _)).WillOnce(Return(true));
  EXPECT_CALL(*mockPtr, startCapture(_)).Times(1);

  CaptureController controller(std::move(mock));
  QSignalSpy startedSpy(&controller, &CaptureController::captureStarted);

  PacketFilter filter;
  filter.networkCard = "eth0";
  controller.startCapture(filter);

  EXPECT_EQ(startedSpy.count(), 1);
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
  QSignalSpy stoppedSpy(&controller, &CaptureController::captureStopped);

  controller.stopCapture();

  EXPECT_EQ(stoppedSpy.count(), 1);
}

TEST_F(CaptureControllerTest, stopCapture_whenNotCapturing_doesNothing) {
  auto mock = std::make_unique<MockPacketCapture>();
  auto *mockPtr = mock.get();

  EXPECT_CALL(*mockPtr, setPacketCallback(_));
  EXPECT_CALL(*mockPtr, setErrorCallback(_));
  EXPECT_CALL(*mockPtr, isCapturing()).WillRepeatedly(Return(false));
  EXPECT_CALL(*mockPtr, stopCapture()).Times(0);

  CaptureController controller(std::move(mock));
  QSignalSpy stoppedSpy(&controller, &CaptureController::captureStopped);

  controller.stopCapture();
  EXPECT_EQ(stoppedSpy.count(), 0);
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
  QSignalSpy packetSpy(&controller, &CaptureController::packetReceived);

  // Simulate a packet arrival
  PacketInfo pkt;
  pkt.protocol = "TCP";
  pkt.ipSource = "1.2.3.4";
  storedCallback(pkt);

  EXPECT_EQ(controller.session().packetCount(), 1u);
  EXPECT_EQ(controller.session().getPacket(0).protocol, "TCP");
  EXPECT_EQ(packetSpy.count(), 1);
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
  QSignalSpy errorSpy(&controller, &CaptureController::captureError);

  storedErrorCb("pcap read error");

  EXPECT_EQ(errorSpy.count(), 1);
  EXPECT_EQ(errorSpy.first().at(0).toString(), QString("pcap read error"));
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
