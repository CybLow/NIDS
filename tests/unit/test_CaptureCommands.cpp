#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "helpers/MockPacketCapture.h"

#include "app/CaptureController.h"
#include "app/commands/CaptureCommands.h"
#include "core/model/PacketFilter.h"

#include <expected>
#include <string>
#include <vector>

using namespace nids::core;
using namespace nids::app;
using nids::testing::MockPacketCapture;
using ::testing::_;

// ── Tests ────────────────────────────────────────────────────────────

TEST(CaptureCommands, StartCaptureCommand_name) {
  auto mockCapture = std::make_unique<MockPacketCapture>();
  CaptureController controller(std::move(mockCapture));
  PacketFilter filter;
  StartCaptureCommand cmd(controller, filter);

  EXPECT_EQ(cmd.name(), "StartCapture");
}

TEST(CaptureCommands, StopCaptureCommand_name) {
  auto mockCapture = std::make_unique<MockPacketCapture>();
  CaptureController controller(std::move(mockCapture));
  StopCaptureCommand cmd(controller);

  EXPECT_EQ(cmd.name(), "StopCapture");
}

TEST(CaptureCommands, StartCaptureCommand_implementsICommand) {
  auto mockCapture = std::make_unique<MockPacketCapture>();
  CaptureController controller(std::move(mockCapture));
  PacketFilter filter;
  StartCaptureCommand cmd(controller, filter);

  // Verify it satisfies the ICommand interface.
  const ICommand *iface = &cmd;
  EXPECT_EQ(iface->name(), "StartCapture");
}

TEST(CaptureCommands, StopCaptureCommand_implementsICommand) {
  auto mockCapture = std::make_unique<MockPacketCapture>();
  CaptureController controller(std::move(mockCapture));
  StopCaptureCommand cmd(controller);

  const ICommand *iface = &cmd;
  EXPECT_EQ(iface->name(), "StopCapture");
}

TEST(CaptureCommands, StartCommand_execute_callsStartCapture) {
  auto mockCapture = std::make_unique<MockPacketCapture>();
  auto *raw = mockCapture.get();

  // startCapture path: initialize → startCapture(dumpFile).
  EXPECT_CALL(*raw, initialize(_, _))
      .WillOnce(testing::Return(std::expected<void, std::string>{}));
  EXPECT_CALL(*raw, startCapture(_)).Times(1);

  CaptureController controller(std::move(mockCapture));
  PacketFilter filter;
  filter.networkCard = "lo";
  StartCaptureCommand cmd(controller, filter);

  cmd.execute();
}

TEST(CaptureCommands, StartCommand_undo_callsStopCapture) {
  auto mockCapture = std::make_unique<MockPacketCapture>();
  auto *raw = mockCapture.get();

  // isCapturing returns false initially, true after start, false after stop.
  bool capturing = false;
  ON_CALL(*raw, isCapturing()).WillByDefault([&] { return capturing; });

  EXPECT_CALL(*raw, initialize(_, _))
      .WillOnce(testing::Return(std::expected<void, std::string>{}));
  EXPECT_CALL(*raw, startCapture(_)).WillOnce([&](const std::string &) {
    capturing = true;
  });
  EXPECT_CALL(*raw, stopCapture()).WillOnce([&] { capturing = false; });

  CaptureController controller(std::move(mockCapture));
  PacketFilter filter;
  filter.networkCard = "lo";
  StartCaptureCommand cmd(controller, filter);

  cmd.execute();
  EXPECT_TRUE(controller.isCapturing());
  cmd.undo(); // Should call stopCapture()
  EXPECT_FALSE(controller.isCapturing());
}

TEST(CaptureCommands, StopCommand_undo_restartsCapture) {
  auto mockCapture = std::make_unique<MockPacketCapture>();
  auto *raw = mockCapture.get();

  bool capturing = false;
  ON_CALL(*raw, isCapturing()).WillByDefault([&] { return capturing; });

  // First start + stop + restart (undo) sequence.
  EXPECT_CALL(*raw, initialize(_, _))
      .WillRepeatedly(testing::Return(std::expected<void, std::string>{}));
  EXPECT_CALL(*raw, startCapture(_))
      .Times(2)
      .WillRepeatedly([&](const std::string &) { capturing = true; });
  // stopCapture called once from execute(), and once from ~CaptureController
  // when the controller is destroyed while still capturing after undo().
  EXPECT_CALL(*raw, stopCapture()).Times(2).WillRepeatedly([&] {
    capturing = false;
  });

  CaptureController controller(std::move(mockCapture));
  PacketFilter filter;
  filter.networkCard = "lo";

  // Start a capture so there's something to stop.
  controller.startCapture(filter);
  EXPECT_TRUE(controller.isCapturing());

  StopCaptureCommand cmd(controller, filter);
  cmd.execute();
  EXPECT_FALSE(controller.isCapturing());

  // Undo should restart with the same filter.
  cmd.undo();
  EXPECT_TRUE(controller.isCapturing());
  // Destructor of CaptureController will call stopCapture() again.
}

TEST(CaptureCommands, StopCommand_execute_callsStopCapture) {
  auto mockCapture = std::make_unique<MockPacketCapture>();
  auto *raw = mockCapture.get();

  // Start first, then stop via the command.
  bool capturing = false;
  ON_CALL(*raw, isCapturing()).WillByDefault([&] { return capturing; });

  EXPECT_CALL(*raw, initialize(_, _))
      .WillOnce(testing::Return(std::expected<void, std::string>{}));
  EXPECT_CALL(*raw, startCapture(_)).WillOnce([&](const std::string &) {
    capturing = true;
  });
  EXPECT_CALL(*raw, stopCapture()).WillOnce([&] { capturing = false; });

  CaptureController controller(std::move(mockCapture));
  PacketFilter filter;
  filter.networkCard = "lo";

  // Start a capture first so there's something to stop.
  controller.startCapture(filter);
  EXPECT_TRUE(controller.isCapturing());

  StopCaptureCommand cmd(controller);
  cmd.execute();
  EXPECT_FALSE(controller.isCapturing());
}
