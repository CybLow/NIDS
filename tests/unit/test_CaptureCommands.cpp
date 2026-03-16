#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "app/commands/CaptureCommands.h"
#include "app/CaptureController.h"
#include "core/model/PacketFilter.h"
#include "core/services/IPacketCapture.h"

#include <expected>
#include <string>
#include <vector>

using namespace nids::core;
using namespace nids::app;
using ::testing::_;

// ── Mock capture backend ─────────────────────────────────────────────

class MockCaptureCmds : public IPacketCapture {
public:
    MOCK_METHOD((std::expected<void, std::string>), initialize,
                (const std::string&, const std::string&), (override));
    MOCK_METHOD(void, startCapture, (const std::string&), (override));
    MOCK_METHOD(void, stopCapture, (), (override));
    MOCK_METHOD(bool, isCapturing, (), (const, override));
    MOCK_METHOD(void, setPacketCallback, (PacketCallback), (override));
    MOCK_METHOD(void, setErrorCallback, (ErrorCallback), (override));
    MOCK_METHOD(void, setRawPacketCallback, (RawPacketCallback), (override));
    MOCK_METHOD(std::vector<std::string>, listInterfaces, (), (override));
};

// ── Tests ────────────────────────────────────────────────────────────

TEST(CaptureCommands, StartCaptureCommand_name) {
    auto mockCapture = std::make_unique<MockCaptureCmds>();
    CaptureController controller(std::move(mockCapture));
    PacketFilter filter;
    StartCaptureCommand cmd(controller, filter);

    EXPECT_EQ(cmd.name(), "StartCapture");
}

TEST(CaptureCommands, StopCaptureCommand_name) {
    auto mockCapture = std::make_unique<MockCaptureCmds>();
    CaptureController controller(std::move(mockCapture));
    StopCaptureCommand cmd(controller);

    EXPECT_EQ(cmd.name(), "StopCapture");
}

TEST(CaptureCommands, StartCaptureCommand_implementsICommand) {
    auto mockCapture = std::make_unique<MockCaptureCmds>();
    CaptureController controller(std::move(mockCapture));
    PacketFilter filter;
    StartCaptureCommand cmd(controller, filter);

    // Verify it satisfies the ICommand interface.
    ICommand* iface = &cmd;
    EXPECT_EQ(iface->name(), "StartCapture");
}

TEST(CaptureCommands, StopCaptureCommand_implementsICommand) {
    auto mockCapture = std::make_unique<MockCaptureCmds>();
    CaptureController controller(std::move(mockCapture));
    StopCaptureCommand cmd(controller);

    ICommand* iface = &cmd;
    EXPECT_EQ(iface->name(), "StopCapture");
}

TEST(CaptureCommands, StartCommand_execute_callsStartCapture) {
    auto mockCapture = std::make_unique<MockCaptureCmds>();
    auto* raw = mockCapture.get();

    // startCapture path: initialize → startCapture(dumpFile).
    EXPECT_CALL(*raw, initialize(_, _)).WillOnce(
        testing::Return(std::expected<void, std::string>{}));
    EXPECT_CALL(*raw, startCapture(_)).Times(1);

    CaptureController controller(std::move(mockCapture));
    PacketFilter filter;
    filter.networkCard = "lo";
    StartCaptureCommand cmd(controller, filter);

    cmd.execute();
}

TEST(CaptureCommands, StartCommand_undo_callsStopCapture) {
    auto mockCapture = std::make_unique<MockCaptureCmds>();
    auto* raw = mockCapture.get();

    // isCapturing returns false initially, true after start, false after stop.
    bool capturing = false;
    ON_CALL(*raw, isCapturing()).WillByDefault([&] { return capturing; });

    EXPECT_CALL(*raw, initialize(_, _)).WillOnce(
        testing::Return(std::expected<void, std::string>{}));
    EXPECT_CALL(*raw, startCapture(_)).WillOnce([&](const std::string&) {
        capturing = true;
    });
    EXPECT_CALL(*raw, stopCapture()).WillOnce([&] {
        capturing = false;
    });

    CaptureController controller(std::move(mockCapture));
    PacketFilter filter;
    filter.networkCard = "lo";
    StartCaptureCommand cmd(controller, filter);

    cmd.execute();
    EXPECT_TRUE(controller.isCapturing());
    cmd.undo(); // Should call stopCapture()
    EXPECT_FALSE(controller.isCapturing());
}

TEST(CaptureCommands, StopCommand_execute_callsStopCapture) {
    auto mockCapture = std::make_unique<MockCaptureCmds>();
    auto* raw = mockCapture.get();

    // Start first, then stop via the command.
    bool capturing = false;
    ON_CALL(*raw, isCapturing()).WillByDefault([&] { return capturing; });

    EXPECT_CALL(*raw, initialize(_, _)).WillOnce(
        testing::Return(std::expected<void, std::string>{}));
    EXPECT_CALL(*raw, startCapture(_)).WillOnce([&](const std::string&) {
        capturing = true;
    });
    EXPECT_CALL(*raw, stopCapture()).WillOnce([&] {
        capturing = false;
    });

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
