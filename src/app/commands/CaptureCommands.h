#pragma once

/// Concrete command implementations for capture lifecycle operations.
///
/// StartCaptureCommand and StopCaptureCommand wrap CaptureController methods
/// following the Command pattern (AGENTS.md 5.7).  They can be logged, queued,
/// and undone (start/stop are mutual inverses).

#include "core/services/ICommand.h"
#include "core/model/PacketFilter.h"

#include <string>
#include <string_view>

namespace nids::app {

class CaptureController;

/// Command that starts a capture session.
/// Undo stops the capture.
class StartCaptureCommand : public nids::core::ICommand {
public:
    /**
     * Construct the command.
     * @param controller  Non-owning reference to the controller.
     * @param filter      Capture filter to apply.
     * @param dumpFile    Optional pcap dump file path.
     */
    StartCaptureCommand(CaptureController& controller,
                        nids::core::PacketFilter filter,
                        std::string dumpFile = "")
        : controller_(controller),
          filter_(std::move(filter)),
          dumpFile_(std::move(dumpFile)) {}

    void execute() override;
    void undo() override;

    [[nodiscard]] std::string_view name() const noexcept override {
        return "StartCapture";
    }

private:
    CaptureController& controller_;
    nids::core::PacketFilter filter_;
    std::string dumpFile_;
};

/// Command that stops the current capture session.
/// Undo restarts capture with the previously used filter.
class StopCaptureCommand : public nids::core::ICommand {
public:
    /**
     * Construct the command.
     * @param controller  Non-owning reference to the controller.
     * @param filter      The filter that was used for the running capture
     *                    (needed for undo to restart with the same config).
     * @param dumpFile    The dump file that was used (needed for undo).
     */
    StopCaptureCommand(CaptureController& controller,
                       nids::core::PacketFilter filter = {},
                       std::string dumpFile = "")
        : controller_(controller),
          filter_(std::move(filter)),
          dumpFile_(std::move(dumpFile)) {}

    void execute() override;
    void undo() override;

    [[nodiscard]] std::string_view name() const noexcept override {
        return "StopCapture";
    }

private:
    CaptureController& controller_;
    nids::core::PacketFilter filter_;
    std::string dumpFile_;
};

} // namespace nids::app
