#include "app/commands/CaptureCommands.h"
#include "app/CaptureController.h"

#include <spdlog/spdlog.h>

namespace nids::app {

void StartCaptureCommand::execute() {
    spdlog::debug("Command: {}", name());
    controller_.startCapture(filter_, dumpFile_);
}

void StartCaptureCommand::undo() {
    spdlog::debug("Undo: {}", name());
    controller_.stopCapture();
}

void StopCaptureCommand::execute() {
    spdlog::debug("Command: {}", name());
    controller_.stopCapture();
}

void StopCaptureCommand::undo() {
    spdlog::debug("Undo: {}", name());
    controller_.startCapture(filter_, dumpFile_);
}

} // namespace nids::app
