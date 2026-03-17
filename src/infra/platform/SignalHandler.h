#pragma once

/// Shared POSIX signal handler for all NIDS entry points.
///
/// Provides a thread-safe atomic shutdown flag and a signal handler that
/// sets it on SIGINT / SIGTERM.  Include once per translation unit, then
/// call installSignalHandlers() early in main().

#include <atomic>
#include <csignal>

namespace nids::infra::platform {

/// Global shutdown flag.  Checked in the main loop of each entry point.
inline std::atomic<bool> gShutdownRequested{false};

/// Signal handler suitable for std::signal().  Sets gShutdownRequested.
inline void signalHandler(int /*signum*/) { gShutdownRequested.store(true); }

/// Install signalHandler for SIGINT and SIGTERM.
inline void installSignalHandlers() {
  std::signal(SIGINT, signalHandler);
  std::signal(SIGTERM, signalHandler);
}

} // namespace nids::infra::platform
