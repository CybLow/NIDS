#pragma once

/// Pluggable output sink for detection results.
///
/// The NIDS server classifies network flows and routes every result through
/// registered output sinks.  Each sink decides what to do with the result:
///
///   - Log it (console, file, syslog)
///   - Forward clean traffic (no malicious flows → downstream gateway)
///   - Stream it to a remote client (gRPC, WebSocket)
///   - Aggregate statistics
///
/// Sinks receive EVERY flow (attack + benign).  Each sink filters locally.
/// This enables the "clean traffic mirror" use case: a sink that only emits
/// flows with `!result.isFlagged()`.

#include "core/model/DetectionResult.h"
#include "core/model/FlowInfo.h"

#include <cstddef>
#include <string_view>

namespace nids::core {

/// Abstract output sink for flow-level detection results.
///
/// Implementations must be safe to call from the FlowAnalysisWorker thread.
/// The `onFlowResult()` method is called synchronously on the worker thread
/// for every completed flow — keep it fast or enqueue internally.
class IOutputSink {
public:
  virtual ~IOutputSink() = default;

  /// Human-readable name of this sink (for logging and diagnostics).
  [[nodiscard]] virtual std::string_view name() const noexcept = 0;

  /// Called once when the capture session starts.
  /// Sinks can open files, connect to remote endpoints, etc.
  /// @return true if initialization succeeded.
  [[nodiscard]] virtual bool start() { return true; }

  /// Called for every completed flow after detection.
  ///
  /// @param flowIndex  Sequential flow number within this session.
  /// @param result     Full detection result (ML + TI + rules + verdict).
  /// @param flow       Flow metadata (5-tuple, packet counts, duration).
  virtual void onFlowResult(std::size_t flowIndex,
                            const DetectionResult &result,
                            const FlowInfo &flow) = 0;

  /// Called when the capture session ends.
  /// Sinks should flush buffers, close connections, print summaries.
  virtual void
  stop() { /* Default no-op: override to flush buffers or print summaries. */ }
};

} // namespace nids::core
