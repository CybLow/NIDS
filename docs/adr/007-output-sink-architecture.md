# ADR-007: Pluggable Output Sink Architecture

## Status

Accepted

## Context

The NIDS was originally GUI-centric: detection results were displayed in Qt
table views and exported as HTML reports via `ReportGenerator`. As the project
pivots to a **server-first architecture** (headless daemon for ML-based
intrusion detection, complementary to Snort/Suricata/Zeek), several problems
emerged:

1. **No structured output**: The server had only a hardcoded lambda that logged
   flagged flows to the console via spdlog.

2. **No "clean traffic" output**: Benign flows were silently discarded. There
   was no mechanism to emit flows that passed ML classification as clean, which
   is essential for traffic filtering use cases (e.g., forwarding only clean
   traffic to a downstream gateway).

3. **`ReportGenerator` was dead weight**: It generated HTML reports from
   `CaptureSession` data -- a GUI concept meaningless for a headless daemon.

4. **No extensibility**: Adding new output formats (JSON, CEF, syslog, gRPC
   stream) required modifying the pipeline itself.

5. **Proto was outdated**: `nids.proto` still had `GenerateReport` RPC and
   lacked `StreamDetections` or any `DetectionResult`/`FlowInfo` messages.

## Decision

### Remove ReportGenerator

`ReportGenerator` and all references are deleted. The concept of "generating
a report" is replaced by output sinks that stream results in real time.

### Introduce `IOutputSink` Interface

A new abstract interface `core::IOutputSink` defines the pluggable output
contract:

```cpp
class IOutputSink {
public:
    virtual ~IOutputSink() = default;
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
    [[nodiscard]] virtual bool start() { return true; }
    virtual void onFlowResult(std::size_t flowIndex,
                              const DetectionResult& result,
                              const FlowInfo& flow) = 0;
    virtual void stop() {}
};
```

Key design choices:

- **Every flow** (attack + benign) is delivered to every sink. Each sink
  filters locally based on its purpose.
- **Non-owning**: `LiveDetectionPipeline` stores raw pointers to sinks. The
  caller owns sink lifetimes and must keep them alive until `stop()` returns.
- **Worker thread execution**: `onFlowResult()` runs on the
  `FlowAnalysisWorker` thread. Sinks must be fast or enqueue internally.
- **Lifecycle**: `start()` before capture, `stop()` after all flows drain.

### Wire Sinks into LiveDetectionPipeline

`LiveDetectionPipeline::addOutputSink(IOutputSink*)` registers sinks before
`start()`. On `start()`, all sinks are initialized. Each flow result is
dispatched to all sinks, then to the optional user `ResultCallback`. On
`stop()`, all sinks are stopped (flush buffers, print summaries).

### First Concrete Sink: ConsoleAlertSink

`infra::ConsoleAlertSink` replaces the hardcoded lambda in `server_main.cpp`.
Supports three filter modes: `All`, `Flagged`, `Clean`. Tracks flow counts
and prints a summary on stop.

### Update Proto for Detection Streaming

The proto is updated to reflect the server's actual role:

- **Removed**: `GenerateReport` RPC and messages.
- **Added**: `StreamDetections` server-streaming RPC with `DetectionFilter`
  (ALL, FLAGGED, CLEAN).
- **Added**: `DetectionEvent` message with full ML + TI + rule results.
- **Added**: `FlowMetadata`, `ThreatIntelMatch`, `RuleMatch` messages.
- **Updated**: `StopCaptureResponse` with flow counts.

### Add Batched Inference API

`IPacketAnalyzer::predictBatch(span<const float>, featureCount)` enables
N-flow inference in a single ONNX Runtime `session.Run()` call. The default
implementation falls back to per-flow `predictWithConfidence()`.
`OnnxAnalyzer` provides native batched inference.

### Fix completedFlows_ Memory Leak

`NativeFlowExtractor` no longer accumulates completed flows in live mode
(`processPacket` path). A `liveMode_` flag distinguishes live from batch
mode. In batch mode (`extractFeatures`), completed flows are still stored
for return value construction.

## Consequences

### Positive

- The server has a clean, extensible output architecture.
- Clean traffic forwarding is now possible by implementing an `IOutputSink`
  that only emits benign flows.
- Future sinks (JSON file, syslog, gRPC stream, CEF) require zero changes
  to the pipeline -- just implement `IOutputSink` and register.
- Batched inference opens the door to 5-20x throughput improvement.
- Memory leak fixed for long-running daemon deployments.

### Negative

- Output sinks execute on the worker thread. A slow sink blocks ML inference
  for subsequent flows. Sinks that perform I/O should enqueue internally.
- The `ResultCallback` on `LiveDetectionPipeline` is now redundant with
  output sinks. It is kept for backward compatibility (UI wiring) but could
  be consolidated in the future.

### Future Work

- **Batched FlowAnalysisWorker**: Modify the worker to drain N items from
  the queue, batch-normalize, call `predictBatch()`, then distribute results.
  This requires changes to `FlowAnalysisWorker` (currently processes one
  item at a time).
- **JSON output sink**: `JsonFileSink` for structured log files.
- **Syslog sink**: CEF/LEEF format for SIEM integration.
- **gRPC streaming sink**: Implements `StreamDetections` RPC.
- **Clean traffic forwarder**: Sink that mirrors benign flows to a
  downstream interface or NFQueue verdict.
