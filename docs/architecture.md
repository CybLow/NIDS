# NIDS Architecture

## Overview

NIDS (Network Intrusion Detection System) is a desktop application that captures network
traffic, extracts flow-level features, and classifies each flow using a CNN-BiLSTM neural
network trained on the LSNM2024 dataset. It identifies 15 attack types plus benign traffic
in real time.

## Layered Architecture (Clean Architecture)

Dependencies flow **inward only**: UI -> App -> Core, and Infra -> Core.

```
┌──────────────────────────────────────────────────────────┐
│                      ui/ (Qt6)                           │
│   MainWindow, FilterPanel, PacketTableModel, HexView     │
├──────────────────────────────────────────────────────────┤
│                    app/ (Orchestration)                   │
│   CaptureController, AnalysisService, ReportGenerator    │
├──────────────────────────────────────────────────────────┤
│         core/ (Pure C++20, zero platform deps)           │
│   PacketInfo, AttackType, CaptureSession, PacketFilter   │
│   IPacketCapture, IPacketAnalyzer, IFlowExtractor        │
│   Configuration (singleton)                              │
├──────────────────────────────────────────────────────────┤
│          infra/ (Platform-specific implementations)      │
│   PcapCapture, OnnxAnalyzer, NativeFlowExtractor         │
│   AnalyzerFactory, PcapHandle, NetworkHeaders            │
└──────────────────────────────────────────────────────────┘
```

| Layer    | May depend on                       | Must NOT depend on          |
|----------|-------------------------------------|-----------------------------|
| `core/`  | C++ Standard Library only           | Qt, pcap, OS headers, infra, app, ui |
| `infra/` | `core/`, OS/platform APIs, third-party C libs | `app/`, `ui/`  |
| `app/`   | `core/`, `infra/` (via interfaces)  | `ui/`, Qt widgets           |
| `ui/`    | `core/`, `app/`, Qt                 | direct pcap calls, OS headers |

## Data Flow

```
Network Interface
      │
      ▼
┌─────────────┐     PacketCallback      ┌───────────────────┐
│ PcapCapture  │ ─────────────────────▶  │ CaptureController │
│ (infra)      │                         │ (app)             │
└─────────────┘                          └────────┬──────────┘
                                                  │ stores packets
                                                  ▼
                                          ┌──────────────┐
                                          │CaptureSession│
                                          │  (core)      │
                                          └──────┬───────┘
                                                 │
                      ┌──────────────────────────┤
                      ▼                          ▼
              ┌───────────────────┐    ┌────────────────┐
              │NativeFlowExtractor│    │ AnalysisService│
              │  (infra)          │───▶│  (app)         │
              └───────────────────┘    └───────┬────────┘
                  extracts flows               │ per-flow
                  to CSV                       │ prediction
                                               ▼
                                       ┌──────────────┐
                                       │ OnnxAnalyzer  │
                                       │  (infra)      │
                                       └──────┬───────┘
                                              │ AttackType
                                              ▼
                                       ┌──────────────┐
                                       │  MainWindow   │
                                       │  (ui)         │
                                       └──────────────┘
```

## Key Design Patterns

### Strategy Pattern
Protocol parsers and ML backends implement common interfaces (`IPacketAnalyzer`,
`IFlowExtractor`). New backends can be added without modifying consuming code.

### Observer Pattern (Qt Signals/Slots)
Cross-component communication uses Qt signals:
- `CaptureController::packetReceived` -> `MainWindow` updates table
- `AnalysisService::analysisProgress` -> `MainWindow` updates progress bar
- `CaptureController::captureError` -> `MainWindow` shows error dialog

### Factory Method
`AnalyzerFactory::createAnalyzer(AnalyzerBackend)` creates the appropriate ML backend.
Currently only ONNX Runtime; additional backends (TensorRT, OpenVINO) can be added to
the enum and factory switch without modifying calling code.

### RAII Wrappers
Every C resource is wrapped in `std::unique_ptr` with a custom deleter:
- `PcapHandle` wraps `pcap_t*` with `pcap_close`
- `PcapDumper` wraps `pcap_dumper_t*` with `pcap_dump_close`
- ONNX Runtime session managed by `Impl` struct in `OnnxAnalyzer`

### Meyers Singleton
`Configuration` provides centralized config via thread-safe static initialization.
Eliminates scattered magic strings and numbers.

### Repository Pattern
`CaptureSession` stores packets and analysis results with thread-safe access via
`std::mutex` + `std::scoped_lock`.

## Threading Model

- **Packet capture**: QThread + worker object pattern (per AGENTS.md).
  `PcapCapture` runs the capture loop on a separate QThread. Packets are delivered
  to the main thread via `Qt::QueuedConnection` signals.
- **Analysis**: Currently synchronous on the calling thread. Future work may move
  this to a dedicated worker thread.
- **Shared state**: `CaptureSession` protects all access with `std::mutex`.
- **Atomics**: Simple flags and counters use `std::atomic<>`.

## ML Pipeline

1. **Feature Extraction**: `NativeFlowExtractor` reads a pcap file and computes
   77 CIC-compatible flow features (duration, packet counts, byte statistics, flags,
   inter-arrival times, etc.)
2. **Normalization**: Handled by the preprocessing script during training. At inference
   time, the model receives raw feature values.
3. **Inference**: `OnnxAnalyzer` creates an ONNX Runtime session, feeds a `(1, N)` tensor,
   and receives softmax probabilities over 16 classes.
4. **Classification**: `attackTypeFromIndex(argmax)` maps the highest-probability index
   to an `AttackType` enum value.

## Configuration

The `Configuration` singleton centralizes all runtime parameters:
- Model path and metadata path
- ONNX Runtime thread count
- Flow timeout and idle threshold
- Default dump file name
- Window title

Optional JSON config file can override defaults via `loadFromFile()`.

## Error Handling

- **Return types**: `[[nodiscard]] bool` for fallible operations. `std::optional<T>`
  for absent values.
- **Logging**: spdlog at all layers. Levels: trace, debug, info, warn, error, critical.
- **Signal propagation**: Errors in `PcapCapture` are forwarded via `ErrorCallback` ->
  `CaptureController::captureError` signal -> `MainWindow` error dialog.
- **Analysis errors**: `AnalysisService` emits both `analysisError` and `analysisFinished`
  to prevent stuck UI spinners.
