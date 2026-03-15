# NIDS Roadmap

> Last updated: 2026-03-15

This document consolidates **all** planned work — features, cleanup, tests, docs, and
operational tasks — into a single prioritized roadmap. Items are organized into phases
for incremental delivery. Each phase should leave the system in a working state.

Cross-references: [ADR-004](adr/004-model-benchmark-analysis.md),
[ADR-005](adr/005-hybrid-detection-system.md), [architecture.md](architecture.md),
[AGENTS.md](../AGENTS.md)

---

## Completed Work

- [x] 9 phases of C++23/Qt6 modernization
- [x] PcapPlusPlus migration (replaced raw libpcap with PcapPlusPlus 25.05)
- [x] ONNX Runtime ML inference (replaces frugally-deep)
- [x] CNN-BiLSTM model trained on LSNM2024 (87.78% accuracy, 97.78% attack recall)
- [x] Native C++ flow feature extraction (77 bidirectional flow features)
- [x] Hybrid detection system (ML + Threat Intelligence + Heuristic Rules)
- [x] `FeatureNormalizer` (z-score normalization with clip values)
- [x] Threat feed update script (`scripts/ops/update_threat_feeds.sh`)
- [x] ADR-004 (model benchmark analysis) and ADR-005 (hybrid detection design)
- [x] Rewritten `docs/architecture.md` with detection philosophy and hybrid data flow
- [x] GitHub Actions CI/CD
- [x] CPack packaging (DEB/RPM/TGZ)
- [x] Phase 7 — UI for hybrid detection results (tabbed Packets/Flows view,
  `FlowTableModel`, `DetectionDetailWidget`, worker thread, TI status panel,
  weight tuning dialog)
- [x] Phase 6 — Cleanup, config, and test foundation (ConfigLoader + `--config`,
  legacy `analysisResults_` removed, 130 hybrid detection unit tests,
  MIT LICENSE, server/client stubs cleaned up)
- [x] Phase 8 — Real-time flow extraction and analysis (Welford accumulators,
  timeout sweeps, streaming flow callbacks, producer-consumer pipeline,
  live packet API, LiveDetectionPipeline)
- [x] Phase 9.1 — gRPC server (`NidsServiceImpl` with 7 RPCs, `GrpcStreamSink`,
  proto codegen, Conan `with_grpc` option, `nids-server` dual-mode executable)
- [x] Phase 9.2 — CLI client (`NidsClient` gRPC wrapper, `nids-cli` with commands:
  status, interfaces, capture start/stop, stream with filter)
- [x] Docker sandbox for inline IPS testing (3-container topology: server, attacker,
  victim on isolated `172.28.0.0/24` bridge network)
- [x] Phase 9.4 — `--headless` flag on GUI binary (standalone capture + console
  output, no Qt dependency at runtime when headless)

---

## Phase 6: Cleanup, Config, and Test Foundation [DONE]

**Goal**: Remove backward-compatibility scaffolding, implement deferred functionality
that has zero new dependencies, and establish test coverage for all new hybrid
detection code.

### 6.1 — ~~Implement `Configuration::loadFromFile()` JSON parsing~~ [DONE]

- `ConfigLoader` in `infra/config/` parses JSON with `nlohmann_json`
- All config sections handled: model, capture, threat_intel, hybrid_detection, ui
- `main.cpp` has `parseConfigArg()` for `--config /path/to/config.json` CLI arg
- Unknown keys silently ignored (partial JSON keeps other defaults)

### 6.2 — ~~Remove legacy `analysisResults_` dual storage~~ [DONE]

- Legacy `analysisResults_` / `getAnalysisResult()` / `setAnalysisResult()` fully
  removed; all consumers migrated to `DetectionResult`-based API
- Renamed `analysisResultCount()` → `detectionResultCount()` for consistency
- Updated all 10 call sites (MainWindow, test_CaptureSession, test_FlowAnalysisWorker)

### 6.3 — ~~Remove `FeatureNormalizer` clip_value fallback~~ [DONE]

- `clip_value` is now required in metadata JSON (error logged if absent)
- No default-to-10.0 fallback in `FeatureNormalizer::loadMetadata()`

### 6.4 — ~~Clean up server/client stubs~~ [DONE]

- Stubs already updated: proper Phase 9 references, spdlog logging, no legacy
  model paths, behind `NIDS_BUILD_SERVER=OFF` option
- Will be rewritten when Phase 9 (gRPC) is implemented

### 6.5 — ~~Remove `PacketInfo.cpp` placeholder~~ [DONE]

- File already removed; no CMake references exist

### 6.6 — ~~Add unit tests for hybrid detection components~~ [DONE]

All 7 test files implemented with comprehensive coverage:

| Test file | Tests | Coverage |
|-----------|-------|----------|
| `test_ThreatIntelProvider.cpp` | 32 | Feed loading, CIDR matching, delimiters, edge cases |
| `test_HeuristicRuleEngine.cpp` | 27 | All 7 rules: trigger/below-threshold/edge values |
| `test_HybridDetectionService.cpp` | 17 | ML-only, TI escalation, ensemble, all detection sources |
| `test_FeatureNormalizer.cpp` | 20 | Load/normalize/clip/mismatch/reload |
| `test_DetectionResult.cpp` | 11 | Struct init, flags, maxSeverity, detectionSourceToString |
| `test_PredictionResult.cpp` | 6 | Struct init, isAttack, isHighConfidence |
| `test_Configuration.cpp` | 17 | Singleton, getters, ConfigLoader with valid/invalid/partial JSON |

### 6.7 — ~~Add LICENSE file~~ [DONE]

- MIT License in project root
- CPack `CPACK_RESOURCE_FILE_LICENSE` points to `${CMAKE_SOURCE_DIR}/LICENSE`

---

## Phase 7: UI for Hybrid Detection Results [DONE]

**Goal**: Surface the rich `DetectionResult` data in the Qt UI so users can see
detection source, confidence scores, TI matches, and heuristic rule matches.

### 7.1 — FlowTableModel + tabbed view [DONE]

- Tabbed layout: "Packets" tab (existing `PacketTableModel`) + "Flows" tab
- `FlowTableModel` with 10 columns (Flow #, Src/Dst IP/Port, Protocol, Verdict,
  ML Confidence, Combined Score, Detection Source)
- Severity color-coding (green/yellow/orange/red)
- Batch and incremental row insertion

### 7.2 — Detection detail panel [DONE]

- `DetectionDetailWidget` shown when a flow row is selected
- Displays: flow metadata, ML verdict + confidence, probability distribution (16 rows),
  TI matches (IP, feed name, direction), heuristic rule matches (name, description,
  severity), combined score breakdown

### 7.3 — Move analysis to a worker thread [DONE]

- `AnalysisService` (QObject) moved to a dedicated `QThread` in `MainWindow` constructor
- `runAnalysis()` dispatches via `QMetaObject::invokeMethod` with `Qt::QueuedConnection`
- Report prompt deferred to `populateFlowResults()` (after analysis finishes)
- Thread properly quit/waited in destructor

### 7.4 — Threat intelligence status panel [DONE]

- Status bar shows "TI: X feeds, Y entries [feed1, feed2, ...]  |  Rules: N"
- `IThreatIntelligence` extended with `feedNames()` virtual method
- `MainWindow` receives non-owning `IThreatIntelligence*` and `IRuleEngine*`

### 7.5 — Hybrid weight tuning UI [DONE]

- `WeightTuningDialog` with three linked sliders (ML/TI/Heuristic, sum-to-1.0 constraint)
- ML confidence threshold slider
- Proportional redistribution: adjusting one slider proportionally adjusts the others
- Apply saves to `HybridDetectionService` (runtime) and `Configuration` (persistent)
- Reset to defaults button
- Accessed via Settings > Detection Weights... menu

---

## Phase 8: Real-Time Flow Extraction and Analysis

**Goal**: Transform the batch post-capture analysis pipeline into a real-time
per-flow detection system. This is the highest-priority performance improvement
documented in ADR-004.

### 8.1 — ~~Replace `std::map` with `std::unordered_map` in `NativeFlowExtractor`~~ [DONE]

- **File**: `src/infra/flow/NativeFlowExtractor.h`
- Completed: `std::unordered_map` with `FlowKeyHash` functor, O(1) amortized lookup

### 8.2 — ~~Switch to Welford's online statistics~~ [DONE]

- **Files**: `NativeFlowExtractor.h`, `NativeFlowExtractor.cpp`, `test_NativeFlowExtractor.cpp`
- Completed: `WelfordAccumulator` struct with numerically stable online algorithm
- Replaced all 12 per-packet vectors with accumulator members (O(1) space per update)
- Per-flow memory reduced from ~7 KB to ~200 B
- Fixed backward IAT double-push bug in `updateDirectionStats()`
- Removed dead vector-based free functions (`mean`, `stddev`, `variance`)
- Added 5 `WelfordAccumulator` unit tests

### 8.3 — ~~Add periodic timeout sweeps~~ [DONE]

- **Files**: `NativeFlowExtractor.h`, `NativeFlowExtractor.cpp`, `test_NativeFlowExtractor.cpp`
- Completed: `sweepExpiredFlows(nowUs)` public method iterates active flows and
  expires any idle beyond `flowTimeoutUs_`
- Called every 30 seconds (by packet timestamp) during batch pcap processing
- Designed for future live mode: external timer can call `sweepExpiredFlows()`
- Constructor now reads `flowTimeoutUs_` and `idleThresholdUs_` from
  `Configuration::instance()` (was hardcoded)
- Removed `kDefaultFlowTimeoutUs` and `kIdleThresholdUs` local constants
- `updateActiveIdle()` now accepts idle threshold as parameter
- Added 4 sweep-specific unit tests (284 total)

### 8.4 — ~~Stream completed flows to ML analyzer~~ [DONE]

- **Files**: `IFlowExtractor.h`, `NativeFlowExtractor.h/.cpp`, `AnalysisService.cpp`,
  `test_NativeFlowExtractor.cpp`, `test_AnalysisService.cpp`, `test_Pipeline.cpp`
- Completed: `FlowCompletionCallback` in `IFlowExtractor` fires for each completed
  flow (FIN/RST, max-packets, timeout sweep, end-of-capture)
- `NativeFlowExtractor::completeFlow()` and `finalizeBulks()` invoke the callback
  with the 77-float feature vector and `FlowInfo` metadata
- `AnalysisService::analyzeCapture()` uses the streaming callback to normalize,
  predict, and store results as flows complete — no batch accumulation
- Backward-compatible batch fallback for extractors that don't invoke the callback
- Added 6 callback unit tests (290 total), updated 2 mock extractors
- All 290 unit + 31 Qt + 24 stress tests pass

### 8.5 — ~~Producer-consumer threading~~ [DONE]

- **Files**: `BoundedQueue.h`, `FlowAnalysisWorker.h/.cpp`, `AnalysisService.cpp`,
  `test_BoundedQueue.cpp`, `test_FlowAnalysisWorker.cpp`, `tests/CMakeLists.txt`,
  `src/app/CMakeLists.txt`
- Completed: `BoundedQueue<T>` thread-safe bounded FIFO (blocking push/pop,
  backpressure, close/end-of-stream semantics)
- Completed: `FlowAnalysisWorker` — `std::jthread`-based consumer that pops
  `FlowWorkItem` from a `BoundedQueue`, normalizes features, runs ML inference
  (with optional hybrid detection), stores results in `CaptureSession`, and
  invokes a `ResultCallback` for UI progress
- Completed: `AnalysisService::analyzeCapture()` wired to use the pipelined
  architecture — extraction and inference run concurrently on separate threads
  with bounded queue backpressure between them
- Batch fallback preserved for mock extractors and alternative implementations
- Added 14 `BoundedQueue` + 11 `FlowAnalysisWorker` unit tests (315 total)
- All 315 unit + 31 Qt + 24 stress tests pass

### 8.6 — ~~Live capture via PcapPlusPlus~~ [DONE]

- **Files**: `IFlowExtractor.h`, `NativeFlowExtractor.h/.cpp`,
  `test_NativeFlowExtractor.cpp`, `test_AnalysisService.cpp`, `test_Pipeline.cpp`
- Completed: Added 3 new pure virtual methods to `IFlowExtractor` interface:
  - `processPacket(data, length, timestampUs)` — feed raw packets during live capture
  - `finalizeAllFlows()` — flush remaining active flows at end-of-capture
  - `reset()` — clear all internal state for a new capture session
- Completed: `NativeFlowExtractor` implements all 3 methods:
  - `processPacket()` wraps raw bytes in `pcpp::RawPacket`, delegates to internal
    parser, includes periodic sweep (same 30s interval as batch mode)
  - `finalizeAllFlows()` calls `finalizeBulks()` to flush pending bulk counters
    and fire completion callbacks for all remaining active flows
  - `reset()` clears `flows_`, `completedFlows_`, `flowMetadata_`, `lastSweepTimeUs_`
  - `extractFeatures()` refactored to call `reset()` at start and
    `processPacketInternal()` internally (shared code path with live mode)
- Feature parity: live mode produces identical feature vectors to batch mode
  (verified by `ProcessPacket_featureVectorMatchesBatchMode` test)
- Updated 2 mock extractors (AnalysisService, Pipeline tests) with no-op overrides
- Added 14 live mode unit tests (329 total)
- All 329 unit + 31 Qt + 24 stress tests pass

### 8.7 — ~~Wire live detection into capture pipeline~~ [DONE]

- **Files**: `IPacketCapture.h`, `PcapCapture.h/.cpp`, `CaptureController.h/.cpp`,
  `LiveDetectionPipeline.h/.cpp`, `FlowAnalysisWorker.h/.cpp`,
  `AnalysisService.cpp`, `MainWindow.cpp`, `main.cpp`,
  `src/app/CMakeLists.txt`, `test_CaptureController.cpp`, `test_Pipeline.cpp`,
  `test_FlowAnalysisWorker.cpp`
- Completed: `RawPacketCallback` on `IPacketCapture` interface — fires on the
  capture thread with raw packet bytes + timestamp for live flow extraction
- Completed: `PcapCaptureWorker` fires the callback before parsing `PacketInfo`,
  thread-safe set/read via mutex
- Completed: `LiveDetectionPipeline` (new, `app/`) — pure C++23 orchestrator:
  - Manages `BoundedQueue<FlowWorkItem>` + `FlowAnalysisWorker` lifecycle
  - `feedPacket()` delegates to `IFlowExtractor::processPacket()`
  - Uses `tryPush()` (non-blocking) to avoid stalling PcapPlusPlus thread;
    drops flows under backpressure with logged warning
  - `start()` resets extractor, creates queue + worker
  - `stop()` finalizes remaining flows, drains queue, joins worker
- Completed: `CaptureController` gains `enableLiveDetection()` / `disableLiveDetection()`
  - On `startCapture()`: starts pipeline, registers raw packet callback
  - On `stopCapture()`: clears callback, finalizes + stops pipeline
  - `liveFlowDetected(DetectionResult, FlowInfo)` signal bridges worker
    thread → main thread via `QMetaObject::invokeMethod`
- Completed: `FlowAnalysisWorker::ResultCallback` extended to pass `FlowInfo`
- Completed: `main.cpp` creates separate `NativeFlowExtractor`, `FeatureNormalizer`,
  and `IPacketAnalyzer` instances for the live pipeline (no shared mutable state
  with `AnalysisService`)
- Completed: `MainWindow` connects `liveFlowDetected` → `FlowTableModel::addFlowResult()`
  for incremental row insertion during capture; skips post-capture analysis prompt
  when live detection was active
- Updated 2 mock `IPacketCapture` implementations + 1 `FlowAnalysisWorker` test
- Thread model: PcapPlusPlus thread → `feedPacket()` → flow extractor →
  `BoundedQueue` → `FlowAnalysisWorker` (std::jthread) → `ResultCallback` →
  `QMetaObject::invokeMethod` → main thread → `FlowTableModel`
- All 329 unit + 31 Qt + 24 stress tests pass

---

## Phase 9: gRPC Server and CLI Client

**Goal**: Enable headless operation for server deployments, systemd services, and
remote monitoring.

### 9.1 — ~~Implement gRPC server~~ [DONE]

- **Files**: `src/server/NidsServer.h/.cpp`, `src/server/server_main.cpp`
- **Proto**: `proto/nids.proto` (7 RPCs: ListInterfaces, StartCapture, StopCapture,
  GetStatus, StreamDetections, StreamPackets, AnalyzeCapture)
- **CMake**: `if(NIDS_BUILD_SERVER)` block with protobuf/gRPC code generation,
  `nids_proto` static library, `nids-server-lib`, `nids-server` executable
- **Conan**: `with_grpc` option (`conan install . -o with_grpc=True`) pulls
  `grpc/1.72.0`, `protobuf/5.27.0`, `abseil`, `c-ares`, `openssl`, `re2`, `zlib`
- `NidsServiceImpl`: full implementations for ListInterfaces, StartCapture,
  StopCapture, GetStatus, StreamDetections; stubs for StreamPackets, AnalyzeCapture
- `GrpcStreamSink`: implements `IOutputSink` to bridge flow detections into
  gRPC server-streaming responses
- `NidsServer`: wrapper managing `grpc::Server` lifecycle (start/stop/blocking wait)
- Dual-mode `server_main.cpp`: `--no-grpc` for standalone capture + console output,
  default for gRPC server mode with full pipeline integration
- Generated proto headers marked as `SYSTEM` include to avoid `-Werror` with GCC 15
- ASan `allow_user_poisoning=0` override for known gRPC epoll false positives

### 9.2 — ~~Implement CLI client~~ [DONE]

- **Files**: `src/client/NidsClient.h/.cpp`, `src/client/cli_main.cpp`
- `NidsClient`: typed C++ wrapper around gRPC stub with connect/disconnect,
  listInterfaces, startCapture, stopCapture, getStatus, streamDetections
- `ClientConfig`: server address (default `localhost:50051`), 5s connect timeout,
  30s per-RPC timeout
- `nids-cli` commands: `status`, `interfaces`, `capture start <iface> [--bpf]`,
  `capture stop [session-id]`, `stream [--filter flagged|clean|all]`, `help`
- Clean error handling: graceful 5s timeout on connection failure, proper exit codes
- Signal handling: Ctrl+C stops stream command gracefully

### 9.3 — ~~Docker sandbox for inline IPS testing~~ [DONE]

- **Files**: `docker/sandbox/Dockerfile.server`, `docker/sandbox/Dockerfile.attacker`,
  `docker/sandbox/Dockerfile.victim`, `docker/sandbox/compose.yml`,
  `docker/sandbox/scripts/victim-start.sh`, `docker/sandbox/scripts/generate-benign.sh`,
  `docker/sandbox/scripts/generate-attacks.sh`
- 3-container topology on isolated `172.28.0.0/24` bridge:
  - `nids-server` (172.28.0.10) — two-stage build, compiles from source with
    `NIDS_BUILD_SERVER=ON`
  - `attacker` (172.28.0.20) — Ubuntu 24.04 with hping3, nmap, scapy, curl, ab, iperf3
  - `victim` (172.28.0.30) — Python HTTP server, dropbear SSH, iperf3, netcat
- Attack scripts generate 8 attack types matching NIDS model classes
- Benign scripts generate HTTP, ping, iperf3, TCP connect patterns

### 9.4 — ~~`--headless` flag~~ [DONE]

- **Files**: `src/main.cpp`
- `--headless --interface <iface>` skips Qt initialization entirely, runs
  standalone capture with `LiveDetectionPipeline` + `ConsoleAlertSink`
- Also added `--bpf`, `--help`/`-h` flags to the GUI binary
- Requires `--interface` in headless mode (validated with error message)
- Graceful shutdown via SIGINT/SIGTERM
- Note: for gRPC server mode, use the separate `nids-server` binary instead

### 9.5 — `--config` flag [DONE]

- **Files**: `src/main.cpp`, `src/server/server_main.cpp`
- Parse `--config /path/to/config.json` from `argv`, pass to
  `Configuration::loadFromFile()` via `ConfigLoader`
- Both GUI (`main.cpp`) and server (`server_main.cpp`) support this flag

---

## Phase 10: Model and Detection Improvements

**Goal**: Improve ML accuracy and detection coverage based on ADR-004 analysis.

### 10.1 — Merge confusable attack classes

- DDoS-ICMP + ICMP-Flood → single "ICMP Flood/DDoS" class
- Evaluate merging DoS + RCE if operational distinction is not needed
- Retrain model, update `AttackType.h`, `attackTypeToString()`
- See ADR-004 and `docs/architecture.md:94`

### 10.2 — Benchmark against XGBoost / Random Forest

- Train baseline models on the same 77 flow features
- Compare accuracy, inference time, model size
- Document results in ADR-004

### 10.3 — Temperature scaling for confidence calibration

- Post-hoc calibration of ML confidence scores
- Train calibration parameter on validation set
- Apply in `OnnxAnalyzer::predictWithConfidence()` or as a separate step

### 10.4 — Asynchronous blocklist loading

- Currently `ThreatIntelProvider::loadDirectory()` runs synchronously at startup
- Move to async loading with a ready signal
- Required for real-time mode where startup latency matters

### 10.5 — Additional threat feeds

- Evaluate: AlienVault OTX, AbuseIPDB, FireHOL Level 1/2/3
- Add feed-specific parsers to `ThreatIntelProvider`

### 10.6 — JA3/JA4 TLS fingerprinting (research)

- Evaluate feasibility for encrypted traffic metadata analysis
- Would require TLS handshake parsing in `NativeFlowExtractor`
- See ADR-005

---

## Phase 11: Documentation and Quality

### 11.1 — Doxygen setup

- Create `Doxyfile` in `docs/`
- Ensure all public APIs in `core/` and `app/` have `/** ... */` documentation
- Generate HTML docs, optionally host via GitHub Pages

### 11.2 — Update README.md

- Add ADR-004 and ADR-005 to the Architecture Decision Records section
- Add hybrid detection to the roadmap checklist
- Update feature list

### 11.3 — Enforce test coverage threshold

- Add coverage gate in CI (fail build if `core/` + `app/` < 80%)
- Track with SonarCloud quality gate

---

## Future / Long-Term (No Current Timeline)

These items are documented for completeness but are not planned for near-term work.

| Item | Source | Notes |
|------|--------|-------|
| Web dashboard | README.md | Would replace or supplement Qt UI for remote monitoring |
| YARA rules integration | README.md | Signature-based detection, overlaps with Snort/Suricata |
| Deep Packet Inspection | README.md | Explicitly out-of-scope per architecture.md |
| NLFlowLyzer feature extraction | ADR-004 | Requires reimplementing NLFlowLyzer in C++ |
| Hyperparameter search (Optuna) | ADR-004 | Low priority given accuracy ceiling evidence |
| Additional ML backends (TensorRT, OpenVINO) | architecture.md | AnalyzerFactory designed for extensibility |
| Concept-drift detection / auto-retraining | ADR-004, ADR-005 | Requires monitoring infrastructure |
| NSIS Windows installer | AGENTS.md | CPack configuration for Windows |
| `IProtocolParser` strategy interface | AGENTS.md §5.1 | For pluggable protocol parsers |
| `FilterBuilder` builder pattern | AGENTS.md §5.5 | For complex filter construction |
| `IAnalysisRepository` repository pattern | AGENTS.md §5.6 | Abstract analysis result storage |
| Command pattern for capture operations | AGENTS.md §5.7 | Undo/queue/log capture operations |
| `std::expected<T, E>` error handling | AGENTS.md §6.1 | Replace bool returns with rich errors |
| ~~`ServiceRegistry` optimize to `unordered_map`~~ | ~~`ServiceRegistry.h:23`~~ | **Done** — already uses `std::unordered_map` |

---

## Priority Order

For implementation, the recommended order is:

1. **Phase 6** — Cleanup + tests + config (foundation for everything else)
2. **Phase 7** — UI for hybrid results (makes the existing work visible to users)
3. **Phase 8** — Real-time flow extraction (biggest architectural improvement)
4. **Phase 9** — gRPC server/client (enables headless deployment)
5. **Phase 10** — Model improvements (iterative, can be done in parallel with others)
6. **Phase 11** — Documentation polish (ongoing)
