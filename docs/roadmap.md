# NIDS Roadmap

> Last updated: 2026-03-14

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

---

## Phase 6: Cleanup, Config, and Test Foundation

**Goal**: Remove backward-compatibility scaffolding, implement deferred functionality
that has zero new dependencies, and establish test coverage for all new hybrid
detection code.

### 6.1 — Implement `Configuration::loadFromFile()` JSON parsing

- **File**: `src/core/services/Configuration.cpp:65`
- **Why**: `nlohmann_json` is already linked. The function is a no-op with a TODO.
  Every runtime setting (model path, TI directory, hybrid weights, ONNX thread count)
  can be loaded from a JSON file.
- **Scope**: Parse the JSON, map keys to setters, log warnings for unknown keys.
- **Deliverable**: Users can pass `--config /path/to/config.json` (add CLI arg parsing
  with a simple `argv` loop in `main.cpp`).

### 6.2 — Remove legacy `analysisResults_` dual storage

- **Files**: `CaptureSession.h/.cpp`, `AnalysisService.cpp`, `PacketTableModel`,
  `ReportGenerator.cpp`, `MainWindow.cpp` (any code reading `analysisResults_`)
- **Why**: `CaptureSession` maintains a legacy `std::vector<AttackType>` alongside the
  new `std::vector<DetectionResult>`. This was kept for backward compatibility with UI
  and report code. Once all consumers read from `DetectionResult`, the legacy vector
  and `setAnalysisResult()`/`getAnalysisResult()` can be removed.
- **Steps**:
  1. Audit all call sites of `getAnalysisResult()` / `analysisResults_`.
  2. Migrate each to use `getDetectionResult()`, extracting `.finalVerdict`.
  3. Remove `analysisResults_`, `setAnalysisResult()`, `getAnalysisResult()`.

### 6.3 — Remove `FeatureNormalizer` clip_value fallback

- **File**: `src/infra/analysis/FeatureNormalizer.cpp:61-68`
- **Why**: Once all metadata JSON files include `clip_value`, the default-to-10.0
  fallback is dead code.
- **Action**: Remove the fallback, make `clip_value` required, log an error if absent.

### 6.4 — Clean up server/client stubs

- **Files**: `src/server/NidsServer.h/.cpp`, `src/client/NidsClient.h/.cpp`
- **Why**: These reference a legacy model path (`"../src/model/model.json"`),
  contain commented-out gRPC code, and are not included in any CMake target.
- **Decision**: Either (a) delete them entirely and recreate when gRPC is implemented,
  or (b) update them to match current architecture (Configuration singleton, ONNX
  model, hybrid detection). Option (a) is cleaner.

### 6.5 — Remove `PacketInfo.cpp` placeholder

- **File**: `src/core/model/PacketInfo.cpp`
- **Why**: Contains only a comment. If no `.cpp` is needed, remove it and any CMake
  reference.

### 6.6 — Add unit tests for hybrid detection components

| Test file | Class under test | Key scenarios |
|-----------|-----------------|---------------|
| `test_ThreatIntelProvider.cpp` | `ThreatIntelProvider` | Load plain-text IPs, CIDR matching, empty file, malformed lines, duplicate IPs, `isKnownThreat()` hit/miss |
| `test_HeuristicRuleEngine.cpp` | `HeuristicRuleEngine` | Each of 7 rules: trigger condition, below threshold, edge values |
| `test_HybridDetectionService.cpp` | `HybridDetectionService` | ML-only fallback, TI escalation, weight calculation, benign + high-confidence override, all three sources contributing |
| `test_FeatureNormalizer.cpp` | `FeatureNormalizer` | Load metadata JSON, normalize features, clip values, missing fields, dimension mismatch |
| `test_DetectionResult.cpp` | `DetectionResult` | Struct initialization, default values |
| `test_PredictionResult.cpp` | `PredictionResult` | Struct initialization, probability array |
| `test_Configuration.cpp` | `Configuration` | `loadFromFile()` with valid JSON, missing file, malformed JSON, all getters |

- **Framework**: GoogleTest + GoogleMock (per AGENTS.md Section 9)
- **Target**: 80% line coverage for `core/` and `app/` (AGENTS.md Section 9.2)

### 6.7 — Add LICENSE file

- **Files**: `LICENSE` (project root), `CMakeLists.txt:137` (uncomment CPack reference)
- **Why**: Missing LICENSE blocks CPack packaging and legal compliance. README links to
  a nonexistent file.

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

### 8.3 — Add periodic timeout sweeps

- **Why**: Currently flow expiry is only checked lazily when the next packet for the
  same 5-tuple arrives. Long-lived idle flows are never expired.
- Add a timer (e.g., every 30s) that sweeps flows and expires those past the idle
  timeout
- Emit completed flows for analysis

### 8.4 — Stream completed flows to ML analyzer

- **Why**: Currently all flows are accumulated in memory and analyzed sequentially
  (`AnalysisService.cpp`). The CSV round-trip has been eliminated — features are
  returned in-memory as `std::vector<std::vector<float>>`.
- Next step: when a flow completes (timeout or FIN/RST), immediately normalize features
  and run inference (true streaming, not batch-after-capture)

### 8.5 — Producer-consumer threading

- **Pattern**: Capture thread → Flow extractor thread → Analyzer thread
- Use a lock-free or mutex-protected queue between stages
- `std::jthread` for non-Qt threads (per AGENTS.md Section 4.1)
- Connect results back to UI via `Qt::QueuedConnection` signals

### 8.6 — Live capture via PcapPlusPlus

- Currently `NativeFlowExtractor::extractFeatures()` reads from a saved `.pcap` file
  via `pcpp::PcapFileReaderDevice`
- Add an overload or mode that accepts packets from the live `PcapCapture` callback
- This enables real-time detection during capture, not just post-capture

---

## Phase 9: gRPC Server and CLI Client

**Goal**: Enable headless operation for server deployments, systemd services, and
remote monitoring.

### 9.1 — Implement gRPC server

- **Files**: `src/server/NidsServer.h/.cpp` (rewrite or recreate after Phase 6.4)
- **Proto**: `proto/nids.proto` (already defines 7 RPCs)
- **CMake**: Add `if(NIDS_BUILD_SERVER)` block, protobuf/gRPC compilation targets
- RPCs: `StartCapture`, `StopCapture`, `GetStatus`, `GetPackets` (streaming),
  `GetAnalysisResults`, `RunAnalysis`, `GetReport`

### 9.2 — Implement CLI client

- **Files**: `src/client/NidsClient.h/.cpp` (rewrite or recreate)
- Commands: `nids-cli capture start/stop`, `nids-cli analyze`, `nids-cli report`,
  `nids-cli status`, `nids-cli feeds update`

### 9.3 — `--headless` flag

- **Files**: `src/main.cpp`
- When `--headless` is passed, skip Qt UI initialization, start gRPC server
- Required for systemd service (`docs/deployment.md:117-141`)

### 9.4 — `--config` flag

- **Files**: `src/main.cpp`
- Parse `--config /path/to/config.json` from `argv`, pass to
  `Configuration::loadFromFile()`
- Required by `docs/deployment.md:160`

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
