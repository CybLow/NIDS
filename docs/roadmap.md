# NIDS Roadmap

> Last updated: 2026-03-10

This document consolidates **all** planned work — features, cleanup, tests, docs, and
operational tasks — into a single prioritized roadmap. Items are organized into phases
for incremental delivery. Each phase should leave the system in a working state.

Cross-references: [ADR-004](adr/004-model-benchmark-analysis.md),
[ADR-005](adr/005-hybrid-detection-system.md), [architecture.md](architecture.md),
[AGENTS.md](../AGENTS.md)

---

## Completed Work

- [x] 9 phases of C++20/Qt6 modernization
- [x] ONNX Runtime ML inference (replaces frugally-deep)
- [x] CNN-BiLSTM model trained on LSNM2024 (87.78% accuracy, 97.78% attack recall)
- [x] Native C++ flow feature extraction (77 bidirectional flow features)
- [x] Hybrid detection system (ML + Threat Intelligence + Heuristic Rules)
- [x] `FeatureNormalizer` (z-score normalization with clip values)
- [x] Threat feed update script (`scripts/update_threat_feeds.sh`)
- [x] ADR-004 (model benchmark analysis) and ADR-005 (hybrid detection design)
- [x] Rewritten `docs/architecture.md` with detection philosophy and hybrid data flow
- [x] GitHub Actions CI/CD
- [x] CPack packaging (DEB/RPM/TGZ)

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

## Phase 7: UI for Hybrid Detection Results

**Goal**: Surface the rich `DetectionResult` data in the Qt UI so users can see
detection source, confidence scores, TI matches, and heuristic rule matches.

### 7.1 — Extend `PacketTableModel` to show `DetectionResult`

- Add columns: Detection Source, Combined Score, ML Confidence
- Color-code rows by combined score severity (green/yellow/orange/red)
- Migrate model from reading `analysisResults_` to `detectionResults_`

### 7.2 — Detection detail panel

- New `DetectionDetailWidget` (or panel in `MainWindow`) shown when a row is selected
- Displays: ML verdict + confidence, TI matches (feed name, category), heuristic rule
  matches (rule name, severity, description), combined score breakdown
- This is read-only; no editing

### 7.3 — Move analysis to a worker thread

- **File**: `docs/architecture.md:304-305` documents this as needed
- **Why**: Analysis currently runs synchronously, freezing the UI
- **Pattern**: QThread + worker object (per AGENTS.md Section 4.1)
- Use `Qt::QueuedConnection` signals to update `CaptureSession` and UI from the worker

### 7.4 — Threat intelligence status panel

- Show loaded feed names, last update time, total IP count, CIDR range count
- Button to trigger `scripts/update_threat_feeds.sh` via `QProcess`

### 7.5 — Hybrid weight tuning UI

- Sliders or spin boxes for ML/TI/Heuristic weights (constrained to sum to 1.0)
- ML confidence threshold slider
- Save to config JSON (requires Phase 6.1)

---

## Phase 8: Real-Time Flow Extraction and Analysis

**Goal**: Transform the batch post-capture analysis pipeline into a real-time
per-flow detection system. This is the highest-priority performance improvement
documented in ADR-004.

### 8.1 — ~~Replace `std::map` with `std::unordered_map` in `NativeFlowExtractor`~~ [DONE]

- **File**: `src/infra/flow/NativeFlowExtractor.h`
- Completed: `std::unordered_map` with `FlowKeyHash` functor, O(1) amortized lookup

### 8.2 — Switch to Welford's online statistics

- **Files**: `NativeFlowExtractor.h:57-88` (FlowStats vectors)
- **Why**: Per-flow memory drops from ~7 KB (storing all per-packet vectors) to ~200 B
  (running mean, variance, min, max, count)
- Remove `fwdPacketLengths`, `bwdPacketLengths`, `allPacketLengths`, `flowIatUs`,
  `fwdIatUs`, `bwdIatUs`, `activePeriodsUs`, `idlePeriodsUs` vectors
- Replace with `WelfordAccumulator` structs that track N, mean, M2 (for variance),
  min, max

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

### 8.6 — Live pcap via `pcap_open_live()`

- Currently `NativeFlowExtractor::extractFeatures()` reads from a saved `.pcap` file
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

- Create `Doxyfile` at project root
- Ensure all public APIs in `core/` and `app/` have `/** ... */` documentation
- Generate HTML docs, optionally host via GitHub Pages

### 11.2 — Update README.md

- Add ADR-004 and ADR-005 to the Architecture Decision Records section
- Add hybrid detection to the roadmap checklist
- Update feature list

### 11.3 — Enforce test coverage threshold

- Add coverage gate in CI (fail build if `core/` + `app/` < 80%)
- Track with Codecov or similar

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
