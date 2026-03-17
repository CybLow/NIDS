# NIDS - Network Intrusion Detection System

[![CI](https://github.com/CybLow/NIDS/actions/workflows/ci.yml/badge.svg)](https://github.com/CybLow/NIDS/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/CybLow/NIDS)](LICENSE)

A server-first, ML-powered Network Intrusion Detection System that performs real-time
flow-level statistical analysis using a CNN-BiLSTM model trained on the LSNM2024 dataset.
Designed to complement Snort/Suricata/Zeek with ML-based detection. Built with C++23,
ONNX Runtime, and optionally gRPC + Qt6.

## Features

### Detection Engine
- **CNN-BiLSTM Attack Detection**: Classifies 15 attack types + benign traffic using
  a hybrid convolutional/recurrent neural network (87.78% accuracy, 97.78% attack recall)
- **Hybrid Detection**: Combines ML inference with threat intelligence feeds and
  heuristic rule matching (configurable weights, ensemble scoring)
- **Real-Time Flow Analysis**: Producer-consumer pipeline with bounded queue
  backpressure -- flows are classified as they complete, not post-capture
- **77 Bidirectional Flow Features**: Native C++ flow extraction with Welford online
  statistics (O(1) memory per flow), timeout sweeps, time-window splitting

### Deployment Modes
- **gRPC Server Daemon** (`nids-server`): Headless deployment with 7 RPCs
  (ListInterfaces, StartCapture, StopCapture, GetStatus, StreamDetections,
  StreamPackets, AnalyzeCapture)
- **CLI Client** (`nids-cli`): Remote control and monitoring via gRPC
- **Headless Mode** (`NIDS --headless --interface eth0`): Standalone capture with
  console output, no Qt dependency at runtime
- **GUI Mode** (`NIDS`): Qt6 interface with tabbed Packets/Flows view, detection
  detail panel, weight tuning dialog

### Infrastructure
- **ONNX Runtime Inference**: Fast CPU inference with batched prediction
- **PcapPlusPlus**: RAII packet capture and parsing (replaced raw libpcap)
- **Threat Intelligence**: Loads IP blocklists from CSV/text feeds (CIDR-aware matching)
- **Heuristic Rules**: 7 built-in rules (port scan, SYN flood, DNS amplification, etc.)
- **Docker Sandbox**: 3-container test topology (server, attacker, victim) for
  inline IPS testing on isolated `172.28.0.0/24` bridge network
- **Cross-Platform**: Linux (primary) and Windows (via Npcap)

## Architecture

Clean Architecture with four layers (dependencies flow inward only):

```
src/
  core/       Pure C++23 domain logic (no platform dependencies)
  infra/      Platform-specific implementations (PcapPlusPlus, ONNX Runtime)
  app/        Application orchestration (Qt-free, pure C++23 with std::function)
  ui/         Qt6 presentation layer (optional)
  server/     gRPC headless daemon
  client/     CLI gRPC client
```

Key design decisions:
- **Server-first**: The primary deployment target is the headless daemon, not the GUI
- **Flow-level ML**: Purely statistical analysis of 77 bidirectional flow features --
  no deep packet inspection, no TLS/JA3 fingerprinting, no payload analysis
- **Complementary**: Designed to run alongside Snort/Suricata/Zeek, not replace them
- **Dependency inversion**: All cross-layer communication via abstract interfaces
  (`IPacketCapture`, `IPacketAnalyzer`, `IFlowExtractor`, `IRuleEngine`)

See [docs/architecture.md](docs/architecture.md) for detailed architecture documentation
and [AGENTS.md](AGENTS.md) for coding standards.

## Quick Start

### Automated Setup (Recommended)

```bash
git clone https://github.com/CybLow/NIDS.git
cd NIDS
./scripts/dev/setup-dev.sh
```

This installs all system dependencies, Conan 2, and runs `conan install` for both
Debug and Release. After completion:

```bash
# Debug build (with ASan/UBSan):
cmake --preset Debug
cmake --build --preset Debug
ctest --preset Debug

# Release build:
cmake --preset Release
cmake --build --preset Release

# Run (requires root or CAP_NET_RAW):
sudo ./build/Debug/NIDS
```

### Docker (No Local Dependencies)

```bash
xhost +local:docker
docker compose -f docker/app/compose.yml up --build
```

### Manual Setup

See [INSTALL.md](INSTALL.md) for detailed per-platform instructions.

## Dependency Management

| Dependency      | Source                                   |
|-----------------|------------------------------------------|
| spdlog          | Conan 2 (`conanfile.py`)                 |
| nlohmann_json   | Conan 2 (`conanfile.py`)                 |
| GoogleTest      | Conan 2 (`conanfile.py`)                 |
| PcapPlusPlus    | Conan 2 (`conanfile.py`)                 |
| gRPC + Protobuf | Conan 2 (optional: `conan install . -o with_grpc=True`) |
| ONNX Runtime    | CMake FetchContent (pre-built binaries)  |
| Qt6             | System package (optional, GUI only)      |

## Build Options

| Option              | Default | Description                          |
|---------------------|---------|--------------------------------------|
| `NIDS_BUILD_TESTS`  | ON      | Build unit and integration tests     |
| `NIDS_BUILD_SERVER` | OFF     | Build headless gRPC server           |
| `NIDS_COVERAGE`     | OFF     | Enable gcov/lcov code coverage       |

## Running Tests

```bash
cmake --preset Debug
cmake --build --preset Debug
ctest --preset Debug
```

Four test executables are built (403 tests total):
- `nids_tests` -- Core/infra unit tests (324 tests, no Qt/ONNX dependencies)
- `nids_qt_tests` -- Qt-dependent tests (31 tests: CaptureController, AnalysisService, pipeline)
- `nids_stress_tests` -- Performance and concurrency stress tests (24 tests)
- `nids_onnx_tests` -- ONNX Runtime tests (24 tests: OnnxAnalyzer, AnalyzerFactory)

## Model Training

The CNN-BiLSTM model can be retrained on the LSNM2024 dataset:

```bash
pip install -r scripts/ml/requirements.txt
python scripts/ml/download_dataset.py
python scripts/ml/preprocess.py
python scripts/ml/train_model.py
python scripts/ml/export_onnx.py
python scripts/ml/evaluate.py
```

See [docs/model-training.md](docs/model-training.md) for the full training guide.

## Attack Types Detected

| Type                  | Description                         |
|-----------------------|-------------------------------------|
| Benign                | Normal traffic                      |
| MITM ARP Spoofing     | Man-in-the-middle via ARP spoofing  |
| SSH Brute Force       | SSH brute force login attempts      |
| FTP Brute Force       | FTP brute force login attempts      |
| DDoS ICMP             | DDoS via ICMP flooding              |
| DDoS Raw IP           | DDoS via raw IP packets             |
| DDoS UDP              | DDoS via UDP flooding               |
| DoS                   | Denial of Service                   |
| Exploiting FTP        | FTP exploitation                    |
| Fuzzing               | Protocol fuzzing attacks            |
| ICMP Flood            | ICMP flood attacks                  |
| SYN Flood             | TCP SYN flood attacks               |
| Port Scanning         | Port scanning/enumeration           |
| Remote Code Execution | RCE attacks                         |
| SQL Injection         | SQL injection attacks               |
| XSS                   | Cross-site scripting                |

## Project Structure

```
NIDS/
  CMakeLists.txt              Root build configuration
  conanfile.py                Conan 2 dependency recipe (with_grpc option)
  CMakePresets.json           Developer + CI build presets
  conan/profiles/             In-repo Conan profiles (linux, windows)
  scripts/
    dev/                      Developer environment setup
    ml/                       ML training pipeline (Colab-compatible)
    ci/                       CI / static analysis tooling
    ops/                      Runtime operational scripts (threat feed updates)
  docker/
    app/                      Production Docker build + compose
    ci/                        CI builder image
    sandbox/                  3-container IPS test environment
  cmake/
    FetchOnnxRuntime.cmake    Downloads pre-built ONNX Runtime binaries
    NidsTargetDefaults.cmake  Shared compiler flags (ASan/UBSan in Debug)
  .github/workflows/          CI/CD (build, test, lint, coverage, release)
  proto/
    nids.proto                gRPC service definitions (7 RPCs)
  src/
    main.cpp                  GUI/headless entry point
    core/                     Domain layer (pure C++23, zero deps)
      model/                  PacketInfo, AttackType, CaptureSession,
                              PacketFilter, DetectionResult, FlowInfo,
                              ProtocolConstants
      concurrent/             BoundedQueue (thread-safe producer-consumer)
      math/                   WelfordAccumulator (online statistics)
      services/               IPacketCapture, IPacketAnalyzer, IFlowExtractor,
                              IRuleEngine, IAnalysisRepository, ICommand,
                              Configuration, ServiceRegistry
    infra/                    Infrastructure
      capture/                PcapCapture (PcapPlusPlus RAII devices)
      analysis/               OnnxAnalyzer, AnalyzerFactory, FeatureNormalizer
      flow/                   NativeFlowExtractor (77 bidirectional features)
      rules/                  HeuristicRuleEngine (7 heuristic rules)
      threat/                 ThreatIntelProvider (IP blocklist feeds)
      parsing/                PacketParser (protocol layer extraction)
      config/                 ConfigLoader (JSON config parsing)
      output/                 ConsoleAlertSink (pluggable output)
      platform/               SocketInit, SignalHandler, AsanOptions
    app/                      Application layer (Qt-free, pure C++23)
      CaptureController       Capture lifecycle management
      AnalysisService         ML pipeline orchestration
      LiveDetectionPipeline   Real-time flow detection pipeline
      FlowAnalysisWorker      ML inference consumer (std::jthread)
      HybridDetectionService  ML + TI + heuristic fusion engine
      PipelineFactory         Service graph construction factory
      commands/               Command pattern (CaptureCommands)
    ui/                       Qt6 presentation (optional)
      MainWindow              Main application window
      PacketTableModel        Packet MVC table model
      FlowTableModel          Flow MVC table model
      DetectionDetailWidget   Detection result inspector
      HexView                 Hex/ASCII display
      FilterPanel             Capture filter controls
      WeightTuningDialog      Hybrid detection weight tuning
    server/                   gRPC headless daemon (nids-server)
    client/                   gRPC CLI client (nids-cli)
  tests/
    unit/                     324 unit tests (GoogleTest + GoogleMock)
    integration/              Pipeline integration tests
    stress/                   24 performance / concurrency stress tests
  docs/
    architecture.md           System architecture and detection philosophy
    model-training.md         Model training guide
    deployment.md             Deployment instructions
    roadmap.md                Phased project roadmap
    adr/                      Architecture Decision Records (6 ADRs)
```

## Documentation

- [Architecture](docs/architecture.md) -- System design, layers, patterns, data flow
- [Roadmap](docs/roadmap.md) -- All planned work, prioritized by phase
- [Model Training](docs/model-training.md) -- How to train, export, and deploy the model
- [Deployment](docs/deployment.md) -- Docker, bare metal, packaging, systemd
- [Installation](INSTALL.md) -- Build dependencies for all platforms
- [Coding Standards](AGENTS.md) -- C++23/Qt6 conventions, banned patterns, design rules

### Architecture Decision Records
- [ADR-001: Replace frugally-deep with ONNX Runtime](docs/adr/001-replace-fdeep-with-onnx.md)
- [ADR-002: LSNM2024 Dataset](docs/adr/002-lsnm2024-dataset.md)
- [ADR-003: Qt6 Migration](docs/adr/003-qt6-migration.md)
- [ADR-004: Model Benchmark Analysis](docs/adr/004-model-benchmark-analysis.md)
- [ADR-005: Hybrid Detection System](docs/adr/005-hybrid-detection-system.md)
- [ADR-006: PcapPlusPlus Migration](docs/adr/006-pcapplusplus-migration.md)

## Roadmap

- [x] Native C++ flow feature extraction (77 bidirectional flow features)
- [x] ONNX Runtime for ML inference
- [x] CNN-BiLSTM model trained on LSNM2024
- [x] Qt6 + C++23 modernization
- [x] GitHub Actions CI/CD
- [x] CPack packaging (DEB/RPM/TGZ)
- [x] Hybrid detection (ML + Threat Intelligence + Heuristic Rules)
- [x] Conan 2 package management
- [x] Cleanup, config JSON loading, and test foundation (Phase 6)
- [x] UI for hybrid detection results (Phase 7)
- [x] Real-time per-flow detection with producer-consumer pipeline (Phase 8)
- [x] gRPC server daemon, CLI client, Docker sandbox (Phase 9)
- [x] C++23 modernization audit (`std::expected`, `std::span`, `std::ranges`,
  `FilterBuilder`, `ICommand`, `PacketParser` extraction, `PipelineFactory`)
- [ ] Model and detection improvements (Phase 10)
- [ ] Documentation polish and coverage enforcement (Phase 11)

See [docs/roadmap.md](docs/roadmap.md) for the full breakdown.

## License

This project is licensed under the MIT License -- see [LICENSE](LICENSE) for details.
