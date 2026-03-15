# NIDS - Network Intrusion Detection System

[![CI](https://github.com/CybLow/NIDS/actions/workflows/ci.yml/badge.svg)](https://github.com/CybLow/NIDS/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/CybLow/NIDS)](LICENSE)

An AI-powered Network Intrusion Detection System that captures packets, extracts
flow features natively in C++, and classifies traffic using a CNN-BiLSTM model trained
on the LSNM2024 dataset. Built with C++23, Qt6, and ONNX Runtime.

## Features

- **CNN-BiLSTM Attack Detection**: Classifies 15 attack types + benign traffic using
  a hybrid convolutional/recurrent neural network
- **LSNM2024 Dataset**: Trained on 6M+ samples covering modern threats (DDoS, brute
  force, RCE, SQL injection, XSS, port scanning, and more)
- **ONNX Runtime Inference**: Fast CPU inference with optional GPU acceleration via
  CUDA/TensorRT
- **Native Flow Extraction**: 77 bidirectional flow features computed in C++ -- no
  external tools required
- **Real-time Packet Capture**: Live capture with BPF filtering via PcapPlusPlus
- **Application Detection**: Port-to-service mapping for 100+ protocols
- **Hex/ASCII Inspector**: Raw packet data viewer
- **Report Generation**: Post-capture analysis reports
- **Cross-Platform**: Linux and Windows (via Npcap)

## Architecture

Clean Architecture with four layers:

```
src/
  core/       Pure C++23 domain logic (no platform dependencies)
  infra/      Platform-specific implementations (PcapPlusPlus, ONNX Runtime)
  app/        Application orchestration (controllers, services)
  ui/         Qt6 presentation layer
  server/     gRPC headless daemon (planned)
  client/     CLI client (planned)
```

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
| ONNX Runtime    | CMake FetchContent (pre-built binaries)  |
| Qt6             | System package                           |
| PcapPlusPlus    | Conan 2 (`conanfile.py`)                 |

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

Three test executables are built:
- `nids_tests` -- Core/infra unit tests (no Qt/ONNX dependencies)
- `nids_qt_tests` -- Qt-dependent tests (CaptureController, AnalysisService, pipeline)
- `nids_onnx_tests` -- ONNX Runtime tests (OnnxAnalyzer, AnalyzerFactory)

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
  conanfile.py                Conan 2 dependency recipe
  CMakePresets.json           Developer + CI build presets
  conan/profiles/             In-repo Conan profiles (linux, windows)
  scripts/
    dev/                      Developer environment setup
    ml/                       ML training pipeline
    ci/                       CI / static analysis tooling
    ops/                      Runtime operational scripts
  .devcontainer/              VS Code / CLion devcontainer
  docker/
    app/
      Dockerfile              Multi-stage Docker build
      compose.yml             Production compose stack
    ci/
      Dockerfile              CI builder image
      compose.yml             Local CI simulation stack
  AGENTS.md                   Coding standards and architecture guide
  INSTALL.md                  Detailed installation instructions
  cmake/
    FetchOnnxRuntime.cmake    Downloads pre-built ONNX Runtime binaries
    NidsTargetDefaults.cmake  Shared compiler flags (ASan/UBSan in Debug)
  .github/workflows/          CI/CD (build, test, lint, coverage, release)
  src/
    main.cpp                  Application entry point
    core/                     Domain layer
      model/                  PacketInfo, AttackType, CaptureSession
      services/               IPacketCapture, IPacketAnalyzer, IFlowExtractor,
                              Configuration, PacketFilter, ServiceRegistry
    infra/                    Infrastructure
      capture/                PcapCapture (PcapPlusPlus RAII devices)
      analysis/               OnnxAnalyzer, AnalyzerFactory
      flow/                   NativeFlowExtractor (77 CIC features)
      platform/               SocketInit
    app/                      Application layer
      CaptureController       Capture lifecycle management
      AnalysisService         ML pipeline orchestration
      LiveDetectionPipeline   Real-time flow detection
      FlowAnalysisWorker     ML inference consumer thread
      HybridDetectionService ML + TI + heuristic fusion
    ui/                       Qt6 presentation
      MainWindow              Main application window
      PacketTableModel        MVC table model
      HexView                 Hex/ASCII display
      FilterPanel             Capture filter controls
    server/                   gRPC server daemon (scaffold)
    client/                   gRPC client (scaffold)
  scripts/                    Setup + Python training pipeline
  tests/
    unit/                     Unit tests (GoogleTest + GoogleMock)
    integration/              Integration tests
  docs/
    architecture.md           System architecture
    model-training.md         Model training guide
    deployment.md             Deployment instructions
    adr/                      Architecture Decision Records
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
- [x] Conan 2 package management (replaced vcpkg)
- [ ] Cleanup, config JSON loading, and test foundation (Phase 6)
- [ ] UI for hybrid detection results (Phase 7)
- [ ] Real-time per-flow detection (Phase 8)
- [ ] gRPC server and CLI client (Phase 9)
- [ ] Model and detection improvements (Phase 10)

See [docs/roadmap.md](docs/roadmap.md) for the full breakdown.

## License

See repository for license information.
