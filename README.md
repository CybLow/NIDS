# NIDS - Network Intrusion Detection System

[![CI](https://github.com/CybLow/NIDS/actions/workflows/ci.yml/badge.svg)](https://github.com/CybLow/NIDS/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/CybLow/NIDS)](LICENSE)

An AI-powered Network Intrusion Detection System that captures packets, extracts
flow features natively in C++, and classifies traffic using a CNN-BiLSTM model trained
on the LSNM2024 dataset. Built with C++20, Qt6, and ONNX Runtime.

## Features

- **CNN-BiLSTM Attack Detection**: Classifies 15 attack types + benign traffic using
  a hybrid convolutional/recurrent neural network
- **LSNM2024 Dataset**: Trained on 6M+ samples covering modern threats (DDoS, brute
  force, RCE, SQL injection, XSS, port scanning, and more)
- **ONNX Runtime Inference**: Fast CPU inference with optional GPU acceleration via
  CUDA/TensorRT
- **Native Flow Extraction**: 77 CIC-compatible features computed in C++ — no external
  tools (CICFlowMeter) required
- **Real-time Packet Capture**: Live capture with BPF filtering via libpcap
- **Application Detection**: Port-to-service mapping for 100+ protocols
- **Hex/ASCII Inspector**: Raw packet data viewer
- **Report Generation**: Post-capture analysis reports
- **Cross-Platform**: Linux and Windows (via Npcap)

## Architecture

Clean Architecture with four layers:

```
src/
  core/       Pure C++20 domain logic (no platform dependencies)
  infra/      Platform-specific implementations (pcap, ONNX Runtime)
  app/        Application orchestration (controllers, services)
  ui/         Qt6 presentation layer
  server/     gRPC headless daemon (planned)
  client/     CLI client (planned)
```

See [docs/architecture.md](docs/architecture.md) for detailed architecture documentation
and [AGENTS.md](AGENTS.md) for coding standards.

## Quick Start

### Docker (easiest)

```bash
xhost +local:docker
docker compose up --build
```

### Build from Source

```bash
# Install system dependencies (Ubuntu 22.04+)
sudo apt install -y cmake g++ ninja-build qt6-base-dev libpcap-dev

# Clone and build with vcpkg
git clone https://github.com/CybLow/NIDS.git
cd NIDS
git clone https://github.com/microsoft/vcpkg
./vcpkg/bootstrap-vcpkg.sh

cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake

cmake --build build --parallel

# Run (requires root or CAP_NET_RAW)
sudo ./build/NIDS
```

See [INSTALL.md](INSTALL.md) for detailed platform-specific instructions.

## Build Options

| Option              | Default | Description                          |
|---------------------|---------|--------------------------------------|
| `NIDS_BUILD_TESTS`  | OFF     | Build unit and integration tests     |
| `NIDS_BUILD_SERVER` | OFF     | Build headless gRPC server           |
| `NIDS_COVERAGE`     | OFF     | Enable gcov/lcov code coverage       |

## Running Tests

```bash
cmake -B build -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake \
    -DNIDS_BUILD_TESTS=ON

cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Three test executables are built:
- `nids_tests` — Core/infra unit tests (no Qt/ONNX dependencies)
- `nids_qt_tests` — Qt-dependent tests (CaptureController, AnalysisService, pipeline)
- `nids_onnx_tests` — ONNX Runtime tests (OnnxAnalyzer, AnalyzerFactory)

## Model Training

The CNN-BiLSTM model can be retrained on the LSNM2024 dataset:

```bash
pip install -r scripts/requirements.txt
python scripts/download_dataset.py
python scripts/preprocess.py
python scripts/train_model.py
python scripts/export_onnx.py
python scripts/evaluate.py
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
  vcpkg.json                  Dependency manifest
  Dockerfile                  Multi-stage Docker build
  docker-compose.yml          Container orchestration
  AGENTS.md                   Coding standards and architecture guide
  INSTALL.md                  Detailed installation instructions
  proto/nids.proto            gRPC service definition
  cmake/FindPCAP.cmake        Cross-platform PCAP finder
  .github/workflows/          CI/CD (build, test, lint, release)
  src/
    main.cpp                  Application entry point
    core/                     Domain layer
      model/                  PacketInfo, AttackType, CaptureSession
      services/               IPacketCapture, IPacketAnalyzer, IFlowExtractor,
                              Configuration, PacketFilter, ServiceRegistry
    infra/                    Infrastructure
      capture/                PcapCapture, PcapHandle (RAII)
      analysis/               OnnxAnalyzer, AnalyzerFactory
      flow/                   NativeFlowExtractor (77 CIC features)
      platform/               NetworkHeaders, SocketInit
    app/                      Application layer
      CaptureController       Capture lifecycle management
      AnalysisService         ML pipeline orchestration
      ReportGenerator         Report output
    ui/                       Qt6 presentation
      MainWindow              Main application window
      PacketTableModel        MVC table model
      HexView                 Hex/ASCII display
      FilterPanel             Capture filter controls
    server/                   gRPC server daemon (scaffold)
    client/                   gRPC client (scaffold)
  scripts/                    Python training pipeline
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

- [Architecture](docs/architecture.md) — System design, layers, patterns, data flow
- [Model Training](docs/model-training.md) — How to train, export, and deploy the model
- [Deployment](docs/deployment.md) — Docker, bare metal, packaging, systemd
- [Installation](INSTALL.md) — Build dependencies for all platforms
- [Coding Standards](AGENTS.md) — C++20/Qt6 conventions, banned patterns, design rules

### Architecture Decision Records
- [ADR-001: Replace frugally-deep with ONNX Runtime](docs/adr/001-replace-fdeep-with-onnx.md)
- [ADR-002: LSNM2024 Dataset](docs/adr/002-lsnm2024-dataset.md)
- [ADR-003: Qt6 Migration](docs/adr/003-qt6-migration.md)

## Roadmap

- [x] Native C++ flow feature extraction (replaces CICFlowMeter)
- [x] ONNX Runtime for ML inference
- [x] CNN-BiLSTM model trained on LSNM2024
- [x] Qt6 + C++20 modernization
- [x] GitHub Actions CI/CD
- [x] CPack packaging (DEB/RPM/TGZ)
- [ ] gRPC client/server for remote capture
- [ ] Real-time per-flow AI detection
- [ ] YARA rules integration
- [ ] Deep Packet Inspection (DPI)
- [ ] Web dashboard

## License

See repository for license information.
