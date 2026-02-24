# NIDS - Network Intrusion Detection System

An advanced Network Intrusion Detection System leveraging AI to monitor and analyze
network traffic for potential threats. NIDS captures packets, extracts flow features,
and classifies traffic using a neural network model.

## Architecture

The project follows Clean Architecture with four layers:

```
src/
  core/       Pure C++ domain logic (no platform dependencies)
  infra/      Platform-specific implementations (pcap, ML backends)
  app/        Application orchestration (controllers, services)
  ui/         Qt5 presentation layer
  server/     gRPC headless daemon (planned)
  client/     CLI/GUI client (planned)
```

See [AGENTS.md](AGENTS.md) for coding standards and design patterns.

## Features

- **AI-Powered Attack Detection**: Neural network classifies 16 attack types
  (DDoS, Portscan, SQL Injection, XSS, Brute Force, etc.)
- **Real-time Packet Capture**: Live capture with BPF filtering
- **Application Detection**: Port-to-service mapping for 100+ protocols
- **Hex/ASCII Inspector**: Raw packet data viewer
- **Report Generation**: Post-capture analysis reports
- **Cross-Platform**: Linux and Windows (via Npcap)

## Prerequisites

- **CMake** >= 3.20
- **C++17** compiler (GCC 9+, Clang 10+, MSVC 2019+)
- **Qt5** (Core, Gui, Widgets)
- **libpcap** (Linux/macOS) or **Npcap SDK** (Windows)
- **frugally-deep** (or ONNX Runtime as alternative)

### Quick Install (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y cmake g++ qtbase5-dev libpcap-dev libeigen3-dev nlohmann-json3-dev
```

For frugally-deep, see [INSTALL.md](INSTALL.md).

## Build

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
sudo ./NIDS
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `NIDS_BUILD_TESTS` | OFF | Build unit tests |
| `NIDS_BUILD_SERVER` | OFF | Build headless gRPC server |

### Run Tests

```bash
cmake .. -DNIDS_BUILD_TESTS=ON
make -j$(nproc)
ctest --output-on-failure
```

## Docker

```bash
docker compose up --build
```

Requires `--net=host` and `NET_RAW` capability for packet capture.

## Project Structure

```
NIDS/
  CMakeLists.txt          Root build configuration
  vcpkg.json              Dependency manifest
  Dockerfile              Multi-stage Docker build
  docker-compose.yml      Container orchestration
  AGENTS.md               Coding standards and architecture guide
  proto/nids.proto        gRPC service definition
  cmake/FindPCAP.cmake    Cross-platform PCAP finder
  src/
    main.cpp              Application entry point
    core/                 Domain layer
      model/              Data structures (PacketInfo, AttackType, CaptureSession)
      services/           Interfaces and pure logic (IPacketCapture, PacketFilter)
    infra/                Infrastructure
      capture/            PcapCapture, RAII handles
      analysis/           FdeepAnalyzer, OnnxAnalyzer
      flow/               CsvFlowProcessor, NativeFlowExtractor
      platform/           NetworkHeaders, SocketInit
    app/                  Application layer
      CaptureController   Capture lifecycle management
      AnalysisService     ML pipeline orchestration
      ReportGenerator     Report output
    ui/                   Qt5 presentation
      MainWindow          Main application window
      PacketTableModel    MVC table model
      HexView             Hex/ASCII display
      FilterPanel         Capture filter controls
    server/               gRPC server daemon (scaffold)
    client/               gRPC client (scaffold)
  tests/
    unit/                 Unit tests (GoogleTest)
    integration/          Integration tests
  pcaptocsv/              CICFlowMeter scripts (legacy)
```

## Roadmap

- [ ] Complete native C++ flow feature extraction (replace CICFlowMeter)
- [ ] ONNX Runtime integration for GPU-accelerated inference
- [ ] gRPC client/server for remote capture
- [ ] Real-time per-flow AI detection
- [ ] YARA rules integration
- [ ] Deep Packet Inspection (DPI)
- [ ] Email notifications
- [ ] Web dashboard

## License

See repository for license information.
