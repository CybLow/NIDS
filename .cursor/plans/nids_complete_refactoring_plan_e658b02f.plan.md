---
name: NIDS Complete Refactoring Plan
overview: "Complete refactoring of the NIDS C++ codebase: rewrite AGENTS.md with exhaustive C++ best practices/design patterns, fix architecture, add platform abstraction for Linux/Windows, modernize build system, and plan future features (client/server, Docker, better ML model, documentation)."
todos:
  - id: agents-md
    content: Rewrite AGENTS.md with comprehensive C++ best practices, design patterns (Strategy, Observer, Factory, RAII, Builder, Repository, Command), coding standards, memory management rules, concurrency rules, platform abstraction rules, error handling, testing standards, and build system rules
    status: completed
  - id: fix-bugs
    content: "Fix critical bugs: sharedVector.at(1)->at(i) in generateReport(), uninitialized dumper_, pcap_breakloop on null handle, process_csv trailing comma"
    status: completed
  - id: cmake-modernize
    content: "Modernize CMakeLists.txt: fix AUTOMOC ordering, add target_include_directories, remove headers from add_executable, add vcpkg.json manifest, add install targets"
    status: completed
  - id: platform-abstraction
    content: "Create platform abstraction layer: NetworkHeaders.h with conditional includes, portable struct aliases, SocketInit for Windows, replace u_char with uint8_t"
    status: completed
  - id: raii-wrappers
    content: "Create RAII wrappers: PcapHandle (unique_ptr<pcap_t, pcap_close>), PcapDumper (unique_ptr<pcap_dumper_t, pcap_dump_close>), replace all raw pcap pointers"
    status: completed
  - id: extract-interfaces
    content: "Extract core interfaces: IPacketCapture, IPacketAnalyzer, IFlowExtractor + implement PcapCapture and FdeepAnalyzer"
    status: completed
  - id: extract-controller
    content: "Extract CaptureController from PacketCaptureUI: move capture lifecycle, packetInfoList, filter management, report generation out of UI"
    status: completed
  - id: mvc-table
    content: Replace QTableWidget with QTableView + PacketTableModel (QAbstractTableModel) for proper MVC pattern
    status: completed
  - id: remove-globals
    content: Remove globals.h and sharedVector, replace with CaptureSession owned by CaptureController, pass results via signals
    status: completed
  - id: remove-system-calls
    content: Replace all system() calls with std::filesystem::remove() and QProcess, add proper error handling
    status: completed
  - id: code-quality
    content: Remove using namespace std from all headers, replace C-style casts with static_cast/reinterpret_cast, standardize to English comments, add spdlog logging
    status: completed
  - id: testing
    content: Add GoogleTest infrastructure, write unit tests for core classes (PacketFilter, ServiceRegistry, PacketInfo, ReportGenerator)
    status: completed
  - id: windows-compat
    content: "Add Windows compatibility: Npcap support, winsock2 headers, WSAStartup, adapt FindPCAP.cmake for Windows"
    status: completed
  - id: docker
    content: Create Dockerfile (multi-stage) and docker-compose.yml for server deployment
    status: completed
  - id: client-server
    content: Plan and implement client/server separation with gRPC API for headless capture daemon + Qt GUI client
    status: completed
  - id: ml-upgrade
    content: Replace frugally-deep with ONNX Runtime, implement real-time per-flow inference, native C++ flow feature extraction
    status: completed
isProject: false
---

# NIDS - Complete Refactoring and Improvement Plan

## Current State Audit

### Codebase Overview

- **Language**: C++17, Qt5 GUI, libpcap, frugally-deep (Keras inference)
- **Size**: ~1200 lines across 10 source files + 10 headers
- **Architecture**: Monolithic Qt application, no separation of concerns
- **Platform**: Linux-only (POSIX headers, shell `system()` calls, CICFlowMeter Java tool)
- **Tests**: None
- **CI/CD**: None
- **Docker**: None
- **Dependency management**: Manual (no vcpkg/conan)

### Critical Bugs Found

1. `**sharedVector.at(1)` in `generateReport()`** ([src/ui/ui.cpp](src/ui/ui.cpp) line 512) -- should be `sharedVector.at(i)`, causes wrong status for every packet
2. **Global `sharedVector`** ([include/globals.h](include/globals.h)) -- written from worker thread, read from UI thread with zero synchronization = data race / UB
3. `**dumper_` never initialized** -- `PacketCapture` constructor doesn't init `dumper_` to `nullptr`, `dumpPacket()` checks `dumper_ != nullptr` on uninitialized memory
4. `**pcap_breakloop` on null handle** -- `StopCapture()` calls `pcap_breakloop(handle_)` before checking `handle_ != nullptr`
5. `**process_csv()` trailing comma** -- the CSV writer outputs an extra comma when skipping columns, corrupting the ML input

---

## Phase 1: AGENTS.md -- C++ Best Practices and Design Patterns Reference

Rewrite `AGENTS.md` as the authoritative coding standard for the project. It will cover:

### Content Structure

1. **Project Architecture Rules**
  - Clean Architecture layers: `core/` (domain), `infra/` (platform), `app/` (use cases), `ui/` (presentation)
  - MVC/MVVM separation for Qt UI
  - Dependency Inversion Principle: depend on abstractions, not concretions
2. **C++ Coding Standards**
  - C++17 minimum, target C++20 where possible
  - **No `using namespace std;` in headers** -- currently in every header file ([PacketCapture.h](include/packet/PacketCapture.h), [PacketFilter.h](include/packet/PacketFilter.h), [PacketInfo.h](include/packet/PacketInfo.h), [ui.h](include/ui/ui.h), [HexAsciiDisplay.h](include/ui/HexAsciiDisplay.h), [FullListDialog.h](include/ui/FullListDialog.h))
  - Prefer `std::string_view` over `const std::string&` for read-only params
  - Use `[[nodiscard]]`, `constexpr`, `noexcept` where appropriate
  - Prefer `static_cast` / `reinterpret_cast` over C-style casts (currently C-style in [PacketCapture.cpp](src/packet/PacketCapture.cpp) lines 70, 78, 86)
  - English-only code and comments (currently mixed FR/EN)
3. **Memory Management Rules (RAII)**
  - `std::unique_ptr` for exclusive ownership (replace raw `PacketCapture`* in [ui.h](include/ui/ui.h) line 68)
  - `std::unique_ptr` with custom deleters for C resources:

```cpp
     using PcapHandle = std::unique_ptr<pcap_t, decltype(&pcap_close)>;
     using PcapDumper = std::unique_ptr<pcap_dumper_t, decltype(&pcap_dump_close)>;
     

```

- `std::shared_ptr` only when truly shared ownership
- Zero raw `new`/`delete` outside of Qt parent-child managed widgets

1. **Concurrency Rules**
  - Never share mutable state without synchronization
  - Prefer `QThread` + worker object pattern over subclassing `QThread` (current antipattern in [PacketCapture.h](include/packet/PacketCapture.h))
  - Use `std::mutex` + `std::lock_guard` for shared data
  - Prefer `std::atomic` for simple flags (already done for `capturing`)
2. **Design Patterns Catalog**
  - **Strategy**: for packet parsing (different protocols), filter generation
  - **Observer**: Qt signals/slots (already used, formalize)
  - **Factory Method**: for creating platform-specific packet capture backends
  - **RAII Wrapper**: for all C resources (pcap, file handles)
  - **Builder**: for complex filter construction (replace the current string concatenation in [PacketFilter.cpp](src/packet/PacketFilter.cpp))
  - **Singleton** (thread-safe): only for truly global services (logging, config)
  - **Repository**: for ML model results (replace `sharedVector`)
  - **Command**: for capture start/stop/pause operations
3. **Error Handling**
  - Use `std::expected` (C++23) or `tl::expected` for recoverable errors
  - Use exceptions only for truly exceptional cases
  - Never ignore return values (currently `system()` return values are ignored in [packetToCsv.cpp](src/packet/packetToCsv.cpp))
  - Use `spdlog` instead of `std::cout`/`std::cerr` for logging
4. **Platform Abstraction Rules**
  - All platform-specific code behind interfaces
  - Use `std::filesystem` instead of `system("rm ...")`
  - Use Qt abstractions (`QStandardPaths`, `QProcess`) for OS operations
  - Conditional compilation only in implementation files, never in headers
5. **Testing Standards**
  - GoogleTest + GoogleMock for unit tests
  - Every new class must have corresponding tests
  - Minimum 80% coverage target
  - Integration tests for capture pipeline
6. **Build System Rules**
  - Modern CMake (targets, not variables)
  - `target_include_directories` instead of `include_directories`
  - vcpkg for dependency management
  - Separate CMakeLists per directory

---

## Phase 2: Architecture Refactoring

### New Directory Structure

```
NIDS/
  CMakeLists.txt
  vcpkg.json
  Dockerfile
  docker-compose.yml
  docs/
  tests/
    unit/
    integration/
  src/
    core/                     # Domain layer (pure C++, no platform deps)
      model/
        PacketInfo.h/cpp      # Packet data structures
        AttackType.h           # Enum for attack classifications
        CaptureSession.h/cpp  # Session state management
      services/
        IPacketAnalyzer.h     # Interface for ML analysis
        IPacketCapture.h      # Interface for capture backend
        IFlowExtractor.h     # Interface for flow feature extraction
        PacketFilter.h/cpp    # Filter logic (pure)
        ServiceRegistry.h/cpp # Port-to-service mapping
    infra/                    # Infrastructure layer
      capture/
        PcapCapture.h/cpp     # libpcap implementation of IPacketCapture
        PcapHandle.h          # RAII wrapper for pcap_t
      analysis/
        FdeepAnalyzer.h/cpp   # frugally-deep impl of IPacketAnalyzer
      flow/
        CICFlowExtractor.h/cpp # CICFlowMeter wrapper (later: native C++)
      platform/
        NetworkHeaders.h      # Platform-conditional network header includes
        SocketInit.h/cpp      # WSAStartup/Cleanup on Windows, no-op on Linux
    app/                      # Application / Use Case layer
      CaptureController.h/cpp # Orchestrates capture lifecycle
      AnalysisService.h/cpp   # Orchestrates ML pipeline
      ReportGenerator.h/cpp   # Report generation logic
    ui/                       # Presentation layer (Qt-specific)
      MainWindow.h/cpp
      PacketTableModel.h/cpp  # QAbstractTableModel (proper MVC)
      HexView.h/cpp
      FilterPanel.h/cpp
      dialogs/
        ServiceDialog.h/cpp
    server/                   # Future: gRPC/REST API server
    client/                   # Future: CLI client
```

### Key Refactoring Steps

**Step 2.1: Extract platform abstraction layer** (`infra/platform/`)

- Create `NetworkHeaders.h` with `#ifdef _WIN32` / `#else` conditional includes
- Define portable struct aliases for IP/TCP/UDP headers
- Create `SocketInit` for Windows WSAStartup

**Step 2.2: RAII wrappers** (`infra/capture/PcapHandle.h`)

- `PcapHandle` wrapping `pcap_t`* with `pcap_close` deleter
- `PcapDumper` wrapping `pcap_dumper_t`* with `pcap_dump_close` deleter

**Step 2.3: Extract interfaces** (`core/services/`)

- `IPacketCapture` -- abstract interface for packet capture
- `IPacketAnalyzer` -- abstract interface for ML inference
- `IFlowExtractor` -- abstract interface for flow feature extraction

**Step 2.4: Extract CaptureController** (`app/CaptureController.h`)

- Move all capture lifecycle logic out of `PacketCaptureUI`
- Manage `PacketCapture` instance, filter setup, start/stop
- Own the `packetInfoList` (currently in UI)
- Thread-safe result storage (replace `sharedVector`)

**Step 2.5: Proper Qt MVC for packet table**

- Create `PacketTableModel : QAbstractTableModel` instead of manually inserting `QTableWidgetItem`s
- Use `QTableView` instead of `QTableWidget`

**Step 2.6: Replace `system()` calls**

- Use `std::filesystem::remove()` instead of `system("rm ...")`
- Use `QProcess` for CICFlowMeter script execution
- Proper error checking on all operations

**Step 2.7: Remove global state**

- Delete `globals.h`
- Replace `sharedVector` with a `CaptureSession` object owned by `CaptureController`
- Pass analysis results via signals/callbacks

---

## Phase 3: Build System Modernization

### CMake Overhaul

Current issues in [CMakeLists.txt](CMakeLists.txt):

- Header files listed in `add_executable` (unnecessary)
- `CMAKE_AUTOMOC` set after target creation (too late)
- No `target_include_directories`
- No install rules

New CMake structure:

- Root `CMakeLists.txt` with project-level settings
- `src/CMakeLists.txt` per subdirectory
- `vcpkg.json` manifest for dependencies (frugally-deep, nlohmann-json, spdlog, gtest)
- `CMAKE_AUTOMOC ON` set before target creation
- Proper `target_include_directories(NIDS PRIVATE ${CMAKE_SOURCE_DIR}/src)`
- Install targets and CPack configuration
- Option flags: `-DNIDS_BUILD_TESTS=ON`, `-DNIDS_BUILD_SERVER=ON`

### vcpkg Integration

```json
{
  "name": "nids",
  "version": "0.2.0",
  "dependencies": [
    "frugally-deep",
    "nlohmann-json",
    "spdlog",
    "gtest",
    "qt5-base",
    "pcap"
  ]
}
```

---

## Phase 4: Linux/Windows Compatibility

### Required Changes


| Component | Linux (current) | Windows (to add) |
| --------- | --------------- | ---------------- |


- **Network headers**: `<netinet/*>`, `<arpa/inet.h>` -> `<winsock2.h>`, `<ws2tcpip.h>`
- **TCP struct members**: `th_sport` / `th_dport` -> `source` / `dest` (varies by SDK)
- **UDP struct members**: `uh_sport` / `uh_dport` -> `source` / `dest`
- **Pcap library**: libpcap -> Npcap SDK
- **Sockets init**: Not needed -> `WSAStartup()`/`WSACleanup()`
- **File ops**: `system("rm ...")` -> `std::filesystem::remove()`
- **Shell scripts**: `system("./script.sh")` -> `QProcess` or native C++
- **Byte type**: `u_char` -> `uint8_t` (portable)

### Approach: Platform Abstraction Interface

```cpp
// core/services/IPacketCapture.h
class IPacketCapture {
public:
    virtual ~IPacketCapture() = default;
    virtual bool initialize(const std::string& interface) = 0;
    virtual void startCapture() = 0;
    virtual void stopCapture() = 0;
    // Signal-like callback for captured packets
    using PacketCallback = std::function<void(const PacketInfo&)>;
    virtual void setCallback(PacketCallback cb) = 0;
};
```

Platform implementations register via factory:

- `PcapCapture` (Linux/macOS with libpcap)
- `NpcapCapture` (Windows with Npcap SDK)

---

## Phase 5: Testing Infrastructure

- **Framework**: GoogleTest + GoogleMock
- **Unit tests**: All `core/` classes (pure logic, no platform deps)
- **Integration tests**: Capture pipeline with pcap replay files
- **Test structure**:

```
  tests/
    unit/
      test_PacketFilter.cpp
      test_ServiceRegistry.cpp
      test_PacketInfo.cpp
      test_ReportGenerator.cpp
    integration/
      test_CaptureController.cpp
      test_AnalysisPipeline.cpp
    fixtures/
      sample.pcap
  

```

---

## Phase 6: Future Features (Post-Refactoring)

### 6.1 Client/Server Separation

- **Server** (`src/server/`): headless daemon with gRPC API
  - Capture management endpoints
  - Real-time packet streaming
  - Analysis results streaming
- **Client** (`src/client/`): Qt GUI connecting to server via gRPC
- **CLI client**: command-line interface for scripting

### 6.2 Docker

- Multi-stage build: build image + slim runtime image
- `docker-compose.yml` for server + optional web dashboard
- Volume mounts for model files and pcap dumps
- `--net=host` or `--cap-add=NET_RAW` for capture privileges

### 6.3 Better ML Model

- Replace frugally-deep with **ONNX Runtime** (faster, GPU support, more model formats)
- Train on CIC-IDS2017 + CIC-IDS2018 + newer datasets
- Real-time inference per-flow instead of batch post-capture
- Model versioning and hot-reload

### 6.4 Native Flow Extraction (Replace CICFlowMeter)

- Implement CICFlowMeter feature extraction in C++ natively
- Eliminates Java dependency and shell script pipeline
- Enables real-time flow features for live AI detection

### 6.5 Documentation

- Doxygen for API documentation
- Architecture Decision Records (ADRs)
- User manual
- Developer setup guide (Linux + Windows)

### 6.6 Additional Features (from README TODO)

- YARA rules integration
- Deep Packet Inspection (DPI)
- Email notifications (via Qt SMTP or libcurl)
- Endpoint network isolation

---

## Execution Order (Priority)

The refactoring should be done in this exact order to avoid regressions:

1. Fix critical bugs (Phase 0 -- immediate)
2. Write AGENTS.md with all rules (Phase 1)
3. Modernize CMake + add vcpkg (Phase 3)
4. Create platform abstraction + RAII wrappers (Phase 2, steps 2.1-2.2)
5. Extract interfaces and CaptureController (Phase 2, steps 2.3-2.4)
6. Refactor UI with proper MVC (Phase 2, step 2.5)
7. Remove `system()` calls + global state (Phase 2, steps 2.6-2.7)
8. Add testing infrastructure (Phase 5)
9. Windows compatibility (Phase 4)
10. Client/Server + Docker (Phase 6)
11. Better ML model + native flow extraction (Phase 6)

