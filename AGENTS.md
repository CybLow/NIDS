# NIDS -- Coding Standards and Architecture Guide

This document is the authoritative reference for all contributors working on the NIDS
(Network Intrusion Detection System) project. Every pull request **must** comply with
these rules. When in doubt, open a discussion before deviating.

---

## 1. Project Architecture

### 1.1 Layered Architecture (Clean Architecture)

The codebase follows a four-layer model. Dependencies flow **inward only**:
UI -> App -> Core, and Infra -> Core.

```
src/
  core/       # Domain layer -- pure C++17, zero platform / framework deps
  infra/      # Infrastructure -- platform-specific implementations
  app/        # Application / use-case layer -- orchestration logic
  ui/         # Presentation layer -- Qt-specific code
  server/     # (Future) gRPC/REST headless daemon
  client/     # (Future) CLI client
```

| Layer | May depend on | Must NOT depend on |
|-------|---------------|--------------------|
| `core/` | C++ Standard Library only | Qt, pcap, OS headers, `infra/`, `app/`, `ui/` |
| `infra/` | `core/`, OS/platform APIs, third-party C libs | `app/`, `ui/` |
| `app/` | `core/`, `infra/` (via interfaces) | `ui/`, Qt widgets |
| `ui/` | `core/`, `app/`, Qt | direct pcap calls, OS headers |

### 1.2 MVC/MVVM for the Qt UI

- **Model**: `PacketTableModel` (`QAbstractTableModel`), domain objects in `core/model/`.
- **View**: Qt widgets in `ui/` -- layout, rendering, user events only.
- **Controller / ViewModel**: classes in `app/` (`CaptureController`, `AnalysisService`,
  `ReportGenerator`) that bridge UI signals to domain logic.

The View **never** creates or manages domain objects directly.

### 1.3 Dependency Inversion Principle

All cross-layer communication goes through abstract interfaces defined in `core/services/`:

```cpp
// core/services/IPacketCapture.h
class IPacketCapture {
public:
    virtual ~IPacketCapture() = default;
    [[nodiscard]] virtual bool initialize(std::string_view interface) = 0;
    virtual void startCapture() = 0;
    virtual void stopCapture() = 0;
    using PacketCallback = std::function<void(const PacketInfo&)>;
    virtual void setCallback(PacketCallback cb) = 0;
};
```

Concrete implementations live in `infra/` and are injected into `app/` layer classes.

---

## 2. C++ Coding Standards

### 2.1 Language Version

- **Minimum**: C++17 (`-std=c++17`).
- **Target**: C++20 when all target compilers support it.
- Use `std::filesystem`, `std::optional`, `std::variant`, structured bindings,
  `if constexpr`, `[[nodiscard]]`, `[[maybe_unused]]` freely.

### 2.2 Naming Conventions

| Entity | Style | Example |
|--------|-------|---------|
| Class / Struct | PascalCase | `PacketCapture`, `CaptureSession` |
| Function / Method | camelCase | `startCapture()`, `getServiceName()` |
| Variable (local, param) | camelCase | `packetInfo`, `filterString` |
| Member variable | camelCase + trailing underscore | `handle_`, `capturing_` |
| Constant / enum value | kPascalCase or UPPER_SNAKE | `kMaxRetries`, `BENIGN` |
| Namespace | lowercase | `nids::core`, `nids::infra` |
| File names | PascalCase matching class | `PacketCapture.h`, `PacketCapture.cpp` |
| Interface | I-prefix + PascalCase | `IPacketCapture`, `IPacketAnalyzer` |

### 2.3 Header Hygiene

- **Never** write `using namespace std;` in a header file.
- `using namespace` is permitted in `.cpp` files inside a limited scope (function body)
  but discouraged at file scope.
- Prefer `#pragma once` over include guards for simplicity.
- Include what you use (IWYU). Do not rely on transitive includes.

### 2.4 Modern C++ Idioms

- Prefer `static_cast<>` and `reinterpret_cast<>` over C-style casts.
- Prefer `std::string_view` for read-only string parameters that do not need ownership.
- Use `auto` where the type is obvious from the RHS. Avoid `auto` when it obscures intent.
- Use range-based `for` loops. Prefer algorithms (`std::transform`, `std::find_if`) over
  raw loops when they improve clarity.
- Mark single-argument constructors `explicit`.
- Mark overrides with `override` (never repeat `virtual` on overrides).

### 2.5 Language

All code, comments, identifiers, commit messages, and documentation **must** be in English.

---

## 3. Memory Management (RAII)

### 3.1 Smart Pointers

- `std::unique_ptr` for exclusive ownership. This is the default.
- `std::shared_ptr` only when ownership is genuinely shared (document why).
- **Zero** raw `new` / `delete` outside of Qt parent-child managed widgets.

### 3.2 C Resource Wrappers

Every C resource (pcap handle, file descriptor, socket) **must** be wrapped in an RAII
type using `std::unique_ptr` with a custom deleter:

```cpp
struct PcapDeleter {
    void operator()(pcap_t* p) const noexcept {
        if (p) pcap_close(p);
    }
};
using PcapHandle = std::unique_ptr<pcap_t, PcapDeleter>;

struct PcapDumperDeleter {
    void operator()(pcap_dumper_t* d) const noexcept {
        if (d) pcap_dump_close(d);
    }
};
using PcapDumper = std::unique_ptr<pcap_dumper_t, PcapDumperDeleter>;
```

### 3.3 Rule of Five / Zero

- Prefer **Rule of Zero**: let compiler-generated special members handle resource
  management via smart pointers and RAII containers.
- If a class must manage a resource manually, implement all five special members
  (destructor, copy/move constructors, copy/move assignment) or `= delete` the ones
  that do not apply.

---

## 4. Concurrency

### 4.1 Threading Model

- Use the **QThread + worker object** pattern: create a `QObject`-derived worker,
  `moveToThread()`, connect signals/slots. Do **not** subclass `QThread` and override
  `run()`.
- For non-Qt threads, use `std::jthread` (C++20) or `std::thread` + RAII join wrapper.

### 4.2 Shared State

- **Never** share mutable state between threads without synchronization.
- Use `std::mutex` + `std::lock_guard` (or `std::scoped_lock`) for protecting shared
  containers.
- Use `std::atomic<>` for simple flags and counters.
- Prefer message-passing (Qt signals across threads with `Qt::QueuedConnection`) over
  shared memory.

### 4.3 Global State

- **No** mutable global variables. Period.
- If a truly singleton service is needed (logger, config), use the Meyers singleton
  pattern with `std::call_once` or C++11 thread-safe static initialization.

---

## 5. Design Patterns

Use the following patterns where indicated. Do not over-engineer: apply a pattern only
when it solves a real problem.

### 5.1 Strategy

Use for interchangeable algorithms sharing a common interface.

**Where**: protocol parsers (TCP, UDP, ICMP), filter generation backends, ML inference
backends.

```cpp
class IProtocolParser {
public:
    virtual ~IProtocolParser() = default;
    virtual void parse(const uint8_t* data, size_t len, PacketInfo& out) = 0;
};
```

### 5.2 Observer

Qt signals/slots **are** the Observer pattern. Formalize by:
- Emitting domain-meaningful signals (`captureStarted`, `packetReceived`, `analysisDone`).
- Connecting across thread boundaries with `Qt::QueuedConnection`.

### 5.3 Factory Method

Use to create platform-specific implementations without exposing concrete types.

```cpp
std::unique_ptr<IPacketCapture> createCaptureBackend();
// Returns PcapCapture on Linux/macOS, NpcapCapture on Windows.
```

### 5.4 RAII Wrapper

Covered in Section 3. Apply to every external C resource.

### 5.5 Builder

Use for constructing complex objects step by step when constructor parameter lists grow.

**Where**: `PacketFilter` construction, report formatting.

```cpp
auto filter = FilterBuilder()
    .protocol("TCP")
    .sourceIp("192.168.1.0/24")
    .destinationPort(443)
    .build();
```

### 5.6 Repository

Use to abstract data storage/retrieval behind an interface.

**Where**: ML analysis results (replaces raw `std::vector<std::string>` global).

```cpp
class IAnalysisRepository {
public:
    virtual ~IAnalysisRepository() = default;
    virtual void store(size_t packetIndex, AttackType type) = 0;
    [[nodiscard]] virtual AttackType get(size_t packetIndex) const = 0;
    [[nodiscard]] virtual size_t size() const noexcept = 0;
};
```

### 5.7 Command

Use for encapsulating operations that can be undone, queued, or logged.

**Where**: capture start/stop/pause, filter application.

---

## 6. Error Handling

### 6.1 Return Types

- Use `std::optional<T>` for functions that may not return a value.
- Use `std::expected<T, E>` (C++23) or a polyfill (`tl::expected`) for operations that
  can fail with a meaningful error.
- Reserve exceptions for truly exceptional, unrecoverable situations (out of memory,
  corrupted state).

### 6.2 Logging

- Use **spdlog** as the project-wide logging library.
- Log levels: `trace`, `debug`, `info`, `warn`, `error`, `critical`.
- **Never** use `std::cout` / `std::cerr` for diagnostic output.
- Format: `[YYYY-MM-DD HH:MM:SS.mmm] [level] [logger] message`

### 6.3 Return Value Discipline

- **Never** ignore the return value of a function that can fail.
- Mark functions whose return value must be checked with `[[nodiscard]]`.
- `system()` is **banned**. Use `QProcess` or `std::filesystem` instead.

---

## 7. Platform Abstraction

### 7.1 Conditional Compilation

- Platform `#ifdef` blocks belong **only** in implementation files (`.cpp`) inside
  `infra/platform/`.
- Headers in `core/` and `app/` must be platform-agnostic.

### 7.2 Portable Types

| Avoid | Use instead |
|-------|-------------|
| `u_char` | `std::uint8_t` |
| `u_int` | `std::uint32_t` |
| POSIX `struct ip` | custom `nids::IPv4Header` or portable alias |
| `system("rm ...")` | `std::filesystem::remove()` |
| `system("./script.sh")` | `QProcess` |

### 7.3 Network Headers

All OS-specific network includes are centralized in a single header:

```cpp
// infra/platform/NetworkHeaders.h
#pragma once
#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <arpa/inet.h>
    #include <netinet/if_ether.h>
#endif
```

### 7.4 File Paths

- Use `std::filesystem::path` for all file path manipulation.
- Use `QStandardPaths` for platform-standard directories (app data, documents).
- Never hardcode path separators (`/` vs `\`).

---

## 8. Build System (CMake)

### 8.1 Modern CMake Practices

- Minimum version: `cmake_minimum_required(VERSION 3.20)`.
- Use **targets**, not global variables. Prefer `target_*` commands:
  `target_include_directories`, `target_link_libraries`, `target_compile_features`.
- Set `CMAKE_AUTOMOC ON` **before** defining targets.
- Do **not** list header files in `add_executable` / `add_library` -- they are
  discovered automatically by the build system via includes.

### 8.2 Dependency Management

- Use **vcpkg** in manifest mode (`vcpkg.json` at project root).
- All third-party dependencies must be declared in `vcpkg.json`.
- Pin dependency versions for reproducible builds.

### 8.3 Project Structure

```cmake
# Root CMakeLists.txt
cmake_minimum_required(VERSION 3.20)
project(NIDS VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

option(NIDS_BUILD_TESTS "Build unit tests" ON)
option(NIDS_BUILD_SERVER "Build headless server" OFF)

add_subdirectory(src)

if(NIDS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
```

### 8.4 Install and Packaging

- Define `install()` targets for the executable and model files.
- Configure CPack for generating `.deb`, `.rpm`, and NSIS installers.

---

## 9. Testing

### 9.1 Framework

- **GoogleTest** for unit tests, **GoogleMock** for mocking interfaces.
- Test files live in `tests/unit/` and `tests/integration/`.
- Naming: `test_ClassName.cpp`, test case names follow
  `TEST(ClassName, methodName_condition_expectedBehavior)`.

### 9.2 Coverage

- Target: **80%** line coverage for `core/` and `app/` layers.
- `infra/` and `ui/` layers tested via integration tests.

### 9.3 What to Test

- Every public method of every class in `core/`.
- Filter generation logic (`PacketFilter`, `FilterBuilder`).
- Service registry lookups.
- ML result mapping (attack type classification).
- Report generation output format.
- Edge cases: empty input, malformed packets, missing model file.

---

## 10. Version Control

### 10.1 Branch Strategy

- `main` -- stable, release-ready.
- `develop` -- integration branch.
- `feature/<name>` -- feature branches off `develop`.
- `fix/<name>` -- bugfix branches.

### 10.2 Commit Messages

Follow Conventional Commits:

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `build`, `ci`, `chore`.

### 10.3 Code Review

- Every PR must pass CI (build + tests + linter).
- At least one approval required before merge.
- Squash-merge feature branches into `develop`.

---

## 11. Documentation

- Public APIs documented with Doxygen-style `/** ... */` comments.
- Architecture decisions recorded in `docs/adr/` (Architecture Decision Records).
- User-facing documentation in `docs/` using Markdown.
- README.md kept up to date with build instructions for all platforms.

---

## 12. Security Considerations

- Never log sensitive data (passwords, tokens, full packet payloads in production).
- Validate all external input (pcap data, CSV files, model files).
- Run with minimum required privileges (drop root after opening raw sockets).
- Use AddressSanitizer (`-fsanitize=address`) and UBSan (`-fsanitize=undefined`) in
  debug builds.

---

## Quick Reference: Banned Patterns

| Banned | Replacement |
|--------|-------------|
| `using namespace std;` in headers | Fully qualified `std::` prefix |
| Raw `new` / `delete` | `std::make_unique`, `std::make_shared` |
| C-style casts `(type)expr` | `static_cast<type>(expr)` |
| `system()` calls | `QProcess`, `std::filesystem` |
| `std::cout` / `std::cerr` | `spdlog::info()`, `spdlog::error()` |
| Mutable global variables | Dependency injection, singleton services |
| `QThread` subclassing | Worker object + `moveToThread()` |
| Magic numbers / strings | Named constants, config files |
| `u_char` | `std::uint8_t` |
| Mixed language comments | English only |
