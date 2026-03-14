# ADR-006: Migrate from raw libpcap to PcapPlusPlus

## Status

Accepted (2026-03-14)

## Context

The NIDS project used raw `libpcap` (C API) for packet capture and parsing. This
required:
- Manual RAII wrappers (`PcapHandle`, `PcapDumper`) around `pcap_t*` and
  `pcap_dumper_t*`
- Custom `NetworkHeaders.h` with OS-specific `#ifdef` blocks for packet header structs
  (`struct ip`, `struct tcphdr`, etc.)
- `reinterpret_cast` to parse raw packet bytes into protocol headers
- Platform-specific include paths and `FindPCAP.cmake` module
- C++23 compilation mode caused build failures with libpcap headers on some platforms

PcapPlusPlus (v25.05) is a modern C++ wrapper around libpcap/WinPcap/Npcap that
provides typed layer classes, built-in RAII device management, and cross-platform
compatibility.

## Decision

Replace all raw libpcap usage with PcapPlusPlus:
- `pcap_t*` + `PcapHandle` → `pcpp::PcapLiveDevice` (RAII, no manual wrapper needed)
- `pcap_dumper_t*` + `PcapDumper` → `pcpp::PcapFileWriterDevice` (RAII)
- `pcap_open_offline()` → `pcpp::PcapFileReaderDevice`
- `struct ip` / `struct tcphdr` / `reinterpret_cast` → `pcpp::IPv4Layer`,
  `pcpp::TcpLayer`, `pcpp::UdpLayer`, `pcpp::IcmpLayer` (typed accessors)
- System libpcap dependency → Conan 2 managed PcapPlusPlus package

## Consequences

### Positive
- **Eliminated platform `#ifdef` blocks** for network header parsing
- **Removed `reinterpret_cast`** for packet headers — type-safe layer accessors instead
- **Removed manual RAII wrappers** (`PcapHandle.h`, `PcapDumper`) — PcapPlusPlus
  devices handle resource cleanup
- **Removed `NetworkHeaders.h`** — no OS-specific header struct definitions needed
- **Removed `FindPCAP.cmake`** — PcapPlusPlus is managed via Conan with CMake targets
- **VLAN (802.1Q) parsing** handled automatically by PcapPlusPlus packet parser
- **Cross-platform consistency** — same API on Linux (libpcap), Windows (Npcap), macOS

### Negative
- PcapPlusPlus 24.09 does not compile under C++23 (GCC 14/15) due to deprecated
  `<cstdint>` usage in headers. Requires PcapPlusPlus >= 25.05 (unreleased at time of
  decision, built from source via Conan).
- `OnPacketArrivesCallback` still uses `void*` for user data — imposed by the
  PcapPlusPlus API, cannot be changed to a typed pointer.
- `getLayerOfType<T>()` returns non-const `T*` even from a `const Packet&` — a
  PcapPlusPlus design choice that requires care with const-correctness.

### Files changed
- `src/infra/capture/PcapCapture.h/.cpp` — rewritten to use PcapPlusPlus devices
- `src/infra/flow/NativeFlowExtractor.h/.cpp` — rewritten packet parsing
- `CMakeLists.txt` — `find_package(PcapPlusPlus)` replaces `find_package(PCAP)`
- `conanfile.py` — added `pcapplusplus/25.05` dependency
- Deleted: `PcapHandle.h`, `NetworkHeaders.h`, `cmake/FindPCAP.cmake`
