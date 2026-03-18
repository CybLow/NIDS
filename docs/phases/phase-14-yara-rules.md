# Phase 14: YARA Rules Integration

> **Effort**: 6–8 weeks | **Dependencies**: libyara 4.x | **Risk**: Medium
>
> **Goal**: Add content/pattern scanning to the hybrid detection pipeline using
> YARA rules for malware signature detection, protocol anomaly matching, and
> threat indicator pattern recognition in packet payloads and reassembled streams.

---

## Motivation

YARA is the de facto standard for pattern-based malware classification. While the
NIDS ML classifier detects statistical flow anomalies, YARA complements it by
detecting **specific byte patterns** in packet payloads:

- **Malware C2 beacons**: Known command-and-control communication patterns
- **Exploit payloads**: Shellcode, ROP chains, known exploit signatures
- **Protocol anomalies**: Malformed headers, unusual encoding
- **Data exfiltration indicators**: Base64-encoded sensitive data patterns
- **Specific tool signatures**: Metasploit, Cobalt Strike, Mimikatz patterns

### Why YARA instead of (or alongside) Snort rules?

| YARA | Snort rules |
|------|-------------|
| Buffer/file-oriented scanning | Packet/stream-oriented matching |
| Rich condition logic (Boolean, math, counting) | Simpler content+PCRE matching |
| Designed for malware classification | Designed for network protocol detection |
| Single library (libyara) | Requires Aho-Corasick + PCRE + flow state |
| Works on reassembled streams naturally | Protocol-aware (flow direction, state) |
| Community rules (YARA-Rules, Malpedia, YARA-Forge) | Community rules (ET Open, Snort Community) |

Both are valuable. YARA is simpler to integrate and provides immediate value for
malware/C2 detection. Snort rules (Phase 15) add deeper protocol-aware matching.

---

## Architecture

### Layer placement

| Component | Layer | Rationale |
|-----------|-------|-----------|
| `IContentScanner` | `core/services/` | Interface — no platform deps |
| `ContentMatch` | `core/model/` | Match result model — pure C++ |
| `YaraScanner` | `infra/rules/` | libyara wrapper — platform dep |
| `TcpReassembler` | `infra/flow/` | PcapPlusPlus dep |
| YARA rule files | `data/yara/` | Bundled + user-configurable |

### Data flow

```
                    Per-packet path (fast, shallow)
                    ┌──────────────────────────────┐
Raw Packet ────────▶│ YaraScanner::scanPacket()    │──▶ ContentMatch
                    └──────────────────────────────┘
                                                        │
                    Per-flow path (deeper)               │
                    ┌──────────────────────────────┐    │
TCP Stream ────────▶│ TcpReassembler               │    │
(reassembled) ──────│  → YaraScanner::scanStream() │──▶ ContentMatch
                    └──────────────────────────────┘    │
                                                        ▼
                                              ┌──────────────────┐
                                              │ HybridDetection  │
                                              │ Service          │
                                              │ (5-layer eval)   │
                                              └──────────────────┘
```

---

## Component Specifications

### 14.1 — IContentScanner Interface

**File**: `src/core/services/IContentScanner.h`

```cpp
#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace nids::core {

/// Result of a content scan match.
struct ContentMatch {
    std::string ruleName;       ///< YARA rule identifier
    std::string ruleNamespace;  ///< YARA namespace (e.g., "malware", "c2")
    std::string description;    ///< Rule description from meta
    float severity = 0.0f;      ///< Severity from meta (0.0-1.0)

    /// Individual string matches within the rule
    struct StringMatch {
        std::string identifier;  ///< String identifier (e.g., "$beacon")
        std::size_t offset;      ///< Byte offset in the scanned data
        std::size_t length;      ///< Length of the match
    };
    std::vector<StringMatch> strings;

    /// Rule metadata key-value pairs
    std::vector<std::pair<std::string, std::string>> metadata;
};

/// Interface for content/pattern scanning engines.
class IContentScanner {
public:
    virtual ~IContentScanner() = default;

    /// Load YARA rules from a file or directory.
    [[nodiscard]] virtual bool loadRules(
        const std::filesystem::path& path) = 0;

    /// Reload all previously loaded rules (hot reload).
    [[nodiscard]] virtual bool reloadRules() = 0;

    /// Scan a buffer (packet payload or reassembled stream).
    [[nodiscard]] virtual std::vector<ContentMatch> scan(
        std::span<const std::uint8_t> data) = 0;

    /// Number of loaded rules.
    [[nodiscard]] virtual std::size_t ruleCount() const noexcept = 0;

    /// Number of loaded rule files.
    [[nodiscard]] virtual std::size_t fileCount() const noexcept = 0;
};

} // namespace nids::core
```

### 14.2 — YaraScanner (libyara RAII Wrapper)

**Files**: `src/infra/rules/YaraScanner.h`, `src/infra/rules/YaraScanner.cpp`

```cpp
#pragma once

#include "core/services/IContentScanner.h"

#include <filesystem>
#include <memory>
#include <mutex>
#include <vector>

// Forward declarations (avoid exposing yara.h in header)
struct YR_RULES;
struct YR_COMPILER;

namespace nids::infra {

class YaraScanner : public core::IContentScanner {
public:
    YaraScanner();
    ~YaraScanner() override;

    // Non-copyable (YARA state is not copyable)
    YaraScanner(const YaraScanner&) = delete;
    YaraScanner& operator=(const YaraScanner&) = delete;
    YaraScanner(YaraScanner&&) noexcept;
    YaraScanner& operator=(YaraScanner&&) noexcept;

    [[nodiscard]] bool loadRules(
        const std::filesystem::path& path) override;

    [[nodiscard]] bool reloadRules() override;

    [[nodiscard]] std::vector<core::ContentMatch> scan(
        std::span<const std::uint8_t> data) override;

    [[nodiscard]] std::size_t ruleCount() const noexcept override;
    [[nodiscard]] std::size_t fileCount() const noexcept override;

    /// Scan with a timeout (milliseconds). 0 = no timeout.
    [[nodiscard]] std::vector<core::ContentMatch> scan(
        std::span<const std::uint8_t> data,
        int timeoutMs);

private:
    /// RAII wrapper for yr_initialize() / yr_finalize()
    struct YaraGlobalInit {
        YaraGlobalInit();
        ~YaraGlobalInit();
    };
    static YaraGlobalInit& globalInit();

    /// Compile rules from loaded paths
    [[nodiscard]] bool compileRules();

    /// libyara scan callback (static, forwarded to instance)
    static int scanCallback(YR_SCAN_CONTEXT* context,
                            int message,
                            void* messageData,
                            void* userData);

    /// Collected rule file paths
    std::vector<std::filesystem::path> rulePaths_;

    /// Compiled YARA rules (RAII via custom deleter)
    struct RulesDeleter {
        void operator()(YR_RULES* rules) const noexcept;
    };
    std::unique_ptr<YR_RULES, RulesDeleter> rules_;

    /// Mutex for thread-safe scanning (yr_rules_scan_mem is thread-safe
    /// per YR_RULES instance, but compilation requires synchronization)
    mutable std::mutex mutex_;
};

} // namespace nids::infra
```

**Implementation details**:

```cpp
// YaraScanner.cpp — key implementation notes

// Global init (Meyers singleton — thread-safe, called once)
YaraScanner::YaraGlobalInit& YaraScanner::globalInit() {
    static YaraGlobalInit init;
    return init;
}

YaraScanner::YaraGlobalInit::YaraGlobalInit() {
    int result = yr_initialize();
    if (result != ERROR_SUCCESS) {
        spdlog::critical("yr_initialize() failed: {}", result);
    }
}

YaraScanner::YaraGlobalInit::~YaraGlobalInit() {
    yr_finalize();
}

// Scan callback — called by libyara for each rule match
int YaraScanner::scanCallback(YR_SCAN_CONTEXT* context,
                               int message,
                               void* messageData,
                               void* userData) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* results = static_cast<std::vector<ContentMatch>*>(userData);
        auto* rule = static_cast<YR_RULE*>(messageData);

        ContentMatch match;
        match.ruleName = rule->identifier;
        match.ruleNamespace = rule->ns->name;

        // Extract metadata
        YR_META* meta;
        yr_rule_metas_foreach(rule, meta) {
            if (meta->type == META_TYPE_STRING) {
                match.metadata.emplace_back(meta->identifier,
                                             meta->string);
                if (std::string_view{meta->identifier} == "description")
                    match.description = meta->string;
                if (std::string_view{meta->identifier} == "severity")
                    match.severity = std::stof(meta->string);
            }
        }

        // Extract string matches
        YR_STRING* string;
        yr_rule_strings_foreach(rule, string) {
            YR_MATCH* m;
            yr_string_matches_foreach(context, string, m) {
                match.strings.push_back({
                    .identifier = string->identifier,
                    .offset = static_cast<std::size_t>(m->offset),
                    .length = static_cast<std::size_t>(m->match_length),
                });
            }
        }

        results->push_back(std::move(match));
    }
    return CALLBACK_CONTINUE;
}
```

### 14.3 — TcpReassembler

**Purpose**: Reassemble TCP streams for deeper YARA scanning. Individual packet
payloads are small; reassembled streams provide the full application-layer data.

**Files**: `src/infra/flow/TcpReassembler.h`, `src/infra/flow/TcpReassembler.cpp`

```cpp
struct ReassemblyConfig {
    std::size_t maxStreamSize = 1 * 1024 * 1024;  // 1 MB per stream
    std::size_t maxConcurrentStreams = 10000;
    std::chrono::seconds streamTimeout{60};
};

/// Callback invoked when a TCP stream is complete or reaches maxStreamSize.
using StreamCallback = std::function<void(
    const FlowInfo& flow,
    std::span<const std::uint8_t> clientData,
    std::span<const std::uint8_t> serverData)>;

class TcpReassembler {
public:
    explicit TcpReassembler(ReassemblyConfig config = {});
    ~TcpReassembler();

    /// Set callback for completed/flushed streams
    void setCallback(StreamCallback cb);

    /// Feed a raw packet for reassembly
    void processPacket(const pcpp::RawPacket& packet);

    /// Flush all active streams (e.g., at end of capture)
    void flushAll();

    /// Reset all state
    void reset();

    /// Statistics
    [[nodiscard]] std::size_t activeStreams() const noexcept;
    [[nodiscard]] std::size_t completedStreams() const noexcept;
    [[nodiscard]] std::size_t memoryUsageBytes() const noexcept;

private:
    ReassemblyConfig config_;
    std::unique_ptr<pcpp::TcpReassembly> reassembly_;
    StreamCallback callback_;

    // PcapPlusPlus TcpReassembly callbacks
    static void onMessageReady(int side,
                                const pcpp::TcpStreamData& streamData,
                                void* userData);
    static void onConnectionStart(const pcpp::ConnectionData& connectionData,
                                   void* userData);
    static void onConnectionEnd(const pcpp::ConnectionData& connectionData,
                                 pcpp::TcpReassembly::ConnectionEndReason reason,
                                 void* userData);

    // Per-connection state
    struct StreamState {
        FlowInfo flow;
        std::vector<std::uint8_t> clientData;
        std::vector<std::uint8_t> serverData;
        std::size_t totalBytes = 0;
    };
    std::unordered_map<uint32_t, StreamState> streams_;
};
```

**Memory management**: Each stream is bounded by `maxStreamSize` (default 1 MB).
When exceeded, the stream is flushed early (YARA scans what's available). This
prevents memory exhaustion from long-lived connections.

**Integration with flow extractor**: `TcpReassembler` runs in parallel with
`NativeFlowExtractor`. Both receive the same packets but serve different purposes:
- `NativeFlowExtractor` computes 77 statistical features (header-only)
- `TcpReassembler` collects payload data for content scanning

### 14.4 — Pipeline Integration

Add YARA scanning to `LiveDetectionPipeline` and `AnalysisService`:

```
Raw Packet
    │
    ├──▶ NativeFlowExtractor (flow features → ML → HybridDetection)
    │                                                    ▲
    └──▶ TcpReassembler ──▶ YaraScanner ──▶ ContentMatch ─┘
```

**Per-packet quick scan**: For UDP and non-reassembled TCP, scan individual
packet payloads directly. Fast but shallow.

**Per-stream deep scan**: For reassembled TCP streams, scan the full stream
data. Deeper but requires buffering.

**Scoring integration**: `HybridDetectionService` gains a 5th layer:

```cpp
// Extended evaluation
DetectionResult evaluate(
    const PredictionResult& mlResult,
    const FlowInfo& flow,
    std::span<const ContentMatch> yaraMatches  // NEW parameter
);
```

YARA match severity contributes to the combined score:
```
combinedScore = w_ml * mlScore
              + w_ti * tiScore
              + w_rules * ruleScore
              + w_yara * maxYaraSeverity  // NEW
```

---

## YARA Rule Organization

### Directory structure

```
data/yara/
├── malware/
│   ├── c2_beacons.yar       # C2 communication patterns
│   ├── exploit_kits.yar     # Known exploit payloads
│   └── ransomware.yar       # Ransomware indicators
├── network/
│   ├── protocol_anomalies.yar  # Malformed headers
│   ├── tunneling.yar        # DNS tunneling, ICMP tunneling
│   └── exfiltration.yar     # Data exfil patterns
├── tools/
│   ├── metasploit.yar       # Metasploit signatures
│   ├── cobalt_strike.yar    # Cobalt Strike beacons
│   └── mimikatz.yar         # Mimikatz patterns
└── custom/
    └── user_rules.yar       # User-defined rules
```

### Rule writing conventions

All NIDS YARA rules should follow this template:

```yara
rule NIDS_Cobalt_Strike_Beacon : c2 beacon {
    meta:
        author = "NIDS Team"
        description = "Cobalt Strike HTTP beacon communication"
        severity = "0.9"
        reference = "https://attack.mitre.org/software/S0154/"
        created = "2026-03-17"
        category = "c2"

    strings:
        $beacon_header = { 00 00 BE EF }
        $ua = "Mozilla/5.0 (compatible; MSIE" nocase
        $sleep_mask = { 4C 8B 53 08 45 8B 0A 45 8B 52 04 }

    condition:
        $beacon_header at 0 or
        ($ua and $sleep_mask)
}
```

**Required meta fields**: `description`, `severity` (0.0-1.0), `category`

---

## Configuration Changes

Add to `Configuration`:

```cpp
struct YaraConfig {
    bool enabled = false;
    std::filesystem::path rulesDirectory = "data/yara";
    bool scanPackets = true;         // per-packet quick scan
    bool scanStreams = true;         // per-stream deep scan (requires TcpReassembler)
    int scanTimeoutMs = 10;          // per-scan timeout in milliseconds
    std::size_t maxStreamSizeBytes = 1 * 1024 * 1024;  // 1 MB max stream buffer
    std::size_t maxConcurrentStreams = 10000;
    bool hotReload = true;           // watch rules dir for changes
};
```

---

## Testing Plan

| Test file | Tests | Coverage |
|-----------|-------|----------|
| `test_YaraScanner.cpp` | Load rules, scan matching data, scan non-matching data, multiple rules, namespace, metadata extraction, string match offsets, timeout, empty data, invalid rules, hot reload | 20+ |
| `test_TcpReassembler.cpp` | Simple stream, out-of-order, retransmission, max size truncation, timeout, concurrent streams, flush, memory bounds | 15+ |
| `test_YaraIntegration.cpp` | End-to-end: capture → reassemble → scan → detect | 10+ |
| `test_ContentMatch.cpp` | Model struct validation, severity ranges | 5+ |

**Test YARA rules**: Create synthetic rules that match known test patterns:

```yara
// tests/data/test_rules.yar
rule NIDS_Test_Pattern {
    meta:
        description = "Test pattern for unit testing"
        severity = "0.5"
    strings:
        $test = "NIDS_TEST_PAYLOAD"
    condition:
        $test
}
```

---

## Dependencies

| Library | Purpose | Conan Package | License |
|---------|---------|---------------|---------|
| **libyara** | YARA rule compilation + scanning | `yara/4.5.2` | BSD-3-Clause |
| **OpenSSL** | Required by libyara crypto modules | Already available (via gRPC) | Apache-2.0 |

Add to `conanfile.py`:
```python
def requirements(self):
    # ... existing deps ...
    if self.options.get_safe("with_yara"):
        self.requires("yara/4.5.2")
```

CMake option:
```cmake
option(NIDS_ENABLE_YARA "Enable YARA content scanning" OFF)
```

---

## Performance Considerations

| Operation | Expected latency | Notes |
|-----------|-----------------|-------|
| Per-packet scan (small payload) | 10–50 μs | Fast, suitable for inline path |
| Per-stream scan (1 KB) | 50–200 μs | Typical HTTP request/response |
| Per-stream scan (100 KB) | 1–5 ms | Larger transfers |
| Per-stream scan (1 MB) | 5–20 ms | Max stream size, run on worker thread |
| Rule compilation (100 rules) | 50–200 ms | One-time at startup / hot reload |
| Rule compilation (1000 rules) | 500 ms–2 s | Larger rule sets |

**Threading**: YARA scanning runs on the `FlowAnalysisWorker` thread (for streams)
or a dedicated scan thread pool (for per-packet scanning in inline mode). Never
blocks the capture thread.

**Memory**: libyara uses ~10-50 MB for compiled rules (1000 rules). Stream buffers
add `maxConcurrentStreams × maxStreamSize` worst case (10 GB with defaults — but
most streams are much smaller than 1 MB).

---

## Community Rule Sources

| Source | Rules | Focus | URL |
|--------|-------|-------|-----|
| YARA-Rules (GitHub) | 500+ | Malware, packers, CVEs | github.com/Yara-Rules/rules |
| YARA-Forge | 2000+ | Curated malware signatures | yarahq.github.io |
| Malpedia | 1000+ | APT malware families | malpedia.caad.fkie.fraunhofer.de |
| Florian Roth (Neo23x0) | 3000+ | Threat hunting, web shells, tools | github.com/Neo23x0/signature-base |
| CAPE Sandbox | 1000+ | Malware behavioral patterns | github.com/kevoreilly/CAPEv2 |

---

## Milestones

| Week | Deliverable |
|------|-------------|
| 1 | `IContentScanner` interface + `ContentMatch` model |
| 2 | `YaraScanner` RAII wrapper + unit tests |
| 3 | `TcpReassembler` using PcapPlusPlus + unit tests |
| 4 | Pipeline integration (per-packet + per-stream scanning) |
| 5 | `HybridDetectionService` 5-layer evaluation + scoring |
| 6 | Bundled YARA rules (C2, exploits, tools) + hot reload |
| 7 | Configuration, gRPC extensions, CLI commands |
| 8 | Integration tests + documentation + performance benchmarks |

---

## Implementation Status

### Completed

| Component | Files | Status |
|-----------|-------|--------|
| **ContentMatch model** | `core/model/ContentMatch.h` | Done |
| **IContentScanner interface** | `core/services/IContentScanner.h` | Done |
| **DetectionSource enum** | Extended with `ContentScan`, `SignatureMatch` | Done |
| **DetectionResult** | Extended with `contentMatches`, `hasContentMatch()`, `maxContentSeverity()` | Done |
| **YaraConfig** | `Configuration.h` — enabled, rulesDir, scanPackets, scanStreams, timeout, weight | Done |
| **ConfigLoader** | YARA JSON section parsing | Done |
| **YaraScanner** | `infra/rules/YaraScanner.h/.cpp` — RAII libyara wrapper, compilation, scanning, metadata extraction, hot reload | Done (14 tests) |
| **TcpReassembler** | `infra/flow/TcpReassembler.h/.cpp` — PcapPlusPlus TCP reassembly with size limits | Done |
| **HybridDetectionService** | 5-layer evaluation with content scan weight and YARA escalation | Done |
| **CMake option** | `NIDS_ENABLE_YARA` — optional, off by default | Done |
| **CI setup** | `libyara-dev` installed in Linux CI | Done |
| **Test YARA rules** | `tests/data/test_rules.yar` — 4 test rules | Done |

### Test Coverage

| Test file | Tests |
|-----------|-------|
| `test_YaraScanner.cpp` | 14 (load, scan string/hex/multiple/empty/no-match, offsets, timeout, reload, metadata, directory, move) |
| `test_InterfaceDestructors.cpp` | +1 (IContentScanner) |
