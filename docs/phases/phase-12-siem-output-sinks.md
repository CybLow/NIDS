# Phase 12: SIEM / OSSEC Output Sinks

> **Effort**: 4–5 weeks | **Dependencies**: None | **Risk**: Low
>
> **Goal**: Enable NIDS to forward detection alerts to enterprise SIEM, HIDS, and
> log management infrastructure using industry-standard formats and protocols.

---

## Motivation

NIDS currently produces `DetectionResult` objects consumed by the Qt UI and gRPC
`StreamDetections` RPC. In enterprise environments, alerts must also reach:

- **SIEM platforms** (Splunk, QRadar, Elastic SIEM, Microsoft Sentinel)
- **OSSEC / Wazuh** managers (host-based IDS/HIDS correlation)
- **Log aggregation** (Graylog, Fluentd, Logstash)
- **SOC dashboards** (TheHive, Cortex, SOAR platforms)

The existing `IOutputSink` interface (ADR-007) is designed for exactly this — pluggable
output backends that receive `DetectionResult` + `FlowInfo` and format/forward them.

---

## Architecture

### Layer placement

| Component | Layer | Rationale |
|-----------|-------|-----------|
| `IOutputSink` interface | `core/services/` | Already exists |
| `SyslogSink` | `infra/output/` | Platform-specific (UDP/TCP sockets) |
| `CefFormatter` | `infra/output/` | Format-specific (CEF string building) |
| `LeefFormatter` | `infra/output/` | Format-specific (LEEF string building) |
| `WazuhApiSink` | `infra/output/` | HTTP client to Wazuh REST API |
| `JsonFileSink` | `infra/output/` | Simple JSON-lines file output |
| `OutputSinkFactory` | `infra/output/` | Creates configured sink chain |
| `SinkChain` | `app/` | Fan-out to multiple sinks simultaneously |

### Data flow

```
DetectionResult + FlowInfo
        │
        ▼
┌──────────────┐
│  SinkChain   │ ──── fan-out to all configured sinks
│  (app/)      │
└──┬───┬───┬───┘
   │   │   │
   ▼   ▼   ▼
┌──────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
│Syslog│ │CEF/Syslog│ │WazuhAPI  │ │JsonFile  │ │gRPC      │
│Sink  │ │Sink      │ │Sink      │ │Sink      │ │StreamSink│
└──────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘
                                                  (existing)
```

---

## Component Specifications

### 12.1 — SyslogSink

**Purpose**: Forward alerts via syslog (RFC 5424) over UDP, TCP, or TLS.

**File**: `src/infra/output/SyslogSink.h`, `src/infra/output/SyslogSink.cpp`

```cpp
struct SyslogConfig {
    std::string host = "127.0.0.1";
    std::uint16_t port = 514;
    enum class Transport { Udp, Tcp, Tls } transport = Transport::Udp;
    enum class Facility { Local0 = 16, Local1, Local2, Local3,
                          Local4, Local5, Local6, Local7 } facility = Facility::Local0;
    std::string appName = "nids";
    std::string hostname;  // auto-detected if empty
};

class SyslogSink : public IOutputSink {
public:
    explicit SyslogSink(SyslogConfig config);
    ~SyslogSink() override;

    void write(const DetectionResult& result,
               const FlowInfo& flow) override;
    void flush() override;

private:
    [[nodiscard]] std::string formatRfc5424(
        const DetectionResult& result,
        const FlowInfo& flow) const;
    [[nodiscard]] int severityFromScore(float combinedScore) const noexcept;

    SyslogConfig config_;
    int socket_ = -1;  // wrapped in RAII via unique_ptr + custom deleter
};
```

**RFC 5424 message format**:
```
<PRI>1 TIMESTAMP HOSTNAME nids PID MSGID [nids@49999 srcIp="1.2.3.4"
 dstIp="5.6.7.8" srcPort="54321" dstPort="80" protocol="TCP"
 verdict="DDoS_UDP" confidence="0.95" combinedScore="0.87"
 detectionSource="Ensemble" sid="" yaraRule=""] MSG
```

**Structured data (SD-ELEMENT)**:
- `srcIp`, `dstIp`, `srcPort`, `dstPort`, `protocol` — flow 5-tuple
- `verdict` — final attack type classification
- `confidence` — ML confidence score
- `combinedScore` — hybrid combined score
- `detectionSource` — which detection layer triggered
- `tlMatches` — comma-separated TI feed names
- `ruleMatches` — comma-separated heuristic rule names
- `sid` — Snort SID (Phase 15, empty until then)
- `yaraRule` — YARA rule name (Phase 14, empty until then)

**Syslog severity mapping**:

| Combined score | Syslog severity | Name |
|----------------|-----------------|------|
| 0.0–0.3 | 6 | Informational |
| 0.3–0.5 | 5 | Notice |
| 0.5–0.7 | 4 | Warning |
| 0.7–0.85 | 3 | Error |
| 0.85–1.0 | 2 | Critical |

### 12.2 — CefFormatter

**Purpose**: Format `DetectionResult` as ArcSight Common Event Format (CEF).

**File**: `src/infra/output/CefFormatter.h`, `src/infra/output/CefFormatter.cpp`

CEF format: `CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension`

```cpp
class CefFormatter {
public:
    [[nodiscard]] std::string format(
        const DetectionResult& result,
        const FlowInfo& flow) const;

private:
    [[nodiscard]] int cefSeverity(float combinedScore) const noexcept;
    [[nodiscard]] std::string escapeField(std::string_view value) const;
    [[nodiscard]] std::string escapeExtension(std::string_view value) const;
};
```

**CEF field mapping**:

| CEF field | Value |
|-----------|-------|
| Vendor | `NIDS` |
| Product | `NIDS` |
| Version | `0.2.0` (from CMake version) |
| SignatureID | `NIDS-{detectionSource}-{attackTypeIndex}` |
| Name | `attackTypeToString(finalVerdict)` |
| Severity | 0–10 (mapped from combinedScore) |
| `src` | Source IP |
| `dst` | Destination IP |
| `spt` | Source port |
| `dpt` | Destination port |
| `proto` | Protocol number |
| `cs1` / `cs1Label` | ML confidence / "mlConfidence" |
| `cs2` / `cs2Label` | Detection source / "detectionSource" |
| `cs3` / `cs3Label` | TI feed matches / "threatIntelFeeds" |
| `cs4` / `cs4Label` | Heuristic rule names / "heuristicRules" |
| `cn1` / `cn1Label` | Combined score (×100) / "combinedScore" |
| `msg` | Human-readable summary |

**Example output**:
```
CEF:0|NIDS|NIDS|0.2.0|NIDS-Ensemble-6|DDoS UDP|8|src=10.0.0.1 dst=192.168.1.100
 spt=54321 dpt=80 proto=17 cs1=0.95 cs1Label=mlConfidence
 cs2=Ensemble cs2Label=detectionSource msg=DDoS UDP detected with 95% ML confidence
```

### 12.3 — LeefFormatter

**Purpose**: Format as IBM QRadar LEEF (Log Event Extended Format).

**File**: `src/infra/output/LeefFormatter.h`, `src/infra/output/LeefFormatter.cpp`

LEEF format: `LEEF:2.0|Vendor|Product|Version|EventID|<tab-separated key=value pairs>`

```cpp
class LeefFormatter {
public:
    [[nodiscard]] std::string format(
        const DetectionResult& result,
        const FlowInfo& flow) const;
};
```

**LEEF field mapping**:

| LEEF field | Value |
|-----------|-------|
| `src` | Source IP |
| `dst` | Destination IP |
| `srcPort` | Source port |
| `dstPort` | Destination port |
| `proto` | Protocol name |
| `sev` | Severity (1–10) |
| `cat` | Attack category |
| `reason` | Detection summary |

### 12.4 — WazuhApiSink

**Purpose**: Forward alerts to Wazuh manager via REST API.

**File**: `src/infra/output/WazuhApiSink.h`, `src/infra/output/WazuhApiSink.cpp`

```cpp
struct WazuhConfig {
    std::string managerUrl = "https://localhost:55000";
    std::string username = "wazuh";
    std::string password;        // from env var or config file
    bool verifySsl = true;
    int timeoutMs = 5000;
    int maxRetries = 3;
};

class WazuhApiSink : public IOutputSink {
public:
    explicit WazuhApiSink(WazuhConfig config);

    void write(const DetectionResult& result,
               const FlowInfo& flow) override;
    void flush() override;

    [[nodiscard]] bool authenticate();

private:
    [[nodiscard]] std::string formatWazuhEvent(
        const DetectionResult& result,
        const FlowInfo& flow) const;

    WazuhConfig config_;
    std::string authToken_;
    std::chrono::steady_clock::time_point tokenExpiry_;
};
```

**Wazuh integration method**: POST to `/active-response` or use the Wazuh Syslog
collector (simpler — just point `SyslogSink` at the Wazuh agent).

**Recommended approach**: Use `SyslogSink` → Wazuh agent (syslog collector) as the
primary integration path. The `WazuhApiSink` is a direct-API alternative for
environments without a local Wazuh agent.

### 12.5 — JsonFileSink

**Purpose**: Write JSON-lines (JSONL) to a file for offline analysis, archival,
or ingestion by log shippers (Filebeat, Fluentd).

**File**: `src/infra/output/JsonFileSink.h`, `src/infra/output/JsonFileSink.cpp`

```cpp
struct JsonFileConfig {
    std::filesystem::path outputPath = "nids_alerts.jsonl";
    bool pretty = false;         // compact by default for JSONL
    bool appendMode = true;      // append to existing file
    std::size_t maxFileSize = 100 * 1024 * 1024;  // 100 MB rotation threshold
    int maxFiles = 5;            // keep 5 rotated files
};

class JsonFileSink : public IOutputSink {
public:
    explicit JsonFileSink(JsonFileConfig config);

    void write(const DetectionResult& result,
               const FlowInfo& flow) override;
    void flush() override;

private:
    [[nodiscard]] std::string toJson(
        const DetectionResult& result,
        const FlowInfo& flow) const;
    void rotateIfNeeded();

    JsonFileConfig config_;
    std::ofstream file_;
    std::size_t currentSize_ = 0;
};
```

**JSON schema (one line per alert)**:
```json
{
  "timestamp": "2026-03-17T01:23:45.678Z",
  "flow": {
    "srcIp": "10.0.0.1", "dstIp": "192.168.1.100",
    "srcPort": 54321, "dstPort": 80,
    "protocol": 6, "protocolName": "TCP",
    "packetCount": 1523, "byteCount": 892451,
    "durationMs": 12340
  },
  "detection": {
    "finalVerdict": "DDoS_UDP",
    "combinedScore": 0.87,
    "detectionSource": "Ensemble",
    "ml": { "classification": "DDoS_UDP", "confidence": 0.95, "probabilities": [...] },
    "threatIntel": [{ "ip": "10.0.0.1", "feed": "abuse.ch", "direction": "source" }],
    "heuristicRules": [{ "name": "high_packet_rate", "severity": 0.5 }],
    "signatures": [],
    "yaraMatches": []
  }
}
```

### 12.6 — SinkChain (fan-out)

**Purpose**: Distribute each `DetectionResult` to multiple output sinks simultaneously.

**File**: `src/app/SinkChain.h`, `src/app/SinkChain.cpp`

```cpp
class SinkChain : public IOutputSink {
public:
    void addSink(std::unique_ptr<IOutputSink> sink);
    void addSink(std::shared_ptr<IOutputSink> sink);  // for shared sinks (gRPC)

    void write(const DetectionResult& result,
               const FlowInfo& flow) override;
    void flush() override;

    [[nodiscard]] std::size_t sinkCount() const noexcept;

private:
    std::vector<std::unique_ptr<IOutputSink>> ownedSinks_;
    std::vector<std::weak_ptr<IOutputSink>> sharedSinks_;
};
```

### 12.7 — OutputSinkFactory

**Purpose**: Create and configure sink chains from configuration.

**File**: `src/infra/output/OutputSinkFactory.h`, `src/infra/output/OutputSinkFactory.cpp`

```cpp
class OutputSinkFactory {
public:
    [[nodiscard]] static std::unique_ptr<SinkChain> createFromConfig(
        const Configuration& config);
};
```

Configuration section in JSON:
```json
{
  "output": {
    "syslog": {
      "enabled": true,
      "host": "10.0.0.50",
      "port": 514,
      "transport": "tcp",
      "facility": "local0",
      "format": "cef"
    },
    "jsonFile": {
      "enabled": true,
      "path": "/var/log/nids/alerts.jsonl",
      "maxSizeMb": 100,
      "maxFiles": 5
    },
    "wazuh": {
      "enabled": false,
      "managerUrl": "https://wazuh-manager:55000",
      "username": "nids_reporter"
    },
    "console": {
      "enabled": true
    }
  }
}
```

---

## Configuration Changes

Add to `Configuration`:

```cpp
// -- Output Sinks --

struct SyslogOutputConfig {
    bool enabled = false;
    std::string host = "127.0.0.1";
    std::uint16_t port = 514;
    std::string transport = "udp";  // "udp", "tcp", "tls"
    std::string facility = "local0";
    std::string format = "rfc5424";  // "rfc5424", "cef", "leef"
};

struct JsonFileOutputConfig {
    bool enabled = false;
    std::filesystem::path path = "nids_alerts.jsonl";
    std::size_t maxSizeMb = 100;
    int maxFiles = 5;
};

struct WazuhOutputConfig {
    bool enabled = false;
    std::string managerUrl;
    std::string username;
    // password from env var NIDS_WAZUH_PASSWORD
};

[[nodiscard]] const SyslogOutputConfig& syslogConfig() const noexcept;
[[nodiscard]] const JsonFileOutputConfig& jsonFileConfig() const noexcept;
[[nodiscard]] const WazuhOutputConfig& wazuhConfig() const noexcept;
```

---

## Testing Plan

| Test file | Tests | Coverage |
|-----------|-------|----------|
| `test_SyslogSink.cpp` | RFC 5424 formatting, severity mapping, structured data escaping, socket error handling | 15+ |
| `test_CefFormatter.cpp` | CEF field mapping, severity scaling, field escaping, special characters | 10+ |
| `test_LeefFormatter.cpp` | LEEF formatting, field mapping | 8+ |
| `test_JsonFileSink.cpp` | JSON schema validation, file rotation, append mode, flush behavior | 12+ |
| `test_SinkChain.cpp` | Fan-out to multiple sinks, error isolation, empty chain | 8+ |
| `test_OutputSinkFactory.cpp` | Configuration parsing, sink creation, partial config | 6+ |

**Integration tests**: Send alerts to a local syslog server (netcat), verify format.

---

## Dependencies

| Library | Purpose | Required? |
|---------|---------|-----------|
| None (new) | Syslog uses POSIX sockets / Winsock | N/A |
| nlohmann_json | JSON formatting (already in project) | Already available |
| (Optional) libcurl | Wazuh REST API calls | Conan `libcurl/8.x` or system |

The Wazuh API sink is the only component that may need a new dependency (libcurl or
cpp-httplib). Alternative: shell out to `curl` via `QProcess` — but this violates
AGENTS.md (`system()` is banned). Better to use a header-only HTTP library or
the simpler syslog-to-Wazuh-agent path.

**Recommendation**: Implement `SyslogSink` + `CefFormatter` + `JsonFileSink` first
(zero new dependencies). `WazuhApiSink` can come later if direct API integration
is needed.

---

## Milestones

| Week | Deliverable |
|------|-------------|
| 1 | `SyslogSink` + RFC 5424 formatting + unit tests |
| 2 | `CefFormatter` + `LeefFormatter` + unit tests |
| 3 | `JsonFileSink` with rotation + `SinkChain` + unit tests |
| 4 | `OutputSinkFactory` + configuration parsing + integration with `LiveDetectionPipeline` and `server_main.cpp` |
| 5 | `WazuhApiSink` (optional) + integration tests + documentation |

---

## Implementation Status

> **Status**: Core implementation complete. WazuhApiSink deferred (requires libcurl dependency).

### Completed Components

| Component | Header | Implementation | Tests | Status |
|-----------|--------|----------------|-------|--------|
| `CefFormatter` | `infra/output/CefFormatter.h` | `infra/output/CefFormatter.cpp` | 10 tests | Done |
| `LeefFormatter` | `infra/output/LeefFormatter.h` | `infra/output/LeefFormatter.cpp` | 9 tests | Done |
| `SyslogSink` | `infra/output/SyslogSink.h` | `infra/output/SyslogSink.cpp` | 13 tests | Done |
| `JsonFileSink` | `infra/output/JsonFileSink.h` | `infra/output/JsonFileSink.cpp` | 12 tests | Done |
| `SinkChain` | `app/SinkChain.h` | `app/SinkChain.cpp` | 12 tests | Done |
| `OutputSinkFactory` | `app/OutputSinkFactory.h` | `app/OutputSinkFactory.cpp` | — | Done |
| Configuration structs | `core/services/Configuration.h` | `core/services/Configuration.cpp` | — | Done |
| ConfigLoader output section | `infra/config/ConfigLoader.cpp` | — | — | Done |

### Test Results

- **56 new tests** across 5 test suites (CefFormatter, LeefFormatter, SyslogSink, JsonFileSink, SinkChain)
- **479 total tests** passing (zero regressions)
- Build: clean (0 warnings, 0 errors)

### Architecture Notes

- `OutputSinkFactory` lives in `app/` (not `infra/`) to avoid circular dependency
  (`nids_app` depends on `nids_infra`, so the factory that creates infra sinks and
  assembles them into an app-layer `SinkChain` belongs in `app/`).
- `SinkChain` supports both owned (`unique_ptr`) and non-owned (raw pointer) sinks,
  enabling the gRPC `StreamSink` (owned by the server) to be added without ownership transfer.
- Error isolation: if one sink throws in `onFlowResult()`, the remaining sinks still receive the result.

### Deferred

- **WazuhApiSink**: Requires `libcurl` or `cpp-httplib` dependency. Recommended path:
  use `SyslogSink` pointed at Wazuh agent's syslog collector instead.
- **Server wiring**: `OutputSinkFactory::createFromConfig()` is ready to be called from
  `server_main.cpp` and `HeadlessCaptureRunner` — integration deferred to next PR to
  keep this PR focused on sink implementations.
