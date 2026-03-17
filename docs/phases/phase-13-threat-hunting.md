# Phase 13: Threat Hunting Capabilities

> **Effort**: 6–8 weeks (minimal viable), 21–28 weeks (full) | **Dependencies**: SQLite or DuckDB | **Risk**: Medium
>
> **Goal**: Enable proactive, retroactive search for threats in historical network
> traffic — PCAP storage with rolling retention, flow metadata indexing, IOC
> retrospective search, retroactive ML analysis, and flow correlation.

---

## Motivation

Threat hunting is the proactive search for threats that evade automated detection.
Current NIDS detects threats in real-time but has no ability to:

1. **Record traffic** for later analysis (only the current capture session is stored)
2. **Re-analyze historical traffic** with updated rules, models, or threat intel
3. **Search for IOCs** (indicators of compromise) retroactively across past sessions
4. **Correlate flows** across time (same attacker IP, lateral movement patterns)
5. **Build incident timelines** from correlated events

These capabilities are essential for security operations (SOC) and incident response.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                      Threat Hunting System                       │
│                                                                  │
│  ┌────────────┐   ┌─────────────┐   ┌───────────────────┐      │
│  │ PcapRing   │   │ FlowIndex   │   │ HuntEngine        │      │
│  │ Buffer     │   │ (SQLite/    │   │ (app/)            │      │
│  │ (infra/)   │   │  DuckDB)    │   │                   │      │
│  │            │   │ (infra/)    │   │ - retroactive ML  │      │
│  │ Rolling    │   │             │   │ - IOC search      │      │
│  │ PCAP       │   │ Query by:   │   │ - flow correlation│      │
│  │ storage    │   │ - IP        │   │ - timeline build  │      │
│  │            │   │ - port      │   │                   │      │
│  │ Retention: │   │ - time range│   └───────────────────┘      │
│  │ - size     │   │ - protocol  │              │                │
│  │ - time     │   │ - verdict   │              ▼                │
│  └────────────┘   └─────────────┘   ┌───────────────────┐      │
│                                     │ HuntResult        │      │
│                                     │ (core/model/)     │      │
│                                     │                   │      │
│                                     │ - matched flows   │      │
│                                     │ - timeline events │      │
│                                     │ - evidence links  │      │
│                                     └───────────────────┘      │
└──────────────────────────────────────────────────────────────────┘
```

### Layer placement

| Component | Layer | Rationale |
|-----------|-------|-----------|
| `IPcapStore` | `core/services/` | Interface — no platform deps |
| `IFlowIndex` | `core/services/` | Interface for queryable flow metadata |
| `IHuntEngine` | `core/services/` | Interface for hunt operations |
| `HuntQuery` | `core/model/` | Query model (filters, time range, IOCs) |
| `HuntResult` | `core/model/` | Results model (matched flows, timeline) |
| `TimelineEvent` | `core/model/` | Single event in an incident timeline |
| `PcapRingBuffer` | `infra/storage/` | Rolling PCAP file management |
| `SqliteFlowIndex` | `infra/storage/` | SQLite-backed flow metadata index |
| `HuntEngine` | `app/` | Orchestrates retroactive analysis |
| `FlowCorrelator` | `app/` | Links related flows |
| `TimelineBuilder` | `app/` | Constructs chronological narratives |
| `StatisticalBaseline` | `app/` | Establishes "normal" traffic patterns |

---

## Component Specifications

### 13.1 — PcapRingBuffer (Rolling PCAP Storage)

**Purpose**: Store all captured packets in rolling PCAP files with configurable
retention by size and/or time. Oldest files are evicted when limits are reached.

**Files**: `src/infra/storage/PcapRingBuffer.h`, `src/infra/storage/PcapRingBuffer.cpp`

```cpp
struct PcapStorageConfig {
    std::filesystem::path storageDir = "/var/lib/nids/pcap";
    std::size_t maxTotalSizeBytes = 10ULL * 1024 * 1024 * 1024;  // 10 GB
    std::chrono::hours maxRetention{168};   // 7 days
    std::size_t maxFileSize = 100 * 1024 * 1024;  // 100 MB per file
    std::string filePrefix = "nids_capture";
};

class PcapRingBuffer : public IPcapStore {
public:
    explicit PcapRingBuffer(PcapStorageConfig config);
    ~PcapRingBuffer() override;

    /// Store a raw packet (called from capture thread — must be fast)
    void store(std::span<const std::uint8_t> packet,
               int64_t timestampUs) override;

    /// Query stored packets matching criteria
    [[nodiscard]] std::vector<StoredPacket> query(
        const HuntQuery& query) override;

    /// Current total storage usage in bytes
    [[nodiscard]] std::size_t sizeBytes() const noexcept override;

    /// Evict oldest files until under targetBytes
    void evict(std::size_t targetBytes) override;

    /// List all stored PCAP files with metadata
    [[nodiscard]] std::vector<PcapFileInfo> listFiles() const;

private:
    void rotateFile();
    void evictExpired();
    [[nodiscard]] std::filesystem::path currentFilePath() const;

    PcapStorageConfig config_;
    std::unique_ptr<pcpp::PcapFileWriterDevice> currentWriter_;
    std::size_t currentFileSize_ = 0;
    int fileIndex_ = 0;
    mutable std::mutex mutex_;
};
```

**File naming**: `nids_capture_20260317_012345_000.pcap` (date_time_sequence)

**Retention policies**:

| Policy | Description | Default |
|--------|-------------|---------|
| Size-based | Evict oldest files when total size exceeds limit | 10 GB |
| Time-based | Evict files older than retention window | 7 days |
| Combined | Both policies apply (whichever triggers first) | Both active |

**Performance considerations**:
- `store()` is called from the capture thread — must not block
- Use PcapPlusPlus `PcapFileWriterDevice` for pcap writing (already RAII)
- File rotation happens when a file reaches `maxFileSize`
- Eviction runs after each rotation (not on every packet)

**Storage math** at common traffic rates:

| Traffic rate | Per hour | Per day | 10 GB retention |
|-------------|----------|---------|-----------------|
| 10 Mbps | 4.5 GB | 108 GB | ~2.2 hours |
| 100 Mbps | 45 GB | 1.08 TB | ~13 minutes |
| 1 Gbps | 450 GB | 10.8 TB | ~80 seconds |
| 10 Mbps (typical home) | 4.5 GB | 108 GB | ~53 hours |

For high-speed networks, storage must be sized appropriately. The default 10 GB
is suitable for lab/home use. Enterprise deployments should use dedicated storage.

### 13.2 — SqliteFlowIndex (Flow Metadata Database)

**Purpose**: Index flow metadata for fast historical queries without scanning PCAPs.

**Files**: `src/infra/storage/SqliteFlowIndex.h`, `src/infra/storage/SqliteFlowIndex.cpp`

```cpp
class SqliteFlowIndex : public IFlowIndex {
public:
    explicit SqliteFlowIndex(const std::filesystem::path& dbPath);
    ~SqliteFlowIndex() override;

    /// Index a completed flow with its detection result
    void index(const FlowInfo& flow,
               const DetectionResult& result,
               std::string_view pcapFile,
               std::size_t pcapOffset) override;

    /// Query flows matching criteria
    [[nodiscard]] std::vector<IndexedFlow> query(
        const FlowQuery& query) override;

    /// Count flows matching criteria (faster than full query)
    [[nodiscard]] std::size_t count(
        const FlowQuery& query) const override;

    /// Get distinct values for a field (for autocomplete/filters)
    [[nodiscard]] std::vector<std::string> distinctValues(
        std::string_view field,
        std::size_t limit = 100) const override;

    /// Aggregate statistics
    [[nodiscard]] FlowStatsSummary aggregate(
        const FlowQuery& query) const override;

    /// Vacuum/optimize the database
    void optimize() override;

    /// Database size in bytes
    [[nodiscard]] std::size_t sizeBytes() const noexcept override;

private:
    void createSchema();
    void prepareStatements();

    sqlite3* db_ = nullptr;  // RAII via custom deleter
    // Prepared statements for common queries
    struct Statements;
    std::unique_ptr<Statements> stmts_;
};
```

**Database schema**:

```sql
CREATE TABLE flows (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_us    INTEGER NOT NULL,
    src_ip          TEXT NOT NULL,
    dst_ip          TEXT NOT NULL,
    src_port        INTEGER NOT NULL,
    dst_port        INTEGER NOT NULL,
    protocol        INTEGER NOT NULL,
    packet_count    INTEGER,
    byte_count      INTEGER,
    duration_us     INTEGER,
    -- Detection results
    verdict         TEXT NOT NULL,         -- AttackType string
    ml_confidence   REAL,
    combined_score  REAL,
    detection_source TEXT,
    is_flagged      INTEGER NOT NULL DEFAULT 0,
    -- TI matches (JSON array)
    ti_matches      TEXT,
    -- Rule matches (JSON array)
    rule_matches    TEXT,
    -- PCAP reference
    pcap_file       TEXT,
    pcap_offset     INTEGER,
    -- Indexing timestamps
    created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

-- Indexes for common query patterns
CREATE INDEX idx_flows_timestamp ON flows(timestamp_us);
CREATE INDEX idx_flows_src_ip ON flows(src_ip);
CREATE INDEX idx_flows_dst_ip ON flows(dst_ip);
CREATE INDEX idx_flows_verdict ON flows(verdict);
CREATE INDEX idx_flows_flagged ON flows(is_flagged) WHERE is_flagged = 1;
CREATE INDEX idx_flows_combined_score ON flows(combined_score);
CREATE INDEX idx_flows_src_dst ON flows(src_ip, dst_ip);
CREATE INDEX idx_flows_ports ON flows(dst_port, protocol);
```

**Query model**:

```cpp
struct FlowQuery {
    // Time range (required for bounded queries)
    std::optional<int64_t> startTimeUs;
    std::optional<int64_t> endTimeUs;

    // IP filters (support CIDR notation)
    std::optional<std::string> srcIp;
    std::optional<std::string> dstIp;
    std::optional<std::string> anyIp;   // matches src OR dst

    // Port filters
    std::optional<std::uint16_t> srcPort;
    std::optional<std::uint16_t> dstPort;
    std::optional<std::uint16_t> anyPort;

    // Protocol filter
    std::optional<std::uint8_t> protocol;

    // Detection filters
    std::optional<AttackType> verdict;
    std::optional<bool> flaggedOnly;
    std::optional<float> minCombinedScore;
    std::optional<DetectionSource> detectionSource;

    // Sorting and pagination
    std::string orderBy = "timestamp_us DESC";
    std::size_t limit = 1000;
    std::size_t offset = 0;
};
```

### 13.3 — HuntEngine (Retroactive Analysis Orchestrator)

**Purpose**: Execute threat hunting operations against historical data.

**Files**: `src/app/HuntEngine.h`, `src/app/HuntEngine.cpp`

```cpp
class HuntEngine : public IHuntEngine {
public:
    HuntEngine(IPcapStore& pcapStore,
               IFlowIndex& flowIndex,
               IFlowExtractor& extractor,
               IPacketAnalyzer& analyzer,
               IFeatureNormalizer& normalizer,
               HybridDetectionService& detector);

    /// Re-analyze a specific PCAP file with current detection stack
    [[nodiscard]] HuntResult retroactiveAnalysis(
        const std::filesystem::path& pcapFile) override;

    /// Search historical flows for specific IOCs
    [[nodiscard]] HuntResult iocSearch(
        const IocSearchQuery& query) override;

    /// Correlate flows involving a specific IP over a time window
    [[nodiscard]] HuntResult correlateByIp(
        std::string_view ip,
        int64_t startTimeUs,
        int64_t endTimeUs) override;

    /// Build a timeline for an incident
    [[nodiscard]] Timeline buildTimeline(
        const std::vector<IndexedFlow>& flows) override;

    /// Detect statistical anomalies in a time window
    [[nodiscard]] std::vector<AnomalyResult> detectAnomalies(
        int64_t startTimeUs,
        int64_t endTimeUs) override;

    /// Progress callback for long-running hunts
    using ProgressCallback = std::function<void(float progress, std::string_view status)>;
    void setProgressCallback(ProgressCallback cb);

private:
    IPcapStore& pcapStore_;
    IFlowIndex& flowIndex_;
    IFlowExtractor& extractor_;
    IPacketAnalyzer& analyzer_;
    IFeatureNormalizer& normalizer_;
    HybridDetectionService& detector_;
    ProgressCallback progressCb_;
};
```

**Hunt operations**:

#### 13.3.1 — Retroactive Analysis

Re-run the full detection pipeline (flow extraction → normalization → ML → hybrid
evaluation) against a stored PCAP file, potentially with:
- Updated ML model
- New threat intelligence feeds
- New heuristic rules
- New YARA/Snort rules (Phases 14-15)

```
Stored PCAP → NativeFlowExtractor → FeatureNormalizer → OnnxAnalyzer
                                                            → HybridDetectionService
                                                            → Store updated results
```

#### 13.3.2 — IOC Retrospective Search

Search historical flow data for indicators of compromise:

```cpp
struct IocSearchQuery {
    std::vector<std::string> ips;       // IP addresses to search for
    std::vector<std::string> cidrs;     // CIDR ranges
    std::vector<std::uint16_t> ports;   // Ports of interest
    std::optional<int64_t> startTimeUs;
    std::optional<int64_t> endTimeUs;
    bool searchSrcOnly = false;
    bool searchDstOnly = false;
};
```

Use case: A new threat intel feed identifies IP `203.0.113.50` as a C2 server.
Search: "Did any of our hosts communicate with `203.0.113.50` in the past 7 days?"

#### 13.3.3 — Flow Correlation

Link flows that share characteristics suggesting a coordinated attack:

```cpp
struct CorrelationCriteria {
    enum class Strategy {
        SameSourceIp,       // All flows from the same attacker
        SameDestIp,         // All flows to the same target
        PortSweep,          // Same src, many dst ports
        NetworkSweep,       // Same src, many dst IPs
        LateralMovement,    // Internal-to-internal after external attack
        TemporalProximity,  // Flows within N seconds of each other
    };

    Strategy strategy;
    int64_t windowUs = 300'000'000;  // 5 minute correlation window
    std::size_t minFlows = 3;        // minimum flows to form a group
};
```

#### 13.3.4 — Timeline Construction

Build a chronological narrative of events for incident reports:

```cpp
struct TimelineEvent {
    int64_t timestampUs;
    std::string description;
    FlowInfo flow;
    DetectionResult detection;
    enum class EventType {
        FirstContact,       // First flow from attacker IP
        Reconnaissance,     // Port scan / network sweep
        Exploitation,       // Attack flow detected
        LateralMovement,    // Internal-to-internal
        Exfiltration,       // Large outbound data transfer
        Persistence,        // Repeated connections over time
    } type;
};

struct Timeline {
    std::string incidentId;
    std::string summary;
    std::vector<TimelineEvent> events;
    int64_t startTimeUs;
    int64_t endTimeUs;
    std::vector<std::string> involvedIps;
    std::vector<AttackType> attackTypes;
};
```

### 13.4 — StatisticalBaseline

**Purpose**: Establish "normal" traffic patterns and detect deviations.

**Files**: `src/app/StatisticalBaseline.h`, `src/app/StatisticalBaseline.cpp`

```cpp
struct BaselineMetrics {
    double avgFlowsPerMinute;
    double avgBytesPerMinute;
    double avgPacketsPerMinute;
    std::unordered_map<std::uint16_t, double> portFrequency;
    std::unordered_map<std::string, double> ipFrequency;
    double avgFlowDurationUs;
    std::chrono::system_clock::time_point computedAt;
    int64_t windowUs;  // time window used for computation
};

struct AnomalyResult {
    std::string description;
    double deviationSigma;  // how many std devs from baseline
    double baselineValue;
    double observedValue;
    enum class AnomalyType {
        TrafficVolumeSpike,
        NewDestinationPort,
        NewExternalIp,
        UnusualProtocol,
        FlowDurationAnomaly,
        ByteRatioAnomaly,
    } type;
};

class StatisticalBaseline {
public:
    /// Compute baseline from historical flow data
    [[nodiscard]] BaselineMetrics computeBaseline(
        IFlowIndex& index,
        int64_t startTimeUs,
        int64_t endTimeUs);

    /// Compare current traffic against baseline
    [[nodiscard]] std::vector<AnomalyResult> detectAnomalies(
        const BaselineMetrics& baseline,
        IFlowIndex& index,
        int64_t windowStartUs,
        int64_t windowEndUs);
};
```

---

## gRPC API Extensions

Add hunt RPCs to `proto/nids.proto`:

```protobuf
// Threat Hunting RPCs
rpc SearchFlows(FlowSearchRequest) returns (FlowSearchResponse);
rpc SearchIOCs(IocSearchRequest) returns (IocSearchResponse);
rpc RetroactiveAnalysis(RetroAnalysisRequest) returns (stream RetroAnalysisProgress);
rpc GetTimeline(TimelineRequest) returns (TimelineResponse);
rpc GetBaseline(BaselineRequest) returns (BaselineResponse);
rpc DetectAnomalies(AnomalyRequest) returns (AnomalyResponse);
```

CLI commands:

```bash
nids-cli hunt search --ip 203.0.113.50 --last 7d
nids-cli hunt ioc --file iocs.txt --last 30d
nids-cli hunt timeline --ip 10.0.0.5 --last 24h
nids-cli hunt reanalyze --pcap /var/lib/nids/pcap/capture_20260317.pcap
nids-cli hunt baseline --window 24h
nids-cli hunt anomalies --baseline-window 7d --check-window 1h
```

---

## Configuration Changes

Add to `Configuration`:

```cpp
struct HuntingConfig {
    bool enabled = false;
    PcapStorageConfig pcapStorage;
    std::filesystem::path flowDatabasePath = "/var/lib/nids/flows.db";
    std::size_t maxDatabaseSizeMb = 1024;  // 1 GB
    bool indexAllFlows = true;              // false = only flagged flows
    int baselineWindowHours = 168;         // 7 days
    double anomalyThresholdSigma = 3.0;    // 3 sigma anomaly threshold
};
```

---

## Testing Plan

| Test file | Tests | Coverage |
|-----------|-------|----------|
| `test_PcapRingBuffer.cpp` | Store, rotation, eviction (size + time), query, concurrent writes | 15+ |
| `test_SqliteFlowIndex.cpp` | Schema creation, CRUD, queries (IP/port/time/verdict), CIDR, pagination, distinct values, aggregation | 25+ |
| `test_HuntEngine.cpp` | Retroactive analysis, IOC search, correlation, timeline construction | 20+ |
| `test_FlowCorrelator.cpp` | Each correlation strategy, edge cases, empty results | 15+ |
| `test_StatisticalBaseline.cpp` | Baseline computation, anomaly detection, edge cases | 10+ |
| `test_TimelineBuilder.cpp` | Event ordering, summary generation, multi-attacker | 8+ |

**Integration tests**: Full round-trip — capture traffic → store PCAP + index → hunt query → verify results.

---

## Dependencies

| Library | Purpose | Conan Package | License |
|---------|---------|---------------|---------|
| **SQLite3** | Flow metadata indexing | `sqlite3/3.45.3` | Public domain |
| **(Alternative) DuckDB** | Columnar analytics DB (faster aggregations) | `duckdb/1.1.0` | MIT |

**Recommendation**: Start with SQLite (simpler, lighter, widely deployed). Migrate to
DuckDB if analytical query performance becomes a bottleneck (DuckDB excels at
aggregation over millions of rows).

**SQLite WAL mode** should be enabled for concurrent read/write access:
```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
```

---

## Milestones

| Week | Deliverable |
|------|-------------|
| 1 | `IPcapStore` + `IFlowIndex` interfaces, `HuntQuery`/`HuntResult` models |
| 2 | `PcapRingBuffer` implementation + unit tests |
| 3 | `SqliteFlowIndex` implementation + unit tests |
| 4 | `HuntEngine` (retroactive analysis + IOC search) + tests |
| 5 | `FlowCorrelator` + `TimelineBuilder` + tests |
| 6 | `StatisticalBaseline` + anomaly detection + tests |
| 7 | gRPC API extensions + CLI commands |
| 8 | Integration tests + documentation |

### Minimal Viable (6 weeks)

Deliver weeks 1–4 + week 7 (gRPC): PCAP storage, flow indexing, retroactive analysis,
IOC search, CLI interface. Defer correlation, timeline, and baseline to a follow-up.
