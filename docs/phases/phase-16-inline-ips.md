# Phase 16: Inline IPS Gateway Mode

> **Effort**: 13–18 weeks | **Dependencies**: Phase 15 (Snort rules), Linux kernel headers | **Risk**: Very High
>
> **Goal**: Transform NIDS from a passive detection system into an active inline
> Intrusion Prevention System (IPS) that sits between two network interfaces,
> inspects all traffic, and selectively forwards or drops packets in real-time.

---

## Motivation

Detection without prevention means the attack has already reached its target by the
time an alert is generated. An inline IPS provides **active protection**:

- **Immediate blocking** of known-bad signatures (Snort rules, YARA matches)
- **Threat-intel-based blocking** of traffic from known C2/botnet IPs
- **ML-informed blocking** of statistically anomalous flows (after flow classification)
- **Defense-in-depth** — the NIDS becomes a security gateway, not just a sensor

### Deployment topology

```
                        ┌──────────────────────────────┐
                        │        NIDS IPS Gateway       │
Internet ──────► NIC1 ──┤                              ├── NIC2 ──► Internal Network
              (input)   │  AF_PACKET inline bridge     │  (output)
                        │                              │
                        │  Signature → immediate DROP  │
                        │  TI match  → immediate DROP  │
                        │  ML flow   → delayed block   │
                        │  Clean     → FORWARD         │
                        │                              │
                        │  fail-open / fail-closed      │
                        └──────────────────────────────┘
```

---

## Prerequisites

This phase **requires Phase 15 (Snort rules)** to be completed first because:

1. ML operates at the **flow level** — verdicts arrive after the flow is complete
   (15-60 seconds, or 200 packets). By that time, the attack packets have already
   passed through.
2. Inline IPS needs **per-packet** verdicts with **<1ms latency**.
3. Only signature matching (Snort) and threat intelligence (IP lookup) can provide
   per-packet verdicts fast enough.
4. ML verdicts are applied **retroactively** by inserting dynamic block rules for
   the 5-tuple.

### Verdict timeline

```
Packet arrives at NIC1
  │
  ├─ 0.001ms: TI lookup (O(1) hash) → FORWARD or DROP
  │
  ├─ 0.1-1ms: Signature match → FORWARD or DROP
  │
  ├─ FORWARD (packet delivered to internal network)
  │
  └─ 15-60 seconds later: ML flow verdict
     → if attack: insert netfilter rule to block 5-tuple
     → subsequent packets from this flow are dropped at kernel level
```

---

## Architecture

### Layer placement

| Component | Layer | Rationale |
|-----------|-------|-----------|
| `IInlineCapture` | `core/services/` | Interface — no platform deps |
| `PacketVerdict` | `core/model/` | Verdict enum — pure C++ |
| `InlineConfig` | `core/model/` | Configuration — pure C++ |
| `AfPacketCapture` | `infra/capture/` | Linux AF_PACKET v3 — platform dep |
| `NfqueueCapture` | `infra/capture/` | Alternative: Netfilter Queue — platform dep |
| `NetfilterBlocker` | `infra/platform/` | Dynamic iptables/nftables rule insertion |
| `VerdictEngine` | `app/` | Combines all signals into per-packet verdict |
| `InlinePipeline` | `app/` | Orchestrates inline mode lifecycle |
| `BypassManager` | `app/` | Moves clean flows to kernel forwarding |

### System-level data flow

```
NIC1 (input)
  │
  ▼ AF_PACKET TPACKET_V3 ring buffer (mmap, zero-copy)
  │
  ├──▶ [Fast path] TI IP lookup (O(1))
  │         │
  │         ├── Known bad → DROP (never enters slow path)
  │         └── Unknown  → continue
  │
  ├──▶ [Fast path] Signature scan (Aho-Corasick)
  │         │
  │         ├── Signature match → DROP (alert generated)
  │         └── No match → continue
  │
  ├──▶ [Default] FORWARD to NIC2
  │
  └──▶ [Parallel, async] Flow extractor → ML → verdict
           │
           └── Attack detected → NetfilterBlocker adds
               iptables/nftables rule for 5-tuple
               → subsequent packets dropped at KERNEL level
               (never reach userspace again)
```

### Thread model

```
┌─────────────────────────────────────────────────────────────┐
│                       Inline Pipeline                        │
│                                                              │
│  Thread 1: AF_PACKET RX (NIC1)                              │
│    ├── Read packet from ring buffer                          │
│    ├── TI lookup (O(1), no lock needed — read-only)         │
│    ├── Signature scan (Aho-Corasick, read-only after compile)│
│    ├── Verdict: FORWARD → sendto() on NIC2 socket            │
│    │           DROP → discard packet                         │
│    └── Copy to flow extractor queue (non-blocking tryPush)   │
│                                                              │
│  Thread 2: Flow extraction (existing NativeFlowExtractor)    │
│    ├── processPacket() → accumulate flow stats               │
│    ├── sweepExpiredFlows() → complete flows                   │
│    └── Push FlowWorkItem to BoundedQueue                      │
│                                                              │
│  Thread 3: ML Analysis (existing FlowAnalysisWorker)         │
│    ├── Pop FlowWorkItem from queue                            │
│    ├── Normalize + predict + hybrid evaluate                  │
│    └── If attack: signal NetfilterBlocker                     │
│                                                              │
│  Thread 4: Stats / management                                │
│    ├── Periodic bypass sweep                                  │
│    ├── Netfilter rule cleanup                                 │
│    └── Performance counters                                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Component Specifications

### 16.1 — PacketVerdict

**File**: `src/core/model/PacketVerdict.h`

```cpp
#pragma once

#include <cstdint>
#include <string_view>

namespace nids::core {

/// Per-packet verdict for inline IPS mode.
enum class PacketVerdict : std::uint8_t {
    Forward,    ///< Forward packet to output interface
    Drop,       ///< Silently drop the packet
    Reject,     ///< Drop + send TCP RST or ICMP unreachable
    Alert,      ///< Forward but generate an alert
    Bypass,     ///< Forward and skip further inspection for this flow
};

/// Source of the verdict decision.
enum class VerdictSource : std::uint8_t {
    Default,        ///< No detection triggered, default forward
    ThreatIntel,    ///< Known-bad IP from TI feed
    Signature,      ///< Snort rule match
    YaraMatch,      ///< YARA content match
    MlClassifier,   ///< ML flow-level classification (delayed)
    BypassManager,  ///< Flow verified clean, bypassed to kernel
    AdminBlock,     ///< Manual block rule
};

[[nodiscard]] constexpr std::string_view verdictToString(
    PacketVerdict v) noexcept {
    constexpr std::array<std::string_view, 5> names = {{
        "Forward", "Drop", "Reject", "Alert", "Bypass"
    }};
    auto idx = static_cast<std::size_t>(v);
    return idx < names.size() ? names[idx] : "Unknown";
}

} // namespace nids::core
```

### 16.2 — IInlineCapture Interface

**File**: `src/core/services/IInlineCapture.h`

```cpp
#pragma once

#include "core/model/PacketVerdict.h"

#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>

namespace nids::core {

/// Configuration for inline IPS capture.
struct InlineConfig {
    std::string inputInterface;     ///< NIC receiving traffic (e.g., "eth0")
    std::string outputInterface;    ///< NIC forwarding traffic (e.g., "eth1")

    enum class FailMode : std::uint8_t {
        FailOpen,   ///< Forward all traffic if IPS fails (safety)
        FailClosed  ///< Drop all traffic if IPS fails (security)
    } failMode = FailMode::FailOpen;

    int ringBlockCount = 64;        ///< TPACKET_V3 ring block count
    int ringBlockSize = 1 << 22;    ///< 4 MB per block
    int ringFrameSize = 1 << 11;    ///< 2048 bytes per frame
    int fanoutId = 42;              ///< PACKET_FANOUT group ID
    int fanoutThreads = 1;          ///< Number of parallel RX threads
    bool promiscuous = true;        ///< Set NIC to promiscuous mode
    int snaplen = 65535;            ///< Maximum capture length
};

/// Callback invoked for each received packet. Must return a verdict.
/// CRITICAL: This callback runs on the hot path — must complete in <1ms.
using VerdictCallback = std::function<PacketVerdict(
    std::span<const std::uint8_t> packet,  // full packet (L2 frame)
    int64_t timestampUs)>;

/// Interface for inline packet capture with verdict capability.
class IInlineCapture {
public:
    virtual ~IInlineCapture() = default;

    /// Initialize the inline capture with two interfaces.
    [[nodiscard]] virtual bool initialize(const InlineConfig& config) = 0;

    /// Set the verdict callback. Called for EVERY packet on the hot path.
    virtual void setVerdictCallback(VerdictCallback cb) = 0;

    /// Start inline capture (blocking until stop() is called).
    virtual void start() = 0;

    /// Stop inline capture gracefully.
    virtual void stop() = 0;

    /// Performance counters.
    struct Stats {
        std::uint64_t packetsReceived = 0;
        std::uint64_t packetsForwarded = 0;
        std::uint64_t packetsDropped = 0;
        std::uint64_t packetsRejected = 0;
        std::uint64_t packetsBypassed = 0;
        std::uint64_t bytesReceived = 0;
        std::uint64_t bytesForwarded = 0;
        std::uint64_t kernelDrops = 0;     // packets dropped by kernel
        double avgVerdictLatencyUs = 0.0;   // average verdict time
        double maxVerdictLatencyUs = 0.0;
    };
    [[nodiscard]] virtual Stats stats() const noexcept = 0;
};

} // namespace nids::core
```

### 16.3 — AfPacketCapture (AF_PACKET v3 Inline)

**Purpose**: High-performance inline packet capture using Linux AF_PACKET v3
with memory-mapped ring buffers for zero-copy.

**Files**: `src/infra/capture/AfPacketCapture.h`, `src/infra/capture/AfPacketCapture.cpp`

```cpp
class AfPacketCapture : public core::IInlineCapture {
public:
    AfPacketCapture();
    ~AfPacketCapture() override;

    [[nodiscard]] bool initialize(const core::InlineConfig& config) override;
    void setVerdictCallback(core::VerdictCallback cb) override;
    void start() override;
    void stop() override;
    [[nodiscard]] core::IInlineCapture::Stats stats() const noexcept override;

private:
    // Setup
    [[nodiscard]] bool createSocket(const std::string& iface, int& fd);
    [[nodiscard]] bool setupRingBuffer(int fd, void*& ring,
                                        const core::InlineConfig& config);
    [[nodiscard]] bool setPromiscuous(const std::string& iface, int fd);
    [[nodiscard]] bool bindToInterface(int fd, const std::string& iface);

    // Packet processing
    void processBlock(tpacket3_hdr* hdr);
    void forwardPacket(std::span<const std::uint8_t> packet);

    // RAII socket wrappers
    struct SocketDeleter {
        void operator()(int* fd) const noexcept;
    };
    std::unique_ptr<int, SocketDeleter> rxSocket_;   // NIC1 (input)
    std::unique_ptr<int, SocketDeleter> txSocket_;    // NIC2 (output)

    // Memory-mapped ring buffers
    void* rxRing_ = nullptr;
    std::size_t rxRingSize_ = 0;

    core::InlineConfig config_;
    core::VerdictCallback verdictCb_;
    std::atomic<bool> running_{false};
    mutable std::atomic<core::IInlineCapture::Stats> stats_{};
};
```

**AF_PACKET v3 key concepts**:

```
                   Kernel space
┌──────────────────────────────────────────┐
│  NIC1 driver ──► AF_PACKET socket        │
│                  ┌─────────────────────┐ │
│                  │ TPACKET_V3 ring     │ │
│                  │ (mmap'd into user)  │ │
│                  │ ┌───┐ ┌───┐ ┌───┐  │ │
│                  │ │blk│ │blk│ │blk│  │ │
│                  │ │ 0 │ │ 1 │ │ 2 │  │ │
│                  │ └───┘ └───┘ └───┘  │ │
│                  └─────────┬───────────┘ │
└────────────────────────────┼─────────────┘
                   User space│ (mmap, zero-copy)
                             ▼
                  ┌─────────────────────┐
                  │  NIDS VerdictEngine  │
                  │  - TI lookup         │
                  │  - Signature scan    │
                  │  - Verdict: FWD/DROP │
                  └──────────┬──────────┘
                             │ sendto()
                             ▼
                  ┌─────────────────────┐
                  │  NIC2 TX socket     │
                  └─────────────────────┘
```

**TPACKET_V3 advantages over v2**:
- Variable-length blocks (efficient for mixed packet sizes)
- `poll()`-based blocking (no busy-wait, saves CPU)
- Block-level timestamps (fewer syscalls)
- VLAN handling improvements

### 16.4 — NfqueueCapture (Alternative: Netfilter Queue)

**Purpose**: Alternative inline path using `iptables -j NFQUEUE`. Simpler than
AF_PACKET but higher latency.

**Files**: `src/infra/capture/NfqueueCapture.h`, `src/infra/capture/NfqueueCapture.cpp`

**When to use NFQUEUE vs AF_PACKET**:

| | AF_PACKET v3 | NFQUEUE |
|---|---|---|
| Latency | ~1-5 μs | ~10-50 μs |
| Throughput | 10+ Gbps | 1-5 Gbps |
| Complexity | High (raw sockets, ring buffers) | Medium (libnetfilter_queue) |
| Kernel integration | Manual bridge | iptables FORWARD chain |
| Drop mechanism | Don't forward | `nfq_set_verdict(NF_DROP)` |
| Multi-queue | PACKET_FANOUT | Multiple queue numbers |
| Use case | Production, high-speed | Lab, testing, low-speed |

**Recommendation**: Implement NFQUEUE first (simpler, better for testing), then
add AF_PACKET for production deployments.

### 16.5 — VerdictEngine

**Purpose**: Combine all detection signals into a per-packet verdict.

**Files**: `src/app/VerdictEngine.h`, `src/app/VerdictEngine.cpp`

```cpp
struct VerdictPolicy {
    bool blockOnTiMatch = true;             // Block known-bad IPs
    bool blockOnSignature = true;           // Block signature matches
    bool blockOnYara = false;               // Alert only for YARA (configurable)
    bool blockOnMlVerdict = true;           // Insert flow block on ML attack
    float mlBlockThreshold = 0.85f;         // Only block if ML confidence > 85%
    bool logDroppedPackets = true;          // Log every drop
    int maxBlockRulesPerFlow = 1;           // Deduplicate block rules
};

class VerdictEngine {
public:
    VerdictEngine(IThreatIntelligence& threatIntel,
                  ISignatureEngine& signatures,
                  IContentScanner& yaraScanner,
                  VerdictPolicy policy = {});

    /// Determine verdict for a single packet.
    /// MUST complete in <1ms on the hot path.
    struct VerdictResult {
        PacketVerdict verdict;
        VerdictSource source;
        std::string reason;  // human-readable (for logging)
    };
    [[nodiscard]] VerdictResult evaluate(
        std::span<const std::uint8_t> packet,
        const FlowInfo& flow) const;

    /// Handle ML flow-level verdict (called from FlowAnalysisWorker thread).
    /// Inserts a dynamic block rule via NetfilterBlocker.
    void onMlVerdict(const FlowInfo& flow,
                     const DetectionResult& result);

private:
    IThreatIntelligence& threatIntel_;
    ISignatureEngine& signatures_;
    IContentScanner& yaraScanner_;
    VerdictPolicy policy_;

    // Dynamic block list (populated by ML verdicts)
    mutable std::mutex blockMutex_;
    std::unordered_set<FlowKey, FlowKeyHash> blockedFlows_;
};
```

**Hot path budget** (per-packet, target <1ms total):

| Step | Budget | Notes |
|------|--------|-------|
| Parse L2/L3/L4 headers | 1 μs | PcapPlusPlus or manual |
| TI IP lookup | 1 μs | O(1) hash table |
| Check dynamic block list | 1 μs | O(1) hash table |
| Signature scan | 100-500 μs | Aho-Corasick + PCRE (if content match) |
| YARA scan (optional) | 10-50 μs | Per-packet, shallow |
| Forward (sendto) | 5-10 μs | Kernel TX |
| **Total** | **~120-570 μs** | Well within 1ms budget |

### 16.6 — NetfilterBlocker

**Purpose**: Insert/remove dynamic iptables/nftables rules to block specific
5-tuples at the kernel level (ML-informed blocking).

**Files**: `src/infra/platform/NetfilterBlocker.h`, `src/infra/platform/NetfilterBlocker.cpp`

```cpp
class NetfilterBlocker {
public:
    explicit NetfilterBlocker(bool useNftables = true);
    ~NetfilterBlocker();

    /// Block a specific 5-tuple
    [[nodiscard]] bool block(const FlowKey& key,
                              std::string_view reason,
                              std::chrono::seconds duration = std::chrono::seconds{300});

    /// Unblock a specific 5-tuple
    [[nodiscard]] bool unblock(const FlowKey& key);

    /// Remove all NIDS-managed block rules
    void clearAll();

    /// Remove expired block rules
    void sweepExpired();

    /// Number of active block rules
    [[nodiscard]] std::size_t activeRuleCount() const noexcept;

private:
    // Use nftables (preferred) or iptables
    [[nodiscard]] bool nftBlock(const FlowKey& key, int durationSec);
    [[nodiscard]] bool nftUnblock(const FlowKey& key);
    [[nodiscard]] bool iptBlock(const FlowKey& key, int durationSec);
    [[nodiscard]] bool iptUnblock(const FlowKey& key);

    bool useNftables_;
    struct BlockEntry {
        FlowKey key;
        std::string reason;
        std::chrono::steady_clock::time_point expiresAt;
    };
    std::vector<BlockEntry> activeBlocks_;
    mutable std::mutex mutex_;
};
```

**nftables implementation** (preferred):

```bash
# Create NIDS chain (once at startup)
nft add table inet nids_ips
nft add chain inet nids_ips forward { type filter hook forward priority -10 \; }

# Block a 5-tuple (dynamic, from C++ via system API)
nft add rule inet nids_ips forward \
    ip saddr 10.0.0.1 ip daddr 192.168.1.100 \
    tcp sport 54321 tcp dport 80 \
    counter drop comment \"NIDS: DDoS_UDP detected\"

# Remove expired rules
nft delete rule inet nids_ips forward handle $HANDLE
```

**C++ integration**: Use `libmnl` (minimal netlink library) for direct nftables
manipulation without shelling out to `nft` command. Falls back to `iptables` CLI
via `QProcess` equivalent if nftables is unavailable.

### 16.7 — BypassManager

**Purpose**: Move verified-clean flows from userspace inspection to kernel-level
forwarding, reducing CPU overhead.

**Files**: `src/app/BypassManager.h`, `src/app/BypassManager.cpp`

```cpp
struct BypassPolicy {
    int cleanPacketThreshold = 100;   // Bypass after 100 clean packets
    int cleanFlowTimeSeconds = 30;    // Bypass after 30s without alerts
    bool bypassBenignMl = true;       // Trust ML benign verdict for bypass
    float mlBypassThreshold = 0.95f;  // Only bypass if ML confidence > 95%
};

class BypassManager {
public:
    explicit BypassManager(BypassPolicy policy = {});

    /// Track a forwarded packet for a flow
    void trackForwarded(const FlowKey& key);

    /// Check if a flow should be bypassed (skip inspection)
    [[nodiscard]] bool shouldBypass(const FlowKey& key) const;

    /// Mark a flow as bypassed (after ML confirms benign)
    void markBypassed(const FlowKey& key);

    /// Remove bypass for a flow (if new alert triggers)
    void revokeBypss(const FlowKey& key);

    /// Clean up expired flow tracking
    void sweep(int64_t nowUs, int64_t timeoutUs);

    /// Statistics
    [[nodiscard]] std::size_t bypassedFlowCount() const noexcept;
    [[nodiscard]] std::size_t trackedFlowCount() const noexcept;

private:
    BypassPolicy policy_;
    struct FlowTracker {
        int cleanPackets = 0;
        int64_t firstSeenUs = 0;
        bool bypassed = false;
    };
    std::unordered_map<FlowKey, FlowTracker, FlowKeyHash> flows_;
    mutable std::mutex mutex_;
};
```

### 16.8 — InlinePipeline (Main Orchestrator)

**Files**: `src/app/InlinePipeline.h`, `src/app/InlinePipeline.cpp`

```cpp
class InlinePipeline {
public:
    InlinePipeline(std::unique_ptr<IInlineCapture> capture,
                   std::unique_ptr<VerdictEngine> verdictEngine,
                   std::unique_ptr<IFlowExtractor> extractor,
                   std::unique_ptr<FlowAnalysisWorker> worker,
                   std::unique_ptr<NetfilterBlocker> blocker,
                   std::unique_ptr<BypassManager> bypass);

    /// Start the inline IPS pipeline
    [[nodiscard]] bool start(const InlineConfig& config);

    /// Stop the pipeline gracefully
    void stop();

    /// Check if the pipeline is running
    [[nodiscard]] bool isRunning() const noexcept;

    /// Get performance statistics
    [[nodiscard]] InlineStats stats() const;

private:
    /// Per-packet verdict callback (runs on capture thread)
    [[nodiscard]] PacketVerdict onPacket(
        std::span<const std::uint8_t> packet,
        int64_t timestampUs);

    /// ML flow verdict callback (runs on worker thread)
    void onMlVerdict(const DetectionResult& result,
                     const FlowInfo& flow);

    std::unique_ptr<IInlineCapture> capture_;
    std::unique_ptr<VerdictEngine> verdictEngine_;
    std::unique_ptr<IFlowExtractor> extractor_;
    std::unique_ptr<FlowAnalysisWorker> worker_;
    std::unique_ptr<NetfilterBlocker> blocker_;
    std::unique_ptr<BypassManager> bypass_;
    std::unique_ptr<BoundedQueue<FlowWorkItem>> flowQueue_;

    std::jthread pipelineThread_;
    std::atomic<bool> running_{false};
};
```

---

## Safety and Failure Modes

### Fail-open (default)

If the IPS process crashes, NIC1 and NIC2 can be bridged at the kernel level
(Linux bridge or macvlan) so traffic continues flowing. This requires pre-configuring
the bridge as a fallback:

```bash
# Watchdog script (systemd timer)
if ! pgrep nids-server; then
    ip link add br-failopen type bridge
    ip link set eth0 master br-failopen
    ip link set eth1 master br-failopen
    ip link set br-failopen up
fi
```

### Fail-closed

All traffic is dropped if the IPS is not running. Use for high-security environments
where unmonitored traffic is unacceptable:

```bash
# iptables default DROP on FORWARD chain
iptables -P FORWARD DROP
# Only NIDS process can forward (via AF_PACKET direct send)
```

### Bypass for critical services

Whitelist flows that should never be dropped (DNS to internal resolvers,
management SSH, health checks):

```json
{
  "inline": {
    "bypass_rules": [
      { "dst_ip": "10.0.0.1", "dst_port": 53, "comment": "Internal DNS" },
      { "src_ip": "10.0.0.100", "dst_port": 22, "comment": "Management SSH" }
    ]
  }
}
```

---

## Configuration Changes

Add to `Configuration`:

```cpp
struct InlineIpsConfig {
    bool enabled = false;
    std::string inputInterface;
    std::string outputInterface;
    InlineConfig::FailMode failMode = InlineConfig::FailMode::FailOpen;
    VerdictPolicy verdictPolicy;
    BypassPolicy bypassPolicy;
    bool useNftables = true;      // false = iptables fallback
    int blockDurationSeconds = 300;  // 5 min default block
    int maxBlockRules = 10000;     // prevent rule table explosion
    std::vector<BypassRule> staticBypasses;  // always-forward rules
};
```

---

## Docker Sandbox Updates

Update `docker/sandbox/compose.yml` for inline testing:

```yaml
services:
  nids-server:
    # ... existing config ...
    cap_add:
      - NET_RAW
      - NET_ADMIN
    sysctls:
      - net.ipv4.ip_forward=1
    networks:
      external:
        ipv4_address: 172.28.0.10
      internal:
        ipv4_address: 172.29.0.10

  attacker:
    networks:
      external:
        ipv4_address: 172.28.0.20
    # Route to victim goes through nids-server
    # Attacker → 172.28.0.10 (NIC1) → IPS → 172.29.0.10 (NIC2) → Victim

  victim:
    networks:
      internal:
        ipv4_address: 172.29.0.30

networks:
  external:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/24
  internal:
    driver: bridge
    ipam:
      config:
        - subnet: 172.29.0.0/24
```

---

## Testing Plan

| Test file | Tests | Coverage |
|-----------|-------|----------|
| `test_PacketVerdict.cpp` | Enum values, verdictToString | 5+ |
| `test_VerdictEngine.cpp` | TI block, signature block, YARA alert, ML delayed block, bypass, combined signals, policy config | 25+ |
| `test_NetfilterBlocker.cpp` | Block/unblock, sweep expired, clear all, nftables commands, iptables fallback | 15+ |
| `test_BypassManager.cpp` | Track, threshold bypass, ML bypass, revoke, sweep | 12+ |
| `test_InlinePipeline.cpp` | Start/stop lifecycle, verdict flow, ML delayed block, fail-open, performance counters | 15+ |
| `test_AfPacketCapture.cpp` | Socket creation, ring buffer setup (requires CAP_NET_RAW) | 8+ (integration) |

**Integration tests** (Docker sandbox):
- **Benign forwarding**: Send HTTP traffic from attacker → victim, verify all packets forwarded
- **Signature blocking**: Send known Snort-matching payload, verify packet dropped
- **TI blocking**: Add attacker IP to TI feed, verify all traffic dropped
- **ML delayed block**: Send attack pattern, verify initial packets forwarded, then flow blocked after ML verdict
- **Bypass verification**: Long-lived clean flow bypasses inspection after threshold
- **Fail-open test**: Kill nids-server, verify traffic still flows via kernel bridge
- **Performance test**: iperf3 through IPS, measure throughput and latency overhead

---

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Per-packet verdict latency | <1 ms (p99) | Critical for inline mode |
| Throughput (no rules) | >5 Gbps | Pure forwarding overhead |
| Throughput (1K rules) | >2 Gbps | Typical custom ruleset |
| Throughput (40K rules) | >500 Mbps | Full ET Open (may need Hyperscan) |
| Kernel drops | <0.01% | At target throughput |
| Fail-open switch time | <100 ms | Time to bridge on IPS crash |
| ML block insertion latency | <100 ms | From ML verdict to netfilter rule |

---

## Dependencies

| Library | Purpose | Packaging | License |
|---------|---------|-----------|---------|
| Linux kernel headers | AF_PACKET v3, TPACKET_V3 | System | GPL |
| libmnl (optional) | Netlink/nftables manipulation | System/Conan | LGPL |
| libnetfilter_queue | NFQUEUE inline mode (alternative) | System | GPL-2 |

**Platform**: Linux only. AF_PACKET is a Linux-specific socket type. The passive
detection mode (PcapPlusPlus) remains cross-platform.

---

## Milestones

| Week | Deliverable |
|------|-------------|
| 1 | `PacketVerdict`, `IInlineCapture`, `InlineConfig` models + interfaces |
| 2 | `NfqueueCapture` (simpler inline path for initial development) |
| 3 | `VerdictEngine` + basic TI + signature verdict logic + tests |
| 4 | `NetfilterBlocker` (nftables + iptables fallback) + tests |
| 5 | `BypassManager` + tests |
| 6 | `InlinePipeline` orchestrator + lifecycle + tests |
| 7 | Docker sandbox: dual-network topology + integration tests |
| 8 | End-to-end: benign forwarding + signature blocking tests |
| 9 | ML delayed blocking: flow verdict → netfilter rule insertion |
| 10 | `AfPacketCapture` (TPACKET_V3, zero-copy) |
| 11 | AF_PACKET ring buffer tuning + multi-queue (PACKET_FANOUT) |
| 12 | Fail-open/fail-closed modes + watchdog |
| 13 | Performance benchmarking (iperf3 through IPS) |
| 14 | Bypass optimization (kernel-level forwarding for clean flows) |
| 15-16 | Hardening: edge cases, error recovery, documentation |
| 17-18 | Production readiness: monitoring, logging, operational docs |

---

## Implementation Status

### Completed

| Component | Files | Status |
|-----------|-------|--------|
| **PacketVerdict model** | `core/model/PacketVerdict.h` | Done |
| **IInlineCapture interface** | `core/services/IInlineCapture.h` | Done |
| **VerdictEngine** | `app/VerdictEngine.h/.cpp` — TI+signature+YARA+dynamic block | Done (9 tests) |
| **BypassManager** | `app/BypassManager.h/.cpp` — clean flow tracking + bypass | Done (10 tests) |
| **NetfilterBlocker** | `infra/platform/NetfilterBlocker.h/.cpp` — dry-run rule tracking | Done (11 tests) |
| **InlineIpsConfig** | `Configuration.h` | Done |
| **ConfigLoader** | Inline JSON section parsing | Done |

### Test Coverage

| Test file | Tests |
|-----------|-------|
| `test_VerdictEngine.cpp` | 9 (default forward, TI block src/dst, TI disabled, dynamic block/unblock/clear, empty payload, policy) |
| `test_BypassManager.cpp` | 10 (new flow, below/above threshold, explicit bypass, revoke, sweep, disabled, multi-flow, policy update) |
| `test_NetfilterBlocker.cpp` | 11 (constructor, block/unblock, duplicate, clearAll, sweep expired/active, unknown key, multi-block, destructor) |
| `test_InterfaceDestructors.cpp` | +1 (IInlineCapture) |
