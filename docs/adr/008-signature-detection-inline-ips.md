# ADR-008: Scope Expansion to Signature Detection, YARA, and Inline IPS

## Status

Proposed — Pending implementation (Phases 12–16).

## Related

- **ADR-005**: Hybrid Detection System — established the 3-layer model (ML + TI + Heuristic Rules).
  This ADR extends it to a 5-layer model by adding signature matching (Snort rules)
  and content scanning (YARA rules).
- **ADR-004**: Model Benchmark Analysis — documented ML blind spots (payload-based attacks)
  that motivate signature detection integration.
- **docs/architecture.md**: "Detection Philosophy & Perimeter" section — this ADR
  **supersedes** the "What we explicitly do NOT do" table for signature matching and
  inline prevention.

## Context

### The gap ADR-005 identified but did not close

ADR-005's hybrid detection system mitigates many ML limitations: TI catches known-bad
IPs that ML passes, and heuristic rules flag protocol red flags. However, two
structural blind spots remain:

1. **Payload-based attacks** (SQL injection at 17.3% FN, XSS at 10.7% FN) are
   fundamentally undetectable at the flow level. The architecture doc says
   *"That is Snort/Suricata's job"* — but this creates a deployment dependency
   on running Snort alongside our system.

2. **Malware delivery** via HTTP/FTP/SMTP cannot be detected without content
   scanning. YARA rules match byte patterns in file content and network payloads
   that flow-level features cannot represent.

3. **Active prevention** is impossible in passive mode. The system detects and alerts,
   but a detected attack has already reached the target. Inline IPS with per-packet
   drop capability is required for prevention.

### Why the perimeter is expanding

The original deployment model assumed our NIDS runs **alongside** Snort/Suricata:

```
Internet → Firewall → Snort (signatures) → NIDS (ML) → Internal Network
```

This model works for organizations that already run Snort/Suricata. But:

- Many small/medium deployments want a **single tool** that provides comprehensive
  detection without the operational burden of managing multiple IDS engines.
- Running Snort + our NIDS + OSSEC/Wazuh is operationally complex. Consolidation
  into a single binary reduces deployment friction.
- Signature matching and ML are **complementary detection methods inside the same
  pipeline**, not separate tools. The hybrid scoring system (`HybridDetectionService`)
  can combine signature matches with ML confidence just as it combines TI and
  heuristic signals today.

### The new deployment model

```
Internet
    │
    ▼
┌─────────┐     ┌────────────────────────────────────────────┐     ┌─────────┐
│  NIC1   │────▶│               NIDS (Inline IPS)            │────▶│  NIC2   │
│ (input) │     │                                            │     │ (output)│
└─────────┘     │  Layer 1: Signature matching (Snort rules) │     └─────────┘
                │  Layer 2: Content scanning (YARA rules)    │
                │  Layer 3: ML flow classifier (CNN-BiLSTM)  │
                │  Layer 4: Threat intelligence (IP reputation)│
                │  Layer 5: Heuristic rules                  │
                │                                            │
                │  ──► Per-packet verdicts (sig + YARA)      │
                │  ──► Per-flow verdicts (ML + TI + rules)   │
                │                                            │
                │  ──► FORWARD / DROP / ALERT                │
                │                                            │
                │  Output: Syslog, CEF, Wazuh, gRPC stream   │
                └────────────────────────────────────────────┘
                                    │
                                    ▼
                            SIEM / OSSEC / Wazuh
                           (alert correlation)
```

## Decision

### D1: Extend the hybrid detection system from 3 layers to 5 layers

Add two new detection layers to `HybridDetectionService`:

| Layer | Interface | Implementation | Operates on |
|-------|-----------|----------------|-------------|
| Signature matching | `ISignatureEngine` (new) | `SnortRuleEngine` | Per-packet payloads |
| Content scanning | `IContentScanner` (new) | `YaraScanner` | Per-flow reassembled streams |
| ML classifier | `IPacketAnalyzer` (existing) | `OnnxAnalyzer` | Per-flow 77-feature vectors |
| Threat intelligence | `IThreatIntelligence` (existing) | `ThreatIntelProvider` | Per-flow IP addresses |
| Heuristic rules | `IRuleEngine` (existing) | `HeuristicRuleEngine` | Per-flow metadata |

### D2: Implement Snort rule compatibility for per-packet signature matching

Support a practical subset of Snort 3.x rule syntax:

| Supported | Description |
|-----------|-------------|
| Rule header | `action protocol src_ip src_port -> dst_ip dst_port` |
| `content` | Byte-pattern matching with `offset`, `depth`, `distance`, `within`, `nocase` |
| `pcre` | Perl-compatible regex via PCRE2 library |
| `flow` | Connection state (`established`, `to_server`, `to_client`) |
| `flowbits` | Cross-rule stateful correlation (`set`, `isset`, `unset`, `toggle`) |
| `threshold` | Rate-based triggering (`count`, `seconds`, `type limit/threshold/both`) |
| `sid`, `rev`, `msg`, `classtype`, `priority` | Rule metadata |
| `reference` | CVE, bugtraq, URL cross-references |
| Variables | `$HOME_NET`, `$EXTERNAL_NET`, `$HTTP_PORTS`, etc. |

**Not initially supported** (can be added later):

| Deferred | Reason |
|----------|--------|
| `byte_test` / `byte_jump` | Protocol-specific field extraction — complex, lower priority |
| `file_data` / `pkt_data` | File extraction — separate YARA concern |
| `service` | HTTP/DNS/TLS service detection — requires protocol analyzers |
| Shared object rules (`.so`) | C plugin rules — security risk in production |
| Lua scripts | Scripting rules — complex runtime, deferred |

### D3: Implement YARA rules for content/malware scanning

Use `libyara` (C API) for pattern scanning of:

1. **Per-packet payloads** — quick scan of individual packet data
2. **Reassembled TCP streams** — full stream data via PcapPlusPlus `TcpReassembly`
3. **(Future)** Carved files from HTTP/SMTP — extracted from reassembled streams

### D4: Implement inline IPS gateway mode (Linux-only)

Use AF_PACKET v3 with `TPACKET_V3` for dual-NIC inline capture:

- **NIC1** (input): receives all traffic
- **NIC2** (output): forwards allowed traffic
- Default mode: **forward-by-default** (fail-open)
- Per-packet verdicts from signature matching provide immediate `FORWARD`/`DROP`
- Per-flow verdicts from ML update dynamic netfilter rules for the 5-tuple
- Configurable fail-open (safety) vs. fail-closed (maximum security)

**The key latency constraint**: Per-packet signature matching must complete in
<1ms. ML flow-level verdicts operate on 15-60 second timescales. The hybrid
approach:

1. Signatures provide **immediate** per-packet verdicts
2. TI provides **immediate** per-IP verdicts (O(1) lookup)
3. ML provides **delayed** per-flow verdicts (after flow completion)
4. ML verdicts dynamically insert netfilter block rules for flagged 5-tuples

### D5: Implement SIEM/OSSEC output integration

OSSEC/Wazuh is a **HIDS** (host-based), not a NIDS. Rather than parsing OSSEC rules
(which operate on log events, not network traffic), provide output sinks that forward
NIDS alerts to existing SIEM/HIDS infrastructure:

| Output format | Protocol | Target |
|---------------|----------|--------|
| Syslog (RFC 5424) | UDP/TCP/TLS | Any SIEM, OSSEC/Wazuh agent |
| CEF (Common Event Format) | Syslog | ArcSight, QRadar, Splunk |
| Wazuh API | HTTPS REST | Wazuh manager |
| JSON over gRPC | gRPC stream | Custom integrations (already exists) |

### D6: Implement threat hunting capabilities

Retroactive analysis of historical traffic:

1. **PCAP ring buffer**: Rolling storage with configurable retention (time/size-based)
2. **Flow metadata indexing**: SQLite or DuckDB for fast historical queries
3. **IOC retrospective search**: Re-scan historical flows against updated TI/rules
4. **Retroactive ML analysis**: Re-analyze stored PCAPs with new models/rules
5. **Flow correlation**: Link related flows (same attacker, lateral movement)

## Consequences

### Positive

- **Single-tool comprehensive detection**: ML + signatures + YARA + TI + heuristics
  in one pipeline, with a unified scoring system
- **Active prevention**: Inline IPS mode blocks attacks instead of just alerting
- **SIEM integration**: Output sinks enable enterprise deployment alongside OSSEC/Wazuh
- **Threat hunting**: Historical analysis enables incident investigation

### Negative

- **Performance impact**: Payload inspection adds CPU cost. Signature matching on
  every packet at 10 Gbps requires Aho-Corasick / Hyperscan, not naive string search.
  Expected throughput drop: 10+ Gbps → 2-5 Gbps with signatures enabled.
- **Complexity**: The codebase grows significantly (~15K-25K additional lines)
- **Platform lock for IPS**: AF_PACKET inline mode is Linux-only. Passive mode
  (PcapPlusPlus) remains cross-platform.
- **Rule maintenance burden**: Snort + YARA rule sets need regular updates
- **False positive risk in IPS mode**: Blocking legitimate traffic is worse than
  missing an attack. Requires extensive testing and tuning.

### Mitigations

- **Layered enablement**: Each capability is independently toggleable:
  `--enable-signatures`, `--enable-yara`, `--inline`, `--enable-hunting`
- **Fail-open default**: Inline IPS defaults to forward-all, adding blocks only
  for high-confidence matches
- **Bypass manager**: Verified-benign flows bypass signature matching entirely
  (kernel-level forwarding after N clean packets)
- **Thread pool architecture**: Signature matching runs on dedicated thread pool,
  not on the capture thread
- **Hot reload**: Rules and TI feeds can be updated at runtime without restart

## Implementation Phases

| Phase | Feature | Dependencies | Effort |
|-------|---------|-------------|--------|
| 12 | SIEM output sinks (Syslog, CEF, Wazuh) | None | 4-5 weeks |
| 13 | Threat hunting (PCAP storage, retroactive analysis, IOC search) | SQLite/DuckDB | 6-8 weeks |
| 14 | YARA rules (libyara wrapper, TCP reassembly, pipeline integration) | libyara | 6-8 weeks |
| 15 | Snort rules (parser, Aho-Corasick, PCRE2, flowbits, pipeline) | PCRE2, optionally Hyperscan | 10-14 weeks |
| 16 | Inline IPS gateway (AF_PACKET, verdict engine, netfilter blocking) | Phase 15 (needs per-packet verdicts) | 13-18 weeks |

Total estimated effort: **40-55 weeks** (sequential), reducible with parallelization.

## New External Dependencies

| Library | Phase | Purpose | Conan Package | License |
|---------|-------|---------|---------------|---------|
| PCRE2 | 15 | Regex for Snort `pcre:` option | `pcre2/10.44` | BSD-3 |
| Hyperscan (optional) | 15 | High-performance multi-pattern matching | `hyperscan/5.4.2` | BSD-3 (Intel, x86_64 only) |
| libyara | 14 | YARA rule compilation + scanning | `yara/4.5.2` | BSD-3 |
| SQLite or DuckDB | 13 | Flow metadata indexing | `sqlite3/3.45.3` or `duckdb/1.1.0` | Public domain / MIT |
| libnetfilter_queue | 16 | NFQUEUE inline IPS (alternative to AF_PACKET) | System package | GPL-2 |

## Architecture Changes

### New interfaces in `core/services/`

```cpp
// core/services/ISignatureEngine.h
class ISignatureEngine {
public:
    virtual ~ISignatureEngine() = default;
    [[nodiscard]] virtual bool loadRules(const std::filesystem::path& path) = 0;
    [[nodiscard]] virtual bool reloadRules() = 0;
    [[nodiscard]] virtual std::vector<SignatureMatch> inspect(
        std::span<const std::uint8_t> payload,
        const FlowInfo& flow) = 0;
    [[nodiscard]] virtual std::size_t ruleCount() const noexcept = 0;
};

// core/services/IContentScanner.h
class IContentScanner {
public:
    virtual ~IContentScanner() = default;
    [[nodiscard]] virtual bool loadRules(const std::filesystem::path& path) = 0;
    [[nodiscard]] virtual std::vector<ContentMatch> scan(
        std::span<const std::uint8_t> data) = 0;
    [[nodiscard]] virtual std::size_t ruleCount() const noexcept = 0;
};

// core/services/IPcapStore.h
class IPcapStore {
public:
    virtual ~IPcapStore() = default;
    virtual void store(std::span<const std::uint8_t> packet, int64_t timestampUs) = 0;
    [[nodiscard]] virtual std::vector<StoredPacket> query(const HuntQuery& query) = 0;
    [[nodiscard]] virtual std::size_t sizeBytes() const noexcept = 0;
    virtual void evict(std::size_t targetBytes) = 0;
};
```

### Extended `DetectionSource` enum

```cpp
enum class DetectionSource : std::uint8_t {
    MlOnly = 0,
    ThreatIntel,
    HeuristicRule,
    SignatureMatch,     // NEW: Snort rule matched
    ContentScan,        // NEW: YARA rule matched
    Ensemble,           // Multiple sources combined
};
```

### Extended `DetectionResult`

```cpp
struct DetectionResult {
    PredictionResult mlResult;
    std::vector<ThreatIntelMatch> threatIntelMatches;
    std::vector<RuleMatch> ruleMatches;
    std::vector<SignatureMatch> signatureMatches;  // NEW
    std::vector<ContentMatch> contentMatches;       // NEW
    float combinedScore = 0.0f;
    AttackType finalVerdict = AttackType::Benign;
    DetectionSource detectionSource = DetectionSource::MlOnly;
};
```

### Updated `HybridDetectionService` weights

```
combinedScore = w_ml * mlScore
              + w_ti * tiScore
              + w_rules * ruleScore
              + w_sig * sigScore       // NEW
              + w_yara * yaraScore     // NEW
```

Default weights: ML=0.35, TI=0.20, Heuristic=0.10, Signatures=0.25, YARA=0.10.
All configurable via `Configuration` and weight tuning UI.

---

## References

- [Snort 3 Rule Writing Guide](https://docs.snort.org/rules/)
- [YARA Documentation](https://yara.readthedocs.io/)
- [Suricata AF_PACKET Inline Mode](https://docs.suricata.io/en/latest/setting-up-ipsinline-for-linux.html)
- [OSSEC Rule Syntax](https://www.ossec.net/docs/manual/rules-decoders/index.html)
- [Common Event Format (CEF)](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/cef-implementation-standard/)
- [PcapPlusPlus TcpReassembly](https://pcapplusplus.github.io/docs/api/classpcpp_1_1_tcp_reassembly.html)
