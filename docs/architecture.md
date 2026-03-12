# NIDS Architecture

## Overview

NIDS (Network Intrusion Detection System) is a desktop application that captures network
traffic, extracts flow-level features, and classifies each flow using a three-layer
hybrid detection system: ML classification (CNN-BiLSTM), threat intelligence (IP
reputation), and heuristic rules. It identifies 15 attack types plus benign traffic.

See also:
- **ADR-004**: Model benchmark analysis, dataset limitations, what flow-level NIDS
  can and cannot detect.
- **ADR-005**: Hybrid detection system design, escalation logic, combination weights.

---

## Detection Philosophy & Perimeter

### The core problem

Every detection method has blind spots:

- **Signature-based NIDS** (Snort, Suricata) are only as good as their rule sets.
  If no signature exists for an attack, it passes through undetected. Zero-day attacks
  and novel techniques are invisible until someone writes a rule.
- **ML-based NIDS** (our system) catches statistical anomalies that signatures miss,
  but cannot see what it cannot measure. Our flow-level features are header-only --
  they see packet sizes, timing, flags, and counts. They cannot see HTTP payloads,
  SQL queries, or JavaScript code.
- **Static threat intel** catches known-bad actors (C2 servers, botnet nodes) that
  both ML and signatures might miss if the traffic itself looks benign.
- **Heuristic rules** catch obvious red flags (suspicious ports, flood patterns,
  brute-force indicators) that ML might underweight or miss on rare patterns.

No single method is sufficient. **Defense-in-depth requires layering complementary
techniques.**

### What we do (our perimeter)

| Capability | How |
|---|---|
| Detect **statistical anomalies** in flow patterns | ML classifier (CNN-BiLSTM, 77 bidirectional flow features) |
| Catch **known-bad IP addresses** regardless of traffic pattern | Threat intelligence (5 free feeds, O(1) lookup) |
| Flag **obvious protocol/port anomalies** | Heuristic rules (7 hardcoded rules) |
| Provide **confidence-aware verdicts** | Full softmax probability distribution + combined score |
| Work **complementary** to Snort/Suricata/Zeek | Focus on what header/flow analysis does well |

### What we explicitly do NOT do

| Out of scope | Why | Who does this |
|---|---|---|
| HTTP payload parsing | Requires DPI, kills throughput, out of perimeter | WAFs (ModSecurity, AWS WAF) |
| Regex signature matching on packet payloads | That is Snort/Suricata's job | Snort, Suricata |
| Deep packet inspection | Drops throughput from 10+ Gbps to ~5 Gbps | Commercial DPI (Palo Alto, etc.) |
| Full protocol reconstruction | Complex, fragile, not our value-add | Zeek (protocol analysis) |
| Blocking / inline prevention | We are a detection system, not prevention | IPS mode in Snort/Suricata |

### The complementary deployment model

```
Internet Traffic
      │
      ▼
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Firewall   │────▶│ Snort/       │────▶│  NIDS       │
│  (iptables) │     │ Suricata     │     │  (our tool) │
└─────────────┘     │ (signatures) │     │  (ML+TI+    │
                    └──────────────┘     │   heuristics)│
                           │             └──────┬──────┘
                           │                    │
                    Catches known               Catches unknown
                    attack patterns             statistical anomalies
                    via signatures              + known-bad IPs
                                                + protocol red flags
```

Each tool covers the other's blind spots:
- Snort catches payload attacks (SQL injection, XSS) that we are blind to.
- We catch novel attacks with no signature, statistical anomalies, and known-bad IPs
  that Snort passes because no rule exists.
- Together: significantly fewer blind spots than either tool alone.

### Known limitations accepted (from ADR-004)

These are **structural** -- not fixable with a better model, only with DPI (which is
out of our perimeter):

| Problem | Root cause | FN rate | Our mitigation | External mitigation |
|---|---|---|---|---|
| SQL injection misclassified as Benign | Flow headers look identical to normal HTTP POST | 17.3% | TI lookup on source IP; heuristic flag if auth port | Snort/Suricata SQL injection rules; WAF |
| XSS misclassified as Benign | Same: payload-level attack, invisible at flow level | 10.7% | TI lookup; combined score threshold | WAF (ModSecurity), browser CSP |
| DoS <-> RCE bidirectional confusion | Both produce similar TCP burst patterns | ~30% cross-confusion | Both are attacks -- binary detection works (97.78% recall) | N/A (operational impact is low) |
| Fuzzing nearly undetectable | Only 462 test samples, overlaps DoS/ICMP | F1=0.49 | Heuristic rule on unusual port + high packet rate | Snort; application-level fuzzing detection |
| DDoS-ICMP <-> ICMP Flood confusion | Arguably the same attack at different scales | ~54% cross-confusion | Both are attacks -- binary detection unaffected | Consider merging classes in future |

---

## Layered Architecture (Clean Architecture)

Dependencies flow **inward only**: UI -> App -> Core, and Infra -> Core.

```
┌──────────────────────────────────────────────────────────────────┐
│                        ui/ (Qt6)                                 │
│   MainWindow, FilterPanel, PacketTableModel, HexView             │
├──────────────────────────────────────────────────────────────────┤
│                      app/ (Orchestration)                        │
│   CaptureController, AnalysisService, HybridDetectionService,   │
│   ReportGenerator                                                │
├──────────────────────────────────────────────────────────────────┤
│           core/ (Pure C++20, zero platform deps)                 │
│   PacketInfo, AttackType, PredictionResult, DetectionResult,     │
│   CaptureSession, PacketFilter, FlowInfo                        │
│   IPacketCapture, IPacketAnalyzer, IFlowExtractor,               │
│   IThreatIntelligence, IRuleEngine                               │
│   Configuration (singleton)                                      │
├──────────────────────────────────────────────────────────────────┤
│            infra/ (Platform-specific implementations)            │
│   PcapCapture, OnnxAnalyzer, NativeFlowExtractor,                │
│   ThreatIntelProvider, HeuristicRuleEngine,                      │
│   AnalyzerFactory, FeatureNormalizer, PcapHandle, NetworkHeaders  │
└──────────────────────────────────────────────────────────────────┘
```

| Layer    | May depend on                       | Must NOT depend on          |
|----------|-------------------------------------|-----------------------------|
| `core/`  | C++ Standard Library only           | Qt, pcap, OS headers, infra, app, ui |
| `infra/` | `core/`, OS/platform APIs, third-party C libs | `app/`, `ui/`  |
| `app/`   | `core/`, `infra/` (via interfaces)  | `ui/`, Qt widgets           |
| `ui/`    | `core/`, `app/`, Qt                 | direct pcap calls, OS headers |

---

## Data Flow (Hybrid Detection Pipeline)

```
Network Interface
      │
      ▼
┌─────────────┐     PacketCallback      ┌───────────────────┐
│ PcapCapture  │ ─────────────────────▶  │ CaptureController │
│ (infra)      │                         │ (app)             │
└─────────────┘                          └────────┬──────────┘
                                                  │ stores packets
                                                  ▼
                                          ┌──────────────┐
                                          │CaptureSession│
                                          │  (core)      │
                                          └──────┬───────┘
                                                 │ dump.pcap
                                                 ▼
                                   ┌───────────────────────┐
                                   │  NativeFlowExtractor  │
                                   │  (infra)              │
                                   └───────┬───────┬───────┘
                                           │       │
                               77 features  │       │  FlowInfo metadata
                               (in-memory)  │       │  (IPs, ports, flags)
                                           ▼       ▼
                                   ┌───────────────────┐
                                   │  AnalysisService   │
                                   │  (app)             │
                                   └───┬───┬───┬───────┘
                                       │   │   │
              ┌────────────────────────┘   │   └────────────────────────┐
              ▼                            ▼                            ▼
      ┌──────────────┐          ┌───────────────────┐         ┌─────────────────┐
      │ OnnxAnalyzer │          │ThreatIntelProvider │         │HeuristicRule    │
      │ (infra)      │          │ (infra)            │         │ Engine (infra)  │
      │              │          │                    │         │                 │
      │ predictWith  │          │ lookup(srcIp)      │         │ evaluate(flow)  │
      │ Confidence() │          │ lookup(dstIp)      │         │                 │
      └──────┬───────┘          └────────┬───────────┘         └───────┬─────────┘
             │                           │                             │
             │ PredictionResult          │ ThreatIntelMatch            │ RuleMatch
             │ (class + confidence       │ (IP + feed name)            │ (rule + severity)
             │  + probabilities)         │                             │
             └───────────┬───────────────┴─────────────┬───────────────┘
                         ▼                             ▼
                 ┌────────────────────────────────────────────┐
                 │         HybridDetectionService             │
                 │         (app)                              │
                 │                                            │
                 │  Escalation logic:                         │
                 │  - TI match always overrides benign ML     │
                 │  - Low ML confidence + rule match = flag   │
                 │  - High ML confidence alone = trust ML     │
                 │                                            │
                 │  combinedScore = w_ml*ML + w_ti*TI + w_h*H │
                 └────────────────────┬───────────────────────┘
                                      │
                                      ▼ DetectionResult
                              ┌──────────────┐
                              │CaptureSession│  stores DetectionResult
                              │  (core)      │  + legacy AttackType
                              └──────┬───────┘
                                     │
                        ┌────────────┴────────────┐
                        ▼                         ▼
                ┌──────────────┐          ┌───────────────┐
                │  MainWindow   │          │ReportGenerator│
                │  (ui)         │          │  (app)        │
                └──────────────┘          └───────────────┘
```

---

## Key Design Patterns

### Strategy Pattern
Protocol parsers and ML backends implement common interfaces (`IPacketAnalyzer`,
`IFlowExtractor`, `IThreatIntelligence`, `IRuleEngine`). New backends can be added
without modifying consuming code.

### Observer Pattern (Qt Signals/Slots)
Cross-component communication uses Qt signals:
- `CaptureController::packetReceived` -> `MainWindow` updates table
- `AnalysisService::analysisProgress` -> `MainWindow` updates progress bar
- `CaptureController::captureError` -> `MainWindow` shows error dialog

### Factory Method
`AnalyzerFactory::createAnalyzer()` creates the appropriate ML backend. Currently only
ONNX Runtime; additional backends (TensorRT, OpenVINO) can be added without modifying
calling code.

### RAII Wrappers
Every C resource is wrapped in `std::unique_ptr` with a custom deleter:
- `PcapHandle` wraps `pcap_t*` with `pcap_close`
- `PcapDumper` wraps `pcap_dumper_t*` with `pcap_dump_close`
- ONNX Runtime session managed by `Impl` struct in `OnnxAnalyzer`

### Meyers Singleton
`Configuration` provides centralized config via thread-safe static initialization.
Eliminates scattered magic strings and numbers.

### Repository Pattern
`CaptureSession` stores packets, analysis results (`AttackType`), and full detection
results (`DetectionResult`) with thread-safe access via `std::mutex` + `std::scoped_lock`.

---

## Hybrid Detection System

### Three detection layers

| Layer | What it detects | Blind spots |
|---|---|---|
| **ML Classifier** | Statistical anomalies in flow patterns (DDoS, port scan, brute force, flooding) | Payload-based attacks (SQLi, XSS), known-bad IPs with benign-looking traffic |
| **Threat Intelligence** | Known-bad IP addresses (C2, botnets, spam) regardless of traffic pattern | Novel attackers not yet in any blocklist |
| **Heuristic Rules** | Obvious protocol red flags (suspicious ports, SYN floods, ICMP floods, brute force patterns) | Sophisticated attacks that mimic normal traffic |

### Escalation model

The `HybridDetectionService` combines signals with escalation logic (full table in
ADR-005):

1. **ML says attack with high confidence** -> trust ML classification
2. **ML says benign but TI matches** -> **override to suspicious** (this is the key
   defense against known-bad actors with benign-looking traffic)
3. **ML says benign with low confidence + heuristic rule fires** -> escalate based on
   rule severity
4. **All three agree benign** -> benign

### Combined threat score

```
combinedScore = w_ml * mlScore + w_ti * tiScore + w_rules * ruleScore
```

Default weights: ML=0.5, TI=0.3, Heuristic=0.2. Configurable via `Configuration`.

### Threat intelligence feeds (5 free sources)

| Feed | What it covers | Update frequency |
|---|---|---|
| abuse.ch Feodo Tracker | C2 botnet IPs | Updated every 5 min |
| Spamhaus DROP/EDROP | Known bad CIDR ranges | Updated daily |
| EmergingThreats | Compromised IPs | Updated daily |
| CINS Score | Bad actor IPs | Updated hourly |
| Blocklist.de | Reported attack IPs | Updated frequently |

Updated via `scripts/ops/update_threat_feeds.sh`, loaded at startup from
`data/threat_intel/`.

### Heuristic rules (7 rules)

| Rule | What it catches | Severity |
|---|---|---|
| `suspicious_port` | Traffic to known-malicious ports (4444, 31337, 6667, etc.) | 0.6 |
| `syn_flood` | High SYN count with low ACK ratio | 0.8 |
| `icmp_flood` | Excessive ICMP packets from one source | 0.7 |
| `brute_force` | Many short connections to auth ports (22, 21, 3389) | 0.7 |
| `high_packet_rate` | Abnormally high packets/sec in a single flow | 0.5 |
| `reset_flood` | High RST flag count (connection abuse) | 0.6 |
| `port_scan` | Many distinct destination ports from same source | 0.7 |

---

## Threading Model

- **Packet capture**: QThread + worker object pattern (per AGENTS.md).
  `PcapCapture` runs the capture loop on a separate QThread. Packets are delivered
  to the main thread via `Qt::QueuedConnection` signals.
- **Analysis**: Currently synchronous on the calling thread. Future work may move
  this to a dedicated worker thread.
- **Shared state**: `CaptureSession` protects all access with `std::mutex`.
- **Atomics**: Simple flags and counters use `std::atomic<>`.

---

## ML Pipeline

1. **Feature Extraction**: `NativeFlowExtractor` reads a pcap file and computes
   77 bidirectional flow features (duration, packet counts, byte statistics, flags,
   inter-arrival times, etc.). Also retains per-flow metadata (`FlowInfo`) for TI
   lookups and heuristic rules.
2. **Normalization**: `FeatureNormalizer` applies StandardScaler parameters from
   `model_metadata.json` (mean/std computed during training).
3. **Inference**: `OnnxAnalyzer::predictWithConfidence()` creates an ONNX Runtime
   session, feeds a `(1, 77)` tensor, receives softmax probabilities over 16 classes.
   Returns `PredictionResult` with classification, confidence, and full probability
   distribution.
4. **Hybrid evaluation**: `HybridDetectionService::evaluate()` combines ML result
   with TI lookups and heuristic rules to produce `DetectionResult`.
5. **Storage**: `CaptureSession` stores both the legacy `AttackType` (for backward
   compatibility) and the full `DetectionResult`.

---

## Configuration

The `Configuration` singleton centralizes all runtime parameters:
- Model path and metadata path
- ONNX Runtime thread count
- Flow timeout and idle threshold
- Default dump file name
- Threat intelligence directory
- Hybrid detection weights (ML, TI, heuristic)
- ML confidence threshold
- Window title

Optional JSON config file can override defaults via `loadFromFile()`.

---

## Error Handling

- **Return types**: `[[nodiscard]] bool` for fallible operations. `std::optional<T>`
  for absent values.
- **Logging**: spdlog at all layers. Levels: trace, debug, info, warn, error, critical.
- **Graceful degradation**: If threat intel feeds are missing, system runs ML-only.
  If model is not loaded, analysis is unavailable. If normalization metadata is missing,
  raw features are used with a warning.
- **Signal propagation**: Errors in `PcapCapture` are forwarded via `ErrorCallback` ->
  `CaptureController::captureError` signal -> `MainWindow` error dialog.
- **Analysis errors**: `AnalysisService` emits both `analysisError` and `analysisFinished`
  to prevent stuck UI spinners.
