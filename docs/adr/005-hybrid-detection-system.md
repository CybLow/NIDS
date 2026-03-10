# ADR-005: Hybrid Detection System (ML + Threat Intelligence + Heuristics)

## Status

Accepted -- Fully implemented and integrated into the analysis pipeline.

## Related

- **ADR-004**: Documents the ML model limitations that motivated this hybrid system.
  The "Mitigations already implemented" section in ADR-004 maps each limitation to its
  hybrid detection mitigation and remaining gap.
- **docs/architecture.md**: "Detection Philosophy & Perimeter" section documents the
  complementary deployment model and what is explicitly out of scope.

## Context

The NIDS currently relies exclusively on a flow-level ML classifier (CNN-LSTM via ONNX
Runtime) to distinguish benign traffic from 15 attack types. While the model achieves
87.78% accuracy and 97.78% binary attack recall on the LSNM2024 test set, ML-only
detection has fundamental limitations:

1. **Known-bad actors bypass**: An IP address listed on every threat intel feed in the
   world can pass undetected if its flow statistics happen to resemble benign traffic
   (e.g., a C2 beacon with low-volume, periodic connections).
2. **No confidence visibility**: `OnnxAnalyzer::predict()` performs argmax and discards
   the full probability distribution. A prediction with 51% confidence is treated
   identically to one with 99.9%.
3. **Payload-blind attacks**: SQL injection and XSS produce flow-level features nearly
   identical to normal HTTP traffic (documented FN rates: 17.3% and 10.7% respectively
   in ADR-004). Static rules can flag these by protocol/port heuristics even when ML
   is uncertain.
4. **Single point of failure**: Any single detection method has blind spots. Defense-in-
   depth requires layering complementary techniques.

This mirrors the real-world gap the user identified: "Snort is great but not perfect
because if no rules are set on signatures it will pass -- and the same for my program."

### Design Constraints

- **Stay within perimeter**: This is a flow/connection-level NIDS, NOT a WAF or DPI
  engine. No HTTP payload parsing, no regex signature matching on packet payloads.
- **Complementary to Suricata/Snort/Zeek**: Focus on what header/flow analysis can do
  well. Leave payload inspection to dedicated tools.
- **Offline-first**: Current pipeline is batch (post-capture). Hybrid detection follows
  the same batch model. Real-time detection is a future enhancement.

## Decision

Implement a three-layer hybrid detection system:

```
                    +---------------------------+
                    |  HybridDetectionService   |   (app/ layer - orchestrator)
                    +---------------------------+
                   /             |               \
                  v              v                v
    +----------------+  +------------------+  +-----------------+
    | IPacketAnalyzer|  | IThreatIntel     |  | IRuleEngine     |
    | (ML inference) |  | (IP reputation)  |  | (heuristics)    |
    +----------------+  +------------------+  +-----------------+
    | OnnxAnalyzer   |  | ThreatIntelProv. |  | HeuristicRule   |
    | (infra/)       |  | (infra/)         |  | Engine (infra/) |
    +----------------+  +------------------+  +-----------------+
```

### Layer 1: ML Classification (existing, enhanced)

- **Change**: `IPacketAnalyzer::predict()` returns `PredictionResult` (class + full
  probability vector) instead of bare `AttackType`.
- The export wrapper already applies softmax, so output values are true probabilities.
- Confidence = max probability. Low confidence (< threshold) triggers escalation.

### Layer 2: Threat Intelligence (new)

- `IThreatIntelligence` interface in `core/services/` for IP reputation lookups.
- `ThreatIntelProvider` in `infra/threat/` loads plain-text IP blocklists:
  - abuse.ch Feodo Tracker (C2 botnet IPs)
  - Spamhaus DROP (known bad CIDR ranges)
  - EmergingThreats compromised IPs
  - CINS Score bad actors
  - Blocklist.de reported IPs
- Storage: `std::unordered_set<std::uint32_t>` for individual IPs (O(1) lookup),
  sorted vector of CIDR ranges with binary search for prefix matching.
- Refresh: `scripts/update_threat_feeds.sh` downloads latest feeds to
  `data/threat_intel/`. Loaded at startup.

### Layer 3: Heuristic Rules (new)

- `IRuleEngine` interface in `core/services/` for rule evaluation.
- `HeuristicRuleEngine` in `infra/rules/` implements:
  - **Known suspicious ports**: 4444 (Metasploit default), 5555, 31337 (Back Orifice),
    6666-6669 (IRC C2), 1337, 12345, 54321.
  - **Protocol anomalies**: SYN flood signature (high SYN count + low established
    connections from same source), ICMP flood (excessive ICMP from one source).
  - **Port scan detection**: Many distinct destination ports from same source IP within
    a flow set.
  - **Brute force indicators**: Many short-lived connections to authentication ports
    (22/SSH, 21/FTP, 3389/RDP) from the same source.
- Rules operate on flow metadata (IPs, ports, protocol, basic flow stats), NOT packet
  payloads.

### Orchestration: HybridDetectionService (new)

Located in `app/`, this service combines all three signals into a unified
`DetectionResult`:

```
DetectionResult {
    AttackType mlClassification;       // ML model's top prediction
    float      mlConfidence;           // max softmax probability
    bool       threatIntelMatch;       // source or dest IP in blocklist
    std::string threatIntelSource;     // which feed matched (e.g., "feodo")
    std::vector<std::string> ruleMatches; // which heuristic rules fired
    AttackType finalVerdict;           // combined decision
    float      combinedScore;          // unified threat score [0.0, 1.0]
    DetectionSource detectionSource;   // what drove the final verdict
}
```

**Combination logic (escalation model)**:

| ML says | TI match? | Rules fire? | Final verdict |
|---------|-----------|-------------|---------------|
| Attack (high conf) | N/A | N/A | ML classification |
| Attack (low conf) | Yes | N/A | Escalate to ML classification |
| Attack (low conf) | No | Yes | Escalate to ML classification |
| Attack (low conf) | No | No | ML classification (with low-confidence flag) |
| Benign (high conf) | Yes | N/A | **Override to suspicious** (TI match) |
| Benign (high conf) | No | Yes | Flag for review |
| Benign (low conf) | Yes | N/A | **Override to suspicious** (TI + low conf) |
| Benign (low conf) | No | Yes | Escalate based on rule severity |
| Benign (high conf) | No | No | Benign |

Key principle: **TI match always escalates**. A known-bad IP classified as benign is
more likely a false negative than a reformed actor.

### Combined Score Calculation

```
combinedScore = w_ml * mlScore + w_ti * tiScore + w_rules * ruleScore
```

Where:
- `mlScore` = 1.0 - confidence if benign, confidence if attack
- `tiScore` = 1.0 if IP in blocklist, 0.0 otherwise
- `ruleScore` = max severity of matching rules (0.0 to 1.0)
- Default weights: `w_ml = 0.5`, `w_ti = 0.3`, `w_rules = 0.2`

Configurable via `Configuration` singleton.

## New Files

### Core layer (`core/`)
- `core/model/DetectionResult.h` -- Unified detection result struct
- `core/model/PredictionResult.h` -- ML prediction with confidence
- `core/services/IThreatIntelligence.h` -- Threat intel lookup interface
- `core/services/IRuleEngine.h` -- Heuristic rule engine interface

### Infrastructure layer (`infra/`)
- `infra/threat/ThreatIntelProvider.h` -- IP blocklist loader + lookup
- `infra/threat/ThreatIntelProvider.cpp`
- `infra/rules/HeuristicRuleEngine.h` -- Port/rate/pattern rule engine
- `infra/rules/HeuristicRuleEngine.cpp`

### Application layer (`app/`)
- `app/HybridDetectionService.h` -- Orchestrator
- `app/HybridDetectionService.cpp`

### Scripts
- `scripts/update_threat_feeds.sh` -- Downloads latest threat intel feeds

### Data
- `data/threat_intel/` -- Directory for downloaded feed files

## Consequences

### Positive
- Defense-in-depth: three independent detection layers cover each other's blind spots.
- Known-bad IPs caught immediately regardless of flow statistics.
- Low-confidence ML predictions get corroborating (or contradicting) evidence.
- Confidence scores enable graduated response (alert vs. block vs. log).
- All new code follows existing Clean Architecture (interfaces in core, implementations
  in infra, orchestration in app).
- No payload inspection = stays within design perimeter, complementary to Snort/Suricata.

### Negative
- Threat intel feeds require periodic updates (stale feeds = missed detections).
- Heuristic rules may generate false positives on legitimate traffic to unusual ports.
- Additional startup time for loading blocklists (~100ms for typical feed sizes).
- Increased code complexity (3 detection paths vs. 1).

### Mitigations
- Default threat intel path is optional; system works ML-only if feeds are missing.
- Heuristic rules have configurable severity thresholds.
- Blocklists loaded asynchronously in future real-time mode.
- Clear `DetectionSource` field in results enables debugging which layer flagged traffic.

### What this does NOT solve (out of perimeter -- see architecture.md)

The hybrid system mitigates many ML-only blind spots but does NOT address:

1. **Payload-based attack detection** (SQL injection, XSS). These require DPI or WAF
   capabilities that are outside our perimeter. Deploy Snort/Suricata/ModSecurity
   alongside this NIDS to cover application-layer attacks.
2. **Zero-day IPs not in any feed**. Novel attackers with no reputation history will only
   be caught by ML statistical analysis (if their traffic patterns are anomalous).
3. **Encrypted traffic analysis**. TLS-encrypted payloads are invisible to all layers.
   JA3/JA4 fingerprinting could be a future addition for TLS metadata analysis.
4. **Concept drift**. If attack patterns change significantly from the training data, ML
   accuracy will degrade. Periodic retraining on fresh datasets is required.
