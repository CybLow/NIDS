# Phase 15: Snort Rules Compatibility

> **Effort**: 10–14 weeks | **Dependencies**: PCRE2, optionally Hyperscan | **Risk**: High
>
> **Goal**: Implement a Snort 3.x-compatible rule engine that performs per-packet
> signature matching with content inspection, regex support, flow state tracking,
> and cross-rule correlation via flowbits.

---

## Motivation

Snort rules are the most widely used signature format in network intrusion detection.
The Emerging Threats (ET) Open ruleset alone contains 40,000+ signatures covering:

- Known CVE exploits
- Malware command-and-control protocols
- Web application attacks (SQLi, XSS, RCE)
- Protocol anomalies and policy violations
- Trojan/backdoor communication patterns
- DNS tunneling and data exfiltration

Snort rules provide **per-packet** verdicts, complementing the NIDS ML classifier
which operates at the **per-flow** level. This is critical for inline IPS mode
(Phase 16), where immediate packet-level decisions are required.

---

## Architecture

### Layer placement

| Component | Layer | Rationale |
|-----------|-------|-----------|
| `ISignatureEngine` | `core/services/` | Interface — no platform deps |
| `SignatureMatch` | `core/model/` | Match result model |
| `SnortRule` | `core/model/` | Parsed rule AST |
| `SnortRuleParser` | `infra/rules/` | Snort syntax parser |
| `SnortRuleEngine` | `infra/rules/` | Rule evaluation engine |
| `ContentMatcher` | `infra/rules/` | Aho-Corasick multi-pattern |
| `PcreEngine` | `infra/rules/` | PCRE2 regex wrapper |
| `FlowStateTracker` | `infra/rules/` | TCP connection state |
| `FlowbitsManager` | `infra/rules/` | Cross-rule state machine |
| `RuleVariableStore` | `infra/rules/` | `$HOME_NET` etc. resolution |
| Rule files | `data/rules/` | ET Open + custom |

### Data flow

```
Raw Packet
    │
    ▼
┌────────────────────┐
│ SnortRuleEngine    │
│                    │
│ 1. Header match    │ ── protocol, IP, port (fast pre-filter)
│    (O(1) lookup)   │
│                    │
│ 2. Content match   │ ── Aho-Corasick multi-pattern on payload
│    (Aho-Corasick)  │
│                    │
│ 3. PCRE match      │ ── regex verification (only if content matched)
│    (PCRE2)         │
│                    │
│ 4. Flow state      │ ── established/to_server/to_client check
│    check           │
│                    │
│ 5. Flowbits eval   │ ── cross-rule state (set/isset/toggle)
│                    │
│ 6. Threshold       │ ── rate-based triggering
│                    │
└────────┬───────────┘
         │
         ▼ std::vector<SignatureMatch>
┌────────────────────┐
│ HybridDetection    │
│ Service            │
│ (5-layer scoring)  │
└────────────────────┘
```

---

## Component Specifications

### 15.1 — ISignatureEngine Interface

**File**: `src/core/services/ISignatureEngine.h`

```cpp
#pragma once

#include "core/model/FlowInfo.h"

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace nids::core {

/// Result of a signature rule match.
struct SignatureMatch {
    std::uint32_t sid = 0;       ///< Snort ID (unique rule identifier)
    std::uint32_t rev = 0;       ///< Rule revision
    std::string msg;             ///< Alert message
    std::string classtype;       ///< Classification (e.g., "web-application-attack")
    int priority = 3;            ///< Priority (1=highest, 4=lowest)
    float severity = 0.0f;       ///< Normalized severity (0.0-1.0)

    /// References (CVE, bugtraq, URL)
    struct Reference {
        std::string type;   ///< "cve", "bugtraq", "url"
        std::string value;  ///< "2024-1234", "http://..."
    };
    std::vector<Reference> references;

    /// Metadata tags
    std::vector<std::pair<std::string, std::string>> metadata;
};

/// Interface for signature-based packet inspection.
class ISignatureEngine {
public:
    virtual ~ISignatureEngine() = default;

    /// Load rules from a file or directory.
    [[nodiscard]] virtual bool loadRules(
        const std::filesystem::path& path) = 0;

    /// Reload all rules from previously loaded paths.
    [[nodiscard]] virtual bool reloadRules() = 0;

    /// Inspect a packet payload against loaded rules.
    /// @param payload  Raw packet payload bytes (after L3/L4 headers)
    /// @param flow     Flow context (IPs, ports, protocol, direction)
    /// @return Matching signatures (empty if no match)
    [[nodiscard]] virtual std::vector<SignatureMatch> inspect(
        std::span<const std::uint8_t> payload,
        const FlowInfo& flow) = 0;

    /// Number of loaded rules.
    [[nodiscard]] virtual std::size_t ruleCount() const noexcept = 0;

    /// Number of loaded rule files.
    [[nodiscard]] virtual std::size_t fileCount() const noexcept = 0;

    /// Set rule variable (e.g., $HOME_NET = "192.168.0.0/16")
    virtual void setVariable(std::string_view name,
                             std::string_view value) = 0;
};

} // namespace nids::core
```

### 15.2 — SnortRule (Parsed Rule AST)

**File**: `src/core/model/SnortRule.h`

```cpp
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace nids::core {

/// Parsed representation of a Snort rule.
struct SnortRule {
    // -- Header --
    enum class Action : std::uint8_t {
        Alert, Log, Pass, Drop, Reject, SDrop
    };
    Action action = Action::Alert;

    std::uint8_t protocol = 0;   // IPPROTO_TCP, etc.
    std::string srcIp;           // may be variable ($HOME_NET)
    std::string srcPort;         // "any", "80", "[80,443]", "1024:"
    std::string dstIp;
    std::string dstPort;
    bool bidirectional = false;  // <> vs ->

    // -- Options --

    /// Content match option
    struct ContentOption {
        std::vector<std::uint8_t> pattern;  // byte pattern (text or hex)
        bool nocase = false;
        bool negated = false;               // ! prefix
        std::optional<int> offset;
        std::optional<int> depth;
        std::optional<int> distance;
        std::optional<int> within;
        enum class Position { Raw, HttpUri, HttpHeader, HttpBody, HttpMethod,
                              HttpCookie, HttpStatCode, HttpStatMsg } position = Position::Raw;
    };

    /// PCRE match option
    struct PcreOption {
        std::string pattern;         // regex pattern
        std::string modifiers;       // "i", "s", "m", etc.
        bool negated = false;
        bool relative = false;       // "R" modifier
    };

    /// Flow option
    struct FlowOption {
        bool established = false;
        bool stateless = false;
        enum class Direction { Any, ToServer, ToClient, FromServer, FromClient }
            direction = Direction::Any;
    };

    /// Flowbits option
    struct FlowbitsOption {
        enum class Command { Set, Isset, Unset, Toggle, Noalert, IsnotSet }
            command = Command::Set;
        std::string name;
        std::optional<std::string> group;
    };

    /// Threshold / detection_filter option
    struct ThresholdOption {
        enum class Type { Limit, Threshold, Both } type = Type::Limit;
        enum class Track { BySrc, ByDst } track = Track::BySrc;
        int count = 1;
        int seconds = 60;
    };

    // Collected options
    std::vector<ContentOption> contents;
    std::vector<PcreOption> pcres;
    std::optional<FlowOption> flow;
    std::vector<FlowbitsOption> flowbits;
    std::optional<ThresholdOption> threshold;

    // Metadata
    std::uint32_t sid = 0;
    std::uint32_t rev = 1;
    std::string msg;
    std::string classtype;
    int priority = 3;
    std::vector<std::pair<std::string, std::string>> references;
    std::vector<std::pair<std::string, std::string>> metadata;

    // For fast filtering — precomputed from header
    bool isEnabled = true;
};

} // namespace nids::core
```

### 15.3 — SnortRuleParser

**Purpose**: Parse Snort 3.x rule syntax into `SnortRule` AST.

**Files**: `src/infra/rules/SnortRuleParser.h`, `src/infra/rules/SnortRuleParser.cpp`

```cpp
class SnortRuleParser {
public:
    /// Parse a single rule line (may span multiple lines with '\')
    [[nodiscard]] std::expected<SnortRule, std::string> parse(
        std::string_view ruleText) const;

    /// Parse all rules from a file
    [[nodiscard]] std::expected<std::vector<SnortRule>, std::string> parseFile(
        const std::filesystem::path& path) const;

    /// Parse all .rules files in a directory
    [[nodiscard]] std::expected<std::vector<SnortRule>, std::string> parseDirectory(
        const std::filesystem::path& dir) const;

    /// Statistics from last parse
    struct ParseStats {
        std::size_t totalLines = 0;
        std::size_t parsedRules = 0;
        std::size_t skippedComments = 0;
        std::size_t parseErrors = 0;
        std::vector<std::string> errors;  // per-line error messages
    };
    [[nodiscard]] const ParseStats& lastStats() const noexcept;

private:
    [[nodiscard]] std::expected<SnortRule, std::string> parseHeader(
        std::string_view header) const;
    [[nodiscard]] std::expected<void, std::string> parseOptions(
        std::string_view options, SnortRule& rule) const;
    [[nodiscard]] std::expected<SnortRule::ContentOption, std::string> parseContent(
        std::string_view value) const;
    [[nodiscard]] std::expected<SnortRule::PcreOption, std::string> parsePcre(
        std::string_view value) const;
    [[nodiscard]] std::vector<std::uint8_t> parseHexContent(
        std::string_view hex) const;

    mutable ParseStats stats_;
};
```

**Parsing strategy**:

1. Skip comments (`#`) and blank lines
2. Extract header: `action protocol src_ip src_port direction dst_ip dst_port`
3. Extract options block: everything inside `(...)`
4. Tokenize options by `;` (handling escaped semicolons)
5. Parse each `key:value` option pair
6. For `content:` — handle `|hex|` patterns, modifiers (nocase, offset, depth, etc.)
7. For `pcre:` — extract `/pattern/modifiers`
8. Resolve content modifiers that apply to the preceding content

### 15.4 — ContentMatcher (Aho-Corasick Multi-Pattern Search)

**Purpose**: Fast multi-pattern search across packet payloads. When 10,000+ rules
each have content patterns, naive string search is unacceptable.

**Files**: `src/infra/rules/ContentMatcher.h`, `src/infra/rules/ContentMatcher.cpp`

```cpp
/// A compiled multi-pattern matcher for Snort content options.
class ContentMatcher {
public:
    /// Add a pattern associated with a rule SID + content index
    void addPattern(std::span<const std::uint8_t> pattern,
                    std::uint32_t sid,
                    std::size_t contentIndex,
                    bool nocase = false);

    /// Compile all patterns into the automaton. Must be called after all
    /// patterns are added and before any search() calls.
    void compile();

    /// Search payload for all matching patterns.
    /// Returns: vector of (sid, contentIndex, offset) tuples
    struct MatchInfo {
        std::uint32_t sid;
        std::size_t contentIndex;
        std::size_t offset;
    };
    [[nodiscard]] std::vector<MatchInfo> search(
        std::span<const std::uint8_t> payload) const;

    /// Number of patterns in the automaton
    [[nodiscard]] std::size_t patternCount() const noexcept;

private:
    // Aho-Corasick automaton state
    struct State {
        std::array<int, 256> transitions{};
        int failureLink = 0;
        std::vector<std::pair<std::uint32_t, std::size_t>> outputs;  // (sid, contentIdx)
    };

    std::vector<State> states_;
    bool compiled_ = false;

    void buildFailureLinks();
};
```

**Alternative: Hyperscan** (Intel high-performance regex engine):

If Hyperscan is available (x86_64 only), use it as a drop-in replacement for both
content matching and PCRE. Hyperscan compiles all patterns (fixed strings + regex)
into a single DFA and scans in a single pass — significantly faster than
Aho-Corasick + PCRE separately.

```cpp
#ifdef NIDS_HAVE_HYPERSCAN
using PatternMatcher = HyperscanMatcher;
#else
using PatternMatcher = AhoCorasickMatcher;
#endif
```

### 15.5 — PcreEngine (PCRE2 Wrapper)

**Purpose**: Execute PCRE regex patterns against packet payloads.

**Files**: `src/infra/rules/PcreEngine.h`, `src/infra/rules/PcreEngine.cpp`

```cpp
class PcreEngine {
public:
    PcreEngine();
    ~PcreEngine();

    /// Compile a PCRE pattern
    [[nodiscard]] std::expected<std::size_t, std::string> compile(
        std::string_view pattern,
        std::string_view modifiers);

    /// Execute a compiled pattern against data
    [[nodiscard]] bool match(std::size_t patternId,
                             std::span<const std::uint8_t> data,
                             std::size_t startOffset = 0) const;

    /// Execute with capture groups
    struct MatchResult {
        bool matched;
        std::size_t offset;
        std::size_t length;
        std::vector<std::pair<std::size_t, std::size_t>> groups;
    };
    [[nodiscard]] MatchResult matchWithCapture(
        std::size_t patternId,
        std::span<const std::uint8_t> data,
        std::size_t startOffset = 0) const;

private:
    struct CompiledPattern {
        pcre2_code* code = nullptr;      // RAII via custom deleter
        pcre2_match_data* matchData = nullptr;
    };
    std::vector<CompiledPattern> patterns_;
};
```

### 15.6 — FlowStateTracker

**Purpose**: Track TCP connection states for Snort `flow:` option evaluation.

**Files**: `src/infra/rules/FlowStateTracker.h`, `src/infra/rules/FlowStateTracker.cpp`

```cpp
/// Per-flow TCP connection state.
struct FlowState {
    enum class State : std::uint8_t {
        New,            // SYN seen, no SYN-ACK yet
        Established,    // 3-way handshake complete
        Closing,        // FIN or RST seen
        Closed
    };

    State state = State::New;
    bool clientInitiated = true;   // who sent the first SYN

    // Track which direction the current packet is going
    enum class Direction : std::uint8_t { ToServer, ToClient };
};

class FlowStateTracker {
public:
    /// Update flow state based on a packet
    void update(const FlowKey& key, std::uint8_t tcpFlags,
                bool isFromInitiator);

    /// Get current state for a flow
    [[nodiscard]] std::optional<FlowState> getState(
        const FlowKey& key) const;

    /// Check if a packet matches a flow option
    [[nodiscard]] bool matches(const FlowKey& key,
                               const SnortRule::FlowOption& option,
                               bool isFromInitiator) const;

    /// Expire old flows
    void sweepExpired(int64_t nowUs, int64_t timeoutUs);

private:
    std::unordered_map<FlowKey, FlowState, FlowKeyHash> states_;
    mutable std::mutex mutex_;
};
```

### 15.7 — FlowbitsManager

**Purpose**: Cross-rule stateful correlation. Rules can set/check bits per-flow
that other rules depend on.

**Files**: `src/infra/rules/FlowbitsManager.h`, `src/infra/rules/FlowbitsManager.cpp`

```cpp
class FlowbitsManager {
public:
    /// Set a flowbit for a flow
    void set(const FlowKey& key, std::string_view bitName);

    /// Unset a flowbit
    void unset(const FlowKey& key, std::string_view bitName);

    /// Toggle a flowbit
    void toggle(const FlowKey& key, std::string_view bitName);

    /// Check if a flowbit is set
    [[nodiscard]] bool isSet(const FlowKey& key,
                              std::string_view bitName) const;

    /// Check if a flowbit is NOT set
    [[nodiscard]] bool isNotSet(const FlowKey& key,
                                 std::string_view bitName) const;

    /// Clear all bits for a flow (on flow expiry)
    void clearFlow(const FlowKey& key);

    /// Sweep expired flow bits
    void sweepExpired(int64_t nowUs, int64_t timeoutUs);

private:
    std::unordered_map<FlowKey,
        std::unordered_set<std::string>,
        FlowKeyHash> bits_;
    mutable std::mutex mutex_;
};
```

**Use case example** (multi-stage SQL injection detection):

```
Rule 1: alert tcp ... (content:"GET"; flow:to_server,established;
         content:"/login.php"; flowbits:set,login_page; ...)
Rule 2: alert tcp ... (flow:to_server,established;
         flowbits:isset,login_page;
         content:"UNION"; content:"SELECT"; nocase;
         msg:"SQL Injection on login page"; ...)
```

Rule 2 only fires if Rule 1 previously matched on the same flow.

### 15.8 — RuleVariableStore

**Purpose**: Resolve Snort variables (`$HOME_NET`, `$EXTERNAL_NET`, etc.)

**Files**: `src/infra/rules/RuleVariableStore.h`, `src/infra/rules/RuleVariableStore.cpp`

```cpp
class RuleVariableStore {
public:
    /// Set a variable value
    void set(std::string_view name, std::string_view value);

    /// Resolve a variable reference (returns the value, or the
    /// input unchanged if not a variable)
    [[nodiscard]] std::string resolve(std::string_view ref) const;

    /// Check if an IP matches a variable value (handles CIDR, groups, negation)
    [[nodiscard]] bool ipMatches(std::string_view ip,
                                  std::string_view spec) const;

    /// Check if a port matches a variable value (handles ranges, groups, negation)
    [[nodiscard]] bool portMatches(std::uint16_t port,
                                    std::string_view spec) const;

    /// Load default Snort variables from a config file
    [[nodiscard]] bool loadConfig(const std::filesystem::path& path);

private:
    std::unordered_map<std::string, std::string> vars_;
};
```

**Default variables** (configured via JSON):

```json
{
  "signatures": {
    "variables": {
      "HOME_NET": "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12",
      "EXTERNAL_NET": "!$HOME_NET",
      "HTTP_PORTS": "80,443,8080,8443",
      "SSH_PORTS": "22",
      "DNS_PORTS": "53",
      "SMTP_PORTS": "25,587,465"
    }
  }
}
```

### 15.9 — SnortRuleEngine (Main Orchestrator)

**Files**: `src/infra/rules/SnortRuleEngine.h`, `src/infra/rules/SnortRuleEngine.cpp`

```cpp
class SnortRuleEngine : public core::ISignatureEngine {
public:
    SnortRuleEngine();
    ~SnortRuleEngine() override;

    [[nodiscard]] bool loadRules(
        const std::filesystem::path& path) override;
    [[nodiscard]] bool reloadRules() override;

    [[nodiscard]] std::vector<core::SignatureMatch> inspect(
        std::span<const std::uint8_t> payload,
        const core::FlowInfo& flow) override;

    [[nodiscard]] std::size_t ruleCount() const noexcept override;
    [[nodiscard]] std::size_t fileCount() const noexcept override;

    void setVariable(std::string_view name,
                     std::string_view value) override;

private:
    /// Pre-filter rules by protocol/port (avoids evaluating all 40K rules
    /// for every packet)
    [[nodiscard]] std::vector<const core::SnortRule*> preFilter(
        const core::FlowInfo& flow) const;

    /// Evaluate a single rule against payload + flow
    [[nodiscard]] bool evaluateRule(
        const core::SnortRule& rule,
        std::span<const std::uint8_t> payload,
        const core::FlowInfo& flow) const;

    /// Check all content options (using Aho-Corasick + position modifiers)
    [[nodiscard]] bool checkContents(
        const core::SnortRule& rule,
        std::span<const std::uint8_t> payload,
        const std::vector<ContentMatcher::MatchInfo>& acMatches) const;

    SnortRuleParser parser_;
    ContentMatcher contentMatcher_;
    PcreEngine pcreEngine_;
    FlowStateTracker flowTracker_;
    FlowbitsManager flowbits_;
    RuleVariableStore variables_;

    // Rules organized for fast lookup
    std::vector<core::SnortRule> rules_;
    // Port-group index: protocol → dst_port → rule indices
    std::unordered_map<std::uint8_t,
        std::unordered_map<std::uint16_t,
            std::vector<std::size_t>>> portGroupIndex_;
    // Rules that match "any" port
    std::unordered_map<std::uint8_t,
        std::vector<std::size_t>> anyPortRules_;
};
```

**Evaluation pipeline** (per packet):

1. **Pre-filter** by protocol + destination port → candidate rule set (typically 50-200 rules from 40K)
2. **Aho-Corasick scan** of payload → content matches for all candidate rules simultaneously
3. For each candidate rule with content matches:
   a. Verify content position modifiers (offset, depth, distance, within)
   b. Execute PCRE patterns (only if content matched — PCRE is expensive)
   c. Check flow state (established, direction)
   d. Evaluate flowbits conditions
   e. Apply threshold/detection_filter
4. Collect all matching rules → `std::vector<SignatureMatch>`

**Performance optimization**:

| Technique | Impact |
|-----------|--------|
| Port-group pre-filter | Reduces candidate rules from 40K to 50-200 |
| Aho-Corasick batch content search | Single-pass multi-pattern matching |
| PCRE only after content match | Avoids expensive regex on non-matching packets |
| Flowbits short-circuit | Skip rules with `isset` when bit is not set |
| Threshold tracking | Avoid alerting on every match (rate limiting) |

---

## Rule Sources

### Emerging Threats (ET) Open

The primary free Snort-compatible ruleset:
- **40,000+ rules** covering exploits, malware, C2, policy violations
- **Updated daily**
- **License**: MIT-like (free for commercial use)
- **Download**: `https://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules`

### Rule categories

| Category | Rules (approx) | Priority |
|----------|----------------|----------|
| `emerging-malware` | 3,000+ | High |
| `emerging-exploit` | 2,000+ | High |
| `emerging-trojan` | 5,000+ | High |
| `emerging-scan` | 1,000+ | Medium |
| `emerging-dos` | 500+ | Medium |
| `emerging-web_server` | 2,000+ | Medium |
| `emerging-web_client` | 1,500+ | Medium |
| `emerging-policy` | 1,000+ | Low |
| `emerging-info` | 2,000+ | Low |

### Rule management

```bash
# Download/update ET Open rules
scripts/ops/update_snort_rules.sh

# Directory structure
data/rules/
├── emerging-malware.rules
├── emerging-exploit.rules
├── emerging-trojan.rules
├── emerging-scan.rules
├── emerging-dos.rules
├── emerging-web_server.rules
├── custom/
│   └── local.rules        # User-defined rules
└── disabled/
    └── ...                 # Disabled rule files
```

---

## Configuration Changes

Add to `Configuration`:

```cpp
struct SignatureConfig {
    bool enabled = false;
    std::filesystem::path rulesDirectory = "data/rules";
    std::filesystem::path customRulesFile = "data/rules/custom/local.rules";
    bool hotReload = true;                  // watch for rule updates
    int maxPcreMatchLength = 1500;          // limit PCRE scan depth
    int thresholdMemoryMb = 50;             // threshold tracking memory limit

    // Variables
    std::string homeNet = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12";
    std::string externalNet = "!$HOME_NET";
    std::string httpPorts = "80,443,8080,8443";
    std::string sshPorts = "22";
    std::string dnsPorts = "53";
};
```

---

## Testing Plan

| Test file | Tests | Coverage |
|-----------|-------|----------|
| `test_SnortRuleParser.cpp` | Header parsing, content options, hex patterns, PCRE, flow, flowbits, threshold, negation, variable refs, multi-line rules, comments, malformed rules | 40+ |
| `test_ContentMatcher.cpp` | Single pattern, multi-pattern, nocase, hex patterns, overlapping patterns, no match, empty payload, large payload | 20+ |
| `test_PcreEngine.cpp` | Simple regex, case insensitive, dot-all, relative matching, capture groups, timeout, invalid patterns | 15+ |
| `test_FlowStateTracker.cpp` | SYN/SYN-ACK/ACK, RST, FIN, direction detection, state transitions, sweep | 15+ |
| `test_FlowbitsManager.cpp` | Set/isset/unset/toggle, cross-rule correlation, flow expiry, sweep | 12+ |
| `test_RuleVariableStore.cpp` | Set/resolve, CIDR matching, port ranges, negation, groups, nested variables | 15+ |
| `test_SnortRuleEngine.cpp` | End-to-end: load rules → inspect packet → verify matches. Port-group filtering, threshold rate limiting, flowbits correlation | 25+ |

**Benchmark tests**:
- Load 40K ET Open rules: target <2 seconds
- Inspect 1 packet against 40K rules: target <1 ms
- Inspect 10K packets/sec sustained: verify throughput

---

## Dependencies

| Library | Purpose | Conan Package | License |
|---------|---------|---------------|---------|
| **PCRE2** | Regex matching for `pcre:` option | `pcre2/10.44` | BSD-3-Clause |
| **Hyperscan** (optional) | High-performance multi-pattern + regex | `hyperscan/5.4.2` | BSD-3-Clause |

Add to `conanfile.py`:
```python
def requirements(self):
    # ... existing deps ...
    if self.options.get_safe("with_signatures"):
        self.requires("pcre2/10.44")
    if self.options.get_safe("with_hyperscan"):
        self.requires("hyperscan/5.4.2")
```

CMake options:
```cmake
option(NIDS_ENABLE_SIGNATURES "Enable Snort signature matching" OFF)
option(NIDS_ENABLE_HYPERSCAN "Use Hyperscan for pattern matching" OFF)
```

**Hyperscan note**: Hyperscan is Intel-only (uses SSSE3/AVX2/AVX512). On ARM
(Apple Silicon, Raspberry Pi, AWS Graviton) or AMD without SSSE3, fall back to
the Aho-Corasick + PCRE2 path. The Vectorscan fork provides ARM support.

---

## Milestones

| Week | Deliverable |
|------|-------------|
| 1 | `ISignatureEngine` + `SignatureMatch` + `SnortRule` models |
| 2 | `SnortRuleParser` (header + basic options) + tests |
| 3 | `SnortRuleParser` (content hex, PCRE, flow, flowbits, threshold) + tests |
| 4 | `ContentMatcher` (Aho-Corasick) + tests |
| 5 | `PcreEngine` (PCRE2 wrapper) + tests |
| 6 | `FlowStateTracker` + `FlowbitsManager` + tests |
| 7 | `RuleVariableStore` + `SnortRuleEngine` integration + tests |
| 8 | Port-group pre-filter + threshold tracking |
| 9 | Pipeline integration (LiveDetectionPipeline + HybridDetection) |
| 10 | Load ET Open ruleset + benchmark performance |
| 11 | Hot reload, configuration, gRPC extensions |
| 12 | Integration tests + documentation |
| 13-14 | Performance tuning + edge case hardening |
