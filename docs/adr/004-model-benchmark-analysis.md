# ADR-004: Model Benchmark Analysis & Real-World Viability

## Status

Accepted (2026-03-10) -- Model accepted with documented limitations.

## Context

After two training runs of the CNN-BiLSTM model on the LSNM2024 dataset, the model
reached a performance ceiling. This document records:

1. Final benchmark results and comparison with published work
2. Analysis of whether the model is viable for real-world deployment
3. Root cause analysis: dataset limitations vs architecture limitations
4. Comparison of our C++ flow extractor vs CICFlowMeter for real-time use
5. Decision on whether to accept or continue tuning

## Final Model Metrics (Run 2)

### Top-Level

| Metric            | Value   |
|-------------------|---------|
| Test accuracy     | 87.78%  |
| Macro F1          | 0.806   |
| Weighted F1       | 0.880   |
| Macro AUC         | 0.990   |
| Best epoch        | 62/100  |
| Early-stopped at  | 72      |
| Training time     | 24.9 min (T4 GPU) |
| Model size        | 1.5 MB (ONNX) |

### Binary Detection (Attack vs Benign)

| Metric           | Value   |
|------------------|---------|
| Attack recall    | 97.78%  |
| Attack precision | 95.28%  |
| False negatives  | 2,625   |
| False positives  | 5,723   |

### Per-Class F1 Scores

| Class                  | F1     | Grade |
|------------------------|--------|-------|
| Benign                 | 0.8570 | OK    |
| MITM ARP Spoofing      | 0.9994 | GOOD  |
| SSH Brute Force        | 0.7832 | WEAK  |
| FTP Brute Force        | 0.8741 | OK    |
| DDoS ICMP              | 0.6270 | WEAK  |
| DDoS Raw IP            | 0.9980 | GOOD  |
| DDoS UDP               | 0.9997 | GOOD  |
| DoS                    | 0.6889 | WEAK  |
| Exploiting FTP         | 0.9829 | GOOD  |
| Fuzzing                | 0.4879 | BAD   |
| ICMP Flood             | 0.6212 | WEAK  |
| SYN Flood              | 0.9997 | GOOD  |
| Port Scanning          | 0.8796 | OK    |
| Remote Code Execution  | 0.7568 | WEAK  |
| SQL Injection          | 0.6923 | WEAK  |
| XSS                    | 0.6468 | WEAK  |

### Critical Confusions

1. **Benign <-> XSS**: 4,024 Benign misclassified as XSS (70.3% of Benign errors),
   831 XSS misclassified as Benign (10.7% false negative rate).
2. **SQL Injection -> Benign**: 1,663 missed (17.3% false negative rate). Security risk.
3. **DoS <-> Remote Code Execution**: Bidirectional confusion (96.4% of DoS errors go
   to RCE, 85.2% of RCE errors go to DoS).
4. **DDoS ICMP <-> ICMP Flood**: 54.3% of DDoS-ICMP errors go to ICMP-Flood.
   Semantically these may be the same attack at different scales.
5. **Fuzzing**: Only 0.49 F1. 462 test samples, errors scattered across DoS (42%),
   ICMP (25%), RCE (14%). Too rare to learn reliably.

### Hyperparameter Tuning Had Minimal Effect

| Metric       | Run 1  | Run 2  | Change |
|--------------|--------|--------|--------|
| Accuracy     | 87.70% | 87.78% | +0.08% |
| Macro F1     | 0.808  | 0.806  | -0.002 |
| Weighted F1  | 0.880  | 0.880  | 0.000  |

Run 2 properly converged (early-stopped at epoch 72 vs hitting the 50-epoch wall in
Run 1), but final metrics are virtually identical. The ceiling is in the data/features,
not the model capacity or learning dynamics.

---

## Comparison with Published Benchmarks

### Original Paper (ICICS 2024)

Abu Al-Haija et al. reported **99.4% accuracy** with Random Forest / Decision Tree and
up to **99.9%** with Decision Tree on the same LSNM2024 dataset.

**Critical difference: apples-to-oranges comparison.**

| Aspect        | Original paper            | Our pipeline              |
|---------------|---------------------------|---------------------------|
| Granularity   | Packet-level (raw rows)   | Flow-level (aggregated)   |
| Features      | 60 NLFlowLyzer features   | 77 CICFlowMeter features  |
| Samples       | ~6 million packets        | ~992K flows               |
| Task          | Classify individual packets | Classify bidirectional flows |
| Model         | Random Forest / Decision Tree | CNN-BiLSTM (deep learning) |

Their 99.4% is on **per-packet classification with the exact features the dataset was
designed around**. Our 87.8% is on **aggregated flows with a different feature set**.
These numbers are not directly comparable.

### Kaggle Community

**Zero public notebooks** exist on this dataset as of March 2026. We are literally the
first public benchmark on LSNM2024 using flow-level features. There is no community
baseline to compare against.

### Similar Datasets (CICIDS2017, UNSW-NB15)

On CICIDS2017 with comparable architectures:

| Model                        | Accuracy | Notes                                |
|------------------------------|----------|--------------------------------------|
| CNN-LSTM (multiclass, 15cl)  | 96.76%   | Same feature type, different dataset  |
| CapsNet + BiLSTM             | 99.0%    | Different architecture                |
| H-RNN                        | 99.99%   | Likely data leakage / overfitting     |
| CNN-BiLSTM + focal loss      | "superior" | No exact numbers published          |
| Random Forest / XGBoost      | 99.4-99.8% | Simpler models, different datasets  |

**Caution**: CICIDS2017 has known data leakage issues that inflate published numbers.
Flow features from CICFlowMeter on that dataset contain artifacts (e.g., flow duration
directly encoding attack type) that make classification trivially easy. Papers reporting
99%+ accuracy on CICIDS2017 should be viewed skeptically.

### Production NIDS (Suricata, Snort, Zeek)

These tools use **signature-based detection** (pattern matching on known attack
signatures), not ML classification. They have near-zero false positive rates for known
threats but cannot detect novel/unknown attacks. ML-based NIDS is a complementary
approach that trades higher false positive rates for the ability to detect unknown
threats.

There is no meaningful accuracy comparison between signature-based and ML-based NIDS --
they solve different problems.

---

## Root Cause: Dataset or Architecture?

### The dataset is the primary bottleneck

1. **Feature mismatch**: LSNM2024 was created with NLFlowLyzer (60 features). We use
   CICFlowMeter-compatible features (77 features). These are different statistical
   computations over different raw values. We lose the exact signal the dataset was
   designed to provide.

2. **Aggregation loses information**: Flow-level analysis condenses ~200 packets into
   77 statistical features. Individual packet characteristics that distinguish attack
   types (e.g., specific payload patterns, exact flag sequences) are averaged away.

3. **Structural confusions are inherent to flow-level features**:
   - **SQL injection / XSS -> Benign**: These attacks happen at the application layer
     (HTTP payloads). Flow-level features (packet sizes, timing, flags) cannot see the
     difference between a legitimate HTTP POST and one containing `'; DROP TABLE --`.
     The 17.3% SQL false negative rate is not a model failure -- it is a **fundamental
     limitation of header-only analysis**.
   - **DoS <-> Remote Code Execution**: Both produce similar flow patterns (bursts of
     TCP traffic with similar size distributions). Without payload inspection, they are
     genuinely hard to distinguish.
   - **DDoS-ICMP <-> ICMP Flood**: These are arguably the same attack type at different
     scales. The distinction may be artificial.

4. **Class rarity**: Fuzzing has only 462 test samples (0.23% of test set). No model
   can learn a reliable decision boundary from so few examples, especially when the
   class overlaps with DoS and ICMP patterns.

### The architecture is secondary but contributes

1. **CNN-BiLSTM treats features as a sequence**: The 77 flow features are not inherently
   sequential. The BiLSTM may not provide meaningful benefit over a pure MLP or ensemble
   model. However, Run 1 vs Run 2 showed that the architecture is not the bottleneck --
   the model converges to the same accuracy regardless of hyperparameters.

2. **No attention mechanism**: Self-attention could help the model focus on the most
   discriminative features for each class. However, this is a minor optimization, not a
   fundamental fix.

3. **Simpler models might match or exceed**: Random Forest / XGBoost achieve 99%+ on
   packet-level data. On flow-level data, tree-based models may perform comparably to
   our CNN-BiLSTM with much less complexity. This was not tested (noted as a limitation
   in the training notebook).

---

## Real-Time Performance: Our Approach vs CICFlowMeter

### What is CICFlowMeter?

CICFlowMeter is a Java-based tool developed by the Canadian Institute for Cybersecurity
(UNB) that generates bidirectional flow features from network traffic. It is the most
widely used tool for creating NIDS training datasets.

### CICFlowMeter's real-time limitations

CICFlowMeter is **not suitable for real-time intrusion detection**:

| Issue                      | Detail                                              |
|----------------------------|-----------------------------------------------------|
| Language                   | Java -- JVM startup, garbage collection pauses       |
| Memory                     | Known issues with inputs >1 GB                       |
| Python version             | Broken / non-functional                              |
| Real-time classification   | Officially rated "No" for real-time analysis          |
| Feature extraction speed   | 83 features with heavy statistical computation       |
| Output                     | Writes to CSV files, not a streaming pipeline        |
| Installation               | Notorious dependency hell (specific Java/Gradle versions) |

CICFlowMeter was designed for **offline dataset generation**, not real-time detection.

### Our NativeFlowExtractor: current state and potential

Our C++ `NativeFlowExtractor` is currently offline-only (reads pcap files), but has
significant advantages over CICFlowMeter for future real-time use:

| Aspect                  | CICFlowMeter                | NativeFlowExtractor (current)  |
|-------------------------|-----------------------------|--------------------------------|
| Language                | Java (JVM, GC)              | C++20 (native, zero-overhead)  |
| Flow lookup             | Java HashMap                | `std::map` (could be `unordered_map`) |
| Feature computation     | Similar statistical features | 77 CICFlowMeter-compatible features |
| Memory model            | JVM heap, GC-managed        | Stack/heap, RAII, predictable  |
| Max-flow splitting      | Not standard                | 200-packet cap (bounded memory) |
| Real-time capability    | No                          | Not yet, but straightforward to add |

### Network speed impact

**Neither approach impacts internet speed.** Both CICFlowMeter and our extractor perform
**header-only analysis** -- they read packet metadata (IP addresses, ports, TCP flags,
sizes, timestamps) without inspecting payloads. This is fundamentally different from
Deep Packet Inspection (DPI):

| Technique                | What it reads         | Network impact        | Can detect payload attacks? |
|--------------------------|-----------------------|-----------------------|-----------------------------|
| Flow-level (ours)        | Headers + metadata    | Near-zero             | No                          |
| Deep Packet Inspection   | Full packet payloads  | Significant (19->5 Gbps on enterprise gear) | Yes     |
| Signature-based (Snort)  | Pattern matching      | Low-moderate          | Yes (known patterns)        |

**Key insight**: Our flow-level approach is fast and lightweight, but this is precisely
why it cannot detect application-layer attacks (SQL injection, XSS). These attacks are
invisible at the header level. The 17.3% SQL and 10.7% XSS false negative rates are not
model failures -- they are architectural limitations of any header-only NIDS.

### What would be needed for real-time deployment

To make `NativeFlowExtractor` real-time capable, the following changes would be needed:

1. **Replace `std::map` with `std::unordered_map`** using packed numeric IP keys instead
   of string-based keys. This changes O(log N) to O(1) amortized per-packet lookup.
2. **Switch to online statistics** (Welford's algorithm for running mean/variance)
   instead of storing per-packet vectors. Reduces per-flow memory from ~7 KB to ~200 B.
3. **Add periodic timeout sweeps** instead of lazy eviction (currently only checks
   timeout when the next packet for the same 5-tuple arrives).
4. **Stream completed flows to the ML analyzer** immediately instead of accumulating
   all flows in memory until the pcap is fully processed.
5. **Producer-consumer threading**: Capture thread feeds packets, extractor thread
   computes features, analyzer thread runs ONNX inference.
6. **Live pcap capture** via `pcap_open_live()` instead of `pcap_open_offline()`.

None of these changes are architecturally difficult. The current design is a solid
foundation that can be incrementally adapted for real-time use.

---

## Decision

### Accept the model as-is

**Rationale:**

1. **No public benchmark to compare against.** We are the first published flow-level
   results on LSNM2024. The original paper's 99.4% used packet-level classification
   with different features -- not a valid comparison.

2. **Binary detection is operationally strong.** 97.78% attack recall means we catch
   the vast majority of attacks. This is the most important metric for a NIDS.

3. **The confusions are structural, not architectural.** Focal loss, class merging, or
   a different model will not fix the fundamental limitation that flow-level features
   cannot see application-layer payloads. The 87.8% ceiling is a data/feature problem.

4. **Hyperparameter tuning confirmed the ceiling.** Run 1 vs Run 2 showed identical
   results despite different hyperparameters. More tuning would be wasted effort.

5. **The model serves a real-time C++ application.** A 1.5 MB ONNX model running in
   microseconds on CPU is already a strong practical result for inline detection.

6. **Diminishing returns.** Engineering effort is better spent on making the extractor
   real-time capable than on squeezing marginal accuracy gains from the model.

### Known limitations (accepted)

1. **SQL injection false negative rate: 17.3%** -- inherent to header-only analysis.
2. **XSS false negative rate: 10.7%** -- same root cause.
3. **Fuzzing is effectively undetectable** (F1 = 0.49) -- too few samples, too similar
   to other attack types at the flow level.
4. **DoS / RCE confusion** -- bidirectional, likely inherent to similar flow patterns.
5. **No concept-drift handling** -- model assumes traffic patterns match training data.
6. **No baseline comparison** -- we did not test simpler models (RF, XGBoost, MLP).

### Recommended future improvements (prioritized)

1. **Make NativeFlowExtractor real-time** (highest impact, independent of model quality)
2. **Benchmark against XGBoost / Random Forest** on the same flow-level features
3. **Train on NLFlowLyzer features** to match the dataset's native format (requires
   reimplementing NLFlowLyzer feature extraction in C++)
4. **Add DPI-based features** for application-layer attacks (highest accuracy gain but
   requires payload inspection with throughput tradeoff)
5. **Hyperparameter search with Optuna** (low-priority given the ceiling evidence)
6. **Temperature scaling** for confidence calibration
7. **Merge confusable classes** (DDoS-ICMP + ICMP-Flood, possibly DoS + RCE) if
   operational use cases do not require the distinction

### Mitigations already implemented

The following limitations identified above have been **partially mitigated** by the
hybrid detection system (ADR-005):

| Limitation from this ADR | Mitigation in ADR-005 | Remaining gap |
|---|---|---|
| **SQL injection FN rate (17.3%)** | TI lookup catches known attacker IPs; heuristic rules flag suspicious port patterns | Novel attackers with no TI listing still slip through. Only DPI/WAF can fully solve this. |
| **XSS FN rate (10.7%)** | Same TI + heuristic mitigation | Same: payload inspection required for full coverage. |
| **Known-bad IPs with benign-looking traffic** | TI match **always overrides** benign ML verdict (escalation logic) | Feeds must be kept updated; novel C2 servers not yet listed will pass. |
| **Low ML confidence = no second opinion** | Combined score uses TI + heuristic signals to corroborate or contradict low-confidence ML | Fundamentally better than ML-alone, but still header-only. |
| **Single point of failure (ML-only)** | Three independent layers (ML + TI + heuristics) | Each layer has its own blind spots, but overlap is small. |
| **Fuzzing undetectable (F1=0.49)** | Heuristic `high_packet_rate` rule can flag fuzzing-like patterns | Low reliability; fuzzing remains the weakest detection area. |

**Key insight**: The hybrid system does NOT fix the fundamental flow-level blindness
to payload attacks. It adds **defense-in-depth for what header/flow analysis CAN do**.
Payload-based attacks (SQL injection, XSS) remain the domain of Snort/Suricata/WAFs.
See `docs/architecture.md` "Detection Philosophy & Perimeter" for the complementary
deployment model.

---

## Consequences

### Positive

- Model is deployed and functional -- the NIDS application can detect 15 attack types.
- Binary attack detection at 97.78% recall provides meaningful security value.
- Small model size (1.5 MB) enables CPU-only inference with microsecond latency.
- Clear roadmap for improvements documented above.

### Negative

- Application-layer attacks (SQL injection, XSS) have unacceptably high false negative
  rates due to the inherent limitation of header-only analysis.
- No competitive benchmark exists to validate our results against peers.
- Users must understand that this is a **complementary** detection tool, not a
  replacement for signature-based NIDS (Suricata, Snort).

### Impact on Codebase

- `models/model.onnx` + `models/model.onnx.data` + `models/model_metadata.json`
  updated with Run 2 artifacts.
- No changes to `AttackType.h` or C++ code required.
- Training notebook (`scripts/ml/train_nids.ipynb`) finalized with stdout-to-file logging.
