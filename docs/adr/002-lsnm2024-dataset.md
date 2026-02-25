# ADR-002: Use LSNM2024 as Primary Training Dataset

## Status

Accepted (implemented in Phase 4)

## Context

The original NIDS model was trained on an older dataset with limited attack diversity.
Modern network threats require a training corpus that reflects current attack techniques.

Requirements:
- Large sample size (millions of flows) for deep learning
- Modern attack types (2023-2024 threat landscape)
- CICFlowMeter-compatible features for compatibility with NativeFlowExtractor
- Published, peer-reviewed, and publicly available
- Balanced class distribution

## Decision

Adopt the **LSNM2024** dataset (Q. Abu Al-Haija et al., "Revolutionizing Threat Hunting
in Communication Networks", ICICS 2024) as the primary training dataset.

Dataset characteristics:
- **Source**: Mendeley Data (publicly available)
- **Size**: ~6 million samples
- **Features**: Generated with CICFlowMeter (78-84 raw features, 60 after selection)
- **Classes**: 15 attack types + Benign (16 total)
- **Balance**: Approximately 50% benign, 50% attack
- **Year**: 2024

Attack types:
| Index | Type                   |
|-------|------------------------|
| 0     | Benign                 |
| 1     | MITM ARP Spoofing      |
| 2     | SSH Brute Force        |
| 3     | FTP Brute Force        |
| 4     | DDoS ICMP              |
| 5     | DDoS Raw IP            |
| 6     | DDoS UDP               |
| 7     | DoS                    |
| 8     | Exploiting FTP         |
| 9     | Fuzzing                |
| 10    | ICMP Flood             |
| 11    | SYN Flood              |
| 12    | Port Scanning          |
| 13    | Remote Code Execution  |
| 14    | SQL Injection          |
| 15    | XSS                    |

## Consequences

### Positive
- Modern threat coverage: includes 15 distinct attack categories relevant to current
  network security landscape.
- CICFlowMeter feature format is directly compatible with our NativeFlowExtractor.
- Large dataset enables training deep architectures (CNN-BiLSTM) without overfitting.
- Published and peer-reviewed, providing scientific credibility.

### Negative
- Exact 60-feature subset from the paper is not publicly documented. Our approach
  extracts 77 CIC-compatible features and relies on preprocessing scripts for feature
  selection.
- Dataset requires ~2 GB download from Mendeley Data.
- Class imbalance within attack subcategories requires weighted sampling during training.

### Impact on Codebase
1. `AttackType.h` rewritten with 17 enum values (15 attacks + Benign + Unknown).
2. `attackTypeToString()` and `attackTypeFromIndex()` updated for all 16 model classes.
3. `NativeFlowExtractor` produces 77 named CIC-compatible features.
4. Preprocessing script (`scripts/preprocess.py`) handles feature selection and
   normalization, storing the mapping in `model_metadata.json`.
5. All tests updated to use new enum values.
