# Contributing to NIDS

Thanks for your interest in contributing! This guide will help you get started.

## Getting Started

1. Fork the repository
2. Clone your fork and set up the dev environment:
   ```bash
   git clone https://github.com/<your-username>/NIDS.git
   cd NIDS
   ./scripts/dev/setup-dev.sh
   ```
3. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/my-feature main
   ```

## Development

### Build & Test

```bash
cmake --preset Debug
cmake --build --preset Debug
ctest --preset Debug
```

### Coding Standards

All code must follow the standards in [CLAUDE.md](CLAUDE.md). Key rules:

- **C++23** (`-std=c++23`)
- **PascalCase** for classes, **camelCase** for functions/variables
- **No raw `new`/`delete`** — use `std::unique_ptr` / `std::make_unique`
- **No `std::cout`** — use `spdlog`
- **No C-style casts** — use `static_cast<>`
- **`[[nodiscard]]`** on functions that return values that must be checked
- **`std::ranges`** over raw `std::find`/`std::transform`

### Architecture

Dependencies flow inward only: `ui/` -> `app/` -> `core/`, `infra/` -> `core/`.

- `core/` — Pure C++23, zero platform dependencies
- `infra/` — Platform-specific implementations (PcapPlusPlus, ONNX Runtime)
- `app/` — Orchestration logic (Qt-free)
- `ui/` — Qt6 presentation layer

See [docs/architecture.md](docs/architecture.md) for details.

## Submitting Changes

1. Make sure all tests pass and there are no linter warnings
2. Write tests for new functionality (target: 80% coverage on new code)
3. Use [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat(flow): add JA3 TLS fingerprinting
   fix(capture): handle truncated VLAN headers
   test(rules): add brute force threshold edge cases
   docs(adr): add ADR-007 for real-time pipeline design
   ```
4. Open a PR against `main` — CI must pass before merge

## Reporting Issues

- **Bugs**: Use the [bug report template](https://github.com/CybLow/NIDS/issues/new?template=bug_report.yml)
- **Features**: Use the [feature request template](https://github.com/CybLow/NIDS/issues/new?template=feature_request.yml)
- **Security**: Email security concerns privately (do not open a public issue)

## Architecture Decision Records

Significant design decisions are documented in `docs/adr/`. If your change involves a non-trivial architectural choice, please add an ADR.
