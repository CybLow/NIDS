# Installation Guide

## Requirements

- **CMake** >= 3.20
- **C++23** compiler (GCC 14+, Clang 18+, MSVC 2022+)
- **Qt6** (Core, Gui, Widgets) -- system package
- **Python 3** + pip (for Conan package manager)
- **Conan 2** (installed via pip)
- **Ninja** (build system)

Conan 2 manages: spdlog, nlohmann_json, GoogleTest, PcapPlusPlus.
ONNX Runtime is fetched automatically via CMake FetchContent (pre-built binaries).

## Linux (Ubuntu/Debian)

### Automated Setup (Recommended)

```bash
git clone https://github.com/CybLow/NIDS.git
cd NIDS
./scripts/dev/setup-dev.sh
```

The script:
1. Detects your distro (Fedora, Ubuntu, Debian)
2. Installs system packages (GCC, CMake, Ninja, Qt6)
3. Installs Conan 2 via pip
4. Runs `conan install` for Debug + Release using the in-repo profile

After setup:

```bash
cmake --preset Debug
cmake --build --preset Debug
ctest --preset Debug
```

### Manual Setup

#### System Dependencies

```bash
# Ubuntu 24.04+
sudo apt update && sudo apt install -y \
    gcc g++ cmake ninja-build \
    qt6-base-dev qt6-base-dev-tools \
    python3 python3-pip \
    curl tar pkg-config

# Fedora 43+
sudo dnf install -y \
    gcc gcc-c++ cmake ninja-build \
    qt6-qtbase-devel \
    python3 python3-pip \
    git curl tar pkg-config
```

#### Conan 2

```bash
pip3 install conan
```

#### Install Dependencies

```bash
# Using in-repo profile (recommended):
conan install . -pr:h conan/profiles/linux-gcc13 -s build_type=Debug --build=missing
conan install . -pr:h conan/profiles/linux-gcc13 -s build_type=Release --build=missing
```

#### Build

The project provides committed presets in `CMakePresets.json`:

| Preset         | Use case                                    |
|----------------|---------------------------------------------|
| `Debug`        | Dev build (Debug + sanitizers, cross-platform) |
| `Release`      | Dev build (Release, cross-platform)         |
| `ci-gcc`       | CI (GCC-13, Ubuntu 24.04)                   |
| `ci-coverage`  | CI (GCC-13 + coverage flags)                |

Conan also generates `CMakeUserPresets.json` with `conan-debug`/`conan-release`
presets for direct CLI use, but prefer the committed presets above.

```bash
# Debug (with ASan/UBSan):
cmake --preset Debug
cmake --build --preset Debug

# Release:
cmake --preset Release
cmake --build --preset Release
```

#### Run Tests

```bash
ctest --preset Debug    # or Release
```

## Linux (Fedora)

### Automated Setup

```bash
./scripts/dev/setup-dev.sh
```

### Manual Setup

Same as Ubuntu above, but use `dnf` instead of `apt` for system packages.
The in-repo Conan profile (`conan/profiles/linux-gcc13`) uses `compiler.version=13`
for binary cache compatibility. This works with any GCC version >= 13 (the ABI is
forward-compatible).

## Windows

### Automated Setup

```powershell
.\scripts\dev\setup-dev.ps1
```

The script:
1. Installs Visual Studio 2022 Build Tools, CMake, Ninja, Python via winget
2. Installs Npcap SDK (prompts if not found)
3. Installs Qt6 via aqtinstall
4. Installs Conan 2 via pip
5. Runs `conan install` for Debug + Release

### Manual Setup

#### Prerequisites

1. **Visual Studio 2022** with C++ workload (for C++23 support)
2. **CMake** >= 3.20
3. **Ninja** build system
4. **Python 3** + pip

#### Npcap SDK

1. Download from https://npcap.com/#download
2. Install Npcap runtime
3. Download the SDK and extract to `C:\npcap-sdk`
4. Set environment variable: `NPCAP_SDK=C:\npcap-sdk`

#### Qt6

Install via the Qt Online Installer or aqtinstall:

```powershell
pip install aqtinstall
python -m aqt install-qt windows desktop 6.8.0 win64_msvc2022_64 -O C:\Qt
set CMAKE_PREFIX_PATH=C:\Qt\6.8.0\msvc2022_64
```

#### Conan 2 + Build

```powershell
pip install conan

# Install dependencies (from project root):
conan install . -pr:h conan/profiles/windows-msvc17 -s build_type=Debug --build=missing
conan install . -pr:h conan/profiles/windows-msvc17 -s build_type=Release --build=missing

# Build (from Developer Command Prompt):
cmake --preset Release
cmake --build --preset Release
```

## macOS

```bash
brew install cmake qt@6 ninja python3
pip3 install conan

conan install . -pr:h conan/profiles/linux-gcc13 -s build_type=Release --build=missing
cmake --preset Release
cmake --build --preset Release
```

## Docker

No local dependencies needed:

```bash
xhost +local:docker
docker compose -f docker/app/compose.yml up --build
```

## Devcontainer (VS Code / CLion)

The project includes a `.devcontainer/` directory with a pre-configured development
container. Open the project in VS Code and click "Reopen in Container", or use
CLion's Remote Development with Docker.

The container includes all build tools, linters, and Conan pre-configured.

## How Presets Work

The project uses CMake presets for reproducible builds:

- **`CMakePresets.json`** (committed) -- Developer presets (`Debug`, `Release`)
  and CI presets (`ci-gcc`, `ci-coverage`). These are the primary presets for
  all workflows.
- **`CMakeUserPresets.json`** (gitignored, generated by Conan) -- Contains
  `conan-debug` and `conan-release` presets with Conan toolchain paths. These are
  a CLI fallback; prefer the committed presets above.

Conan generates `CMakeUserPresets.json` when you run `conan install`. The committed
presets in `CMakePresets.json` inherit from these to pick up `find_package()` paths.

## Conan Profiles

In-repo profiles are in `conan/profiles/`:

| Profile              | Use case                              |
|----------------------|---------------------------------------|
| `linux-gcc13`        | Local Linux dev (any GCC >= 13)       |
| `linux-ci`           | GitHub Actions CI (Ubuntu 24.04)      |
| `windows-msvc17`     | Windows MSVC 2022                     |

## Model Setup

### Pre-trained Model

If a pre-trained `model.onnx` is included in the repository, no additional setup is
needed. The model is loaded from `models/model.onnx` by default.

### Training a New Model

See [docs/model-training.md](docs/model-training.md) for the full training pipeline.

Quick version:

```bash
pip install -r scripts/ml/requirements.txt
python scripts/ml/download_dataset.py
python scripts/ml/preprocess.py
python scripts/ml/train_model.py
python scripts/ml/export_onnx.py
```

## Verifying Installation

```bash
cmake --preset Debug
cmake --build --preset Debug
ctest --preset Debug
```

All three test targets should pass:
- `nids_tests` -- Core and infrastructure unit tests
- `nids_qt_tests` -- Qt-dependent tests (requires Qt6)
- `nids_onnx_tests` -- ONNX analyzer tests (requires ONNX Runtime)
