# Installation Guide

## Requirements

- **CMake** >= 3.20
- **C++20** compiler (GCC 13+, Clang 17+, MSVC 2022+)
- **Qt6** (Core, Gui, Widgets)
- **libpcap** (Linux/macOS) or **Npcap SDK** (Windows)
- **vcpkg** (recommended for automatic dependency management)

vcpkg automatically provides: ONNX Runtime, spdlog, nlohmann-json, GoogleTest.

## Linux (Ubuntu/Debian)

### System Dependencies

```bash
sudo apt update && sudo apt install -y \
    cmake g++ ninja-build \
    qt6-base-dev qt6-base-dev-tools \
    libpcap-dev \
    curl zip unzip tar pkg-config
```

### vcpkg (Recommended)

vcpkg handles ONNX Runtime, spdlog, nlohmann-json, and GoogleTest automatically:

```bash
git clone https://github.com/microsoft/vcpkg
cd vcpkg && ./bootstrap-vcpkg.sh
cd ..
```

Build NIDS:

```bash
cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake \
    -DNIDS_BUILD_TESTS=ON

cmake --build build --parallel
```

### Manual Installation (Alternative)

If not using vcpkg, install dependencies individually:

#### ONNX Runtime

Download from [GitHub Releases](https://github.com/microsoft/onnxruntime/releases):

```bash
wget https://github.com/microsoft/onnxruntime/releases/download/v1.23.0/onnxruntime-linux-x64-1.23.0.tgz
tar xzf onnxruntime-linux-x64-1.23.0.tgz
sudo cp -r onnxruntime-linux-x64-1.23.0/include/* /usr/local/include/
sudo cp -r onnxruntime-linux-x64-1.23.0/lib/* /usr/local/lib/
sudo ldconfig
```

#### spdlog

```bash
sudo apt install -y libspdlog-dev
```

#### GoogleTest

On Ubuntu 22.04+, `libgtest-dev` only provides sources. Build from source for CMake
`find_package(GTest CONFIG REQUIRED)` to work:

```bash
sudo apt install -y libgtest-dev cmake
cd /usr/src/googletest
sudo cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local
sudo cmake --build build -j$(nproc)
sudo cmake --install build
```

Or install via vcpkg: `vcpkg install gtest`

## Windows

### Prerequisites

1. **Visual Studio 2022** with C++ workload (for C++20 support)
2. **CMake** >= 3.20
3. **vcpkg** (recommended)

### Using vcpkg

```powershell
git clone https://github.com/microsoft/vcpkg
cd vcpkg && bootstrap-vcpkg.bat
cd ..
```

Build with vcpkg manifest mode (dependencies auto-installed from `vcpkg.json`):

```powershell
cmake -B build -DCMAKE_TOOLCHAIN_FILE=vcpkg\scripts\buildsystems\vcpkg.cmake
cmake --build build --config Release
```

### Npcap SDK

1. Download from https://npcap.com/#download
2. Install Npcap runtime
3. Download the SDK and extract to `C:\npcap-sdk`
4. Set environment variable: `NPCAP_SDK=C:\npcap-sdk`

## macOS

```bash
brew install cmake qt@6 libpcap ninja
```

Then use vcpkg for remaining dependencies:

```bash
git clone https://github.com/microsoft/vcpkg
./vcpkg/bootstrap-vcpkg.sh

cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake

cmake --build build --parallel
```

## Docker

No local dependencies needed:

```bash
xhost +local:docker
docker compose up --build
```

## Model Setup

### Pre-trained Model

If a pre-trained `model.onnx` is included in the repository, no additional setup is
needed. The model is loaded from `src/model/model.onnx` by default.

### Training a New Model

See [docs/model-training.md](docs/model-training.md) for the full training pipeline.

Quick version:

```bash
pip install -r scripts/requirements.txt
python scripts/download_dataset.py
python scripts/preprocess.py
python scripts/train_model.py
python scripts/export_onnx.py
```

### Converting a Legacy Keras Model

If you have an existing Keras model (`.keras` or `.h5`):

```bash
pip install tensorflow tf2onnx onnxruntime
python scripts/convert_model.py --input src/model/model.keras --output src/model/model.onnx
```

## Verifying Installation

```bash
cmake -B build -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake \
    -DNIDS_BUILD_TESTS=ON

cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

All three test targets should pass:
- `nids_tests` — Core and infrastructure unit tests
- `nids_qt_tests` — Qt-dependent tests (requires Qt6)
- `nids_onnx_tests` — ONNX analyzer tests (requires ONNX Runtime)
