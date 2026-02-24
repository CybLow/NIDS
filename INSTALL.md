# Installation Guide

## Linux (Ubuntu/Debian)

### System Dependencies

```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y \
    cmake \
    g++ \
    qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools \
    libpcap-dev \
    libeigen3-dev \
    nlohmann-json3-dev
```

### FunctionalPlus

```bash
git clone -b 'v0.2.22' --single-branch --depth 1 https://github.com/Dobiasd/FunctionalPlus
cd FunctionalPlus && mkdir -p build && cd build
cmake .. && make -j$(nproc) && sudo make install
cd ../..
```

### frugally-deep

```bash
git clone https://github.com/Dobiasd/frugally-deep
cd frugally-deep && mkdir -p build && cd build
cmake .. && make -j$(nproc) && sudo make install
cd ../..
```

### spdlog (optional, recommended)

```bash
sudo apt install -y libspdlog-dev
```

### GoogleTest (for tests)

```bash
sudo apt install -y libgtest-dev
```

## Windows

### Prerequisites

1. **Visual Studio 2019+** with C++ workload
2. **CMake** >= 3.20
3. **vcpkg** (recommended) or manual installs

### Using vcpkg

```powershell
git clone https://github.com/microsoft/vcpkg
cd vcpkg && bootstrap-vcpkg.bat
vcpkg install qt5-base:x64-windows
vcpkg install frugally-deep:x64-windows
vcpkg install spdlog:x64-windows
vcpkg install gtest:x64-windows
```

### Npcap SDK

1. Download from https://npcap.com/#download
2. Install Npcap runtime
3. Download the SDK and extract to `C:\npcap-sdk`
4. Set environment variable: `NPCAP_SDK=C:\npcap-sdk`

### Build

```powershell
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=[vcpkg-root]/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release
```

## macOS

```bash
brew install cmake qt@5 libpcap eigen nlohmann-json
```

Then follow the FunctionalPlus and frugally-deep steps from the Linux section.

## Docker

No local dependencies needed:

```bash
docker compose up --build
```

## Verifying Installation

```bash
mkdir build && cd build
cmake .. -DNIDS_BUILD_TESTS=ON
make -j$(nproc)
ctest --output-on-failure
```
