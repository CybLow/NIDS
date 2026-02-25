# Deployment Guide

## Bare Metal (Linux)

### From Source

```bash
# Install system dependencies
sudo apt update && sudo apt install -y \
    cmake g++ ninja-build \
    qt6-base-dev \
    libpcap-dev

# Clone and build with vcpkg
git clone https://github.com/CybLow/NIDS.git
cd NIDS
git clone https://github.com/microsoft/vcpkg
./vcpkg/bootstrap-vcpkg.sh

cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake

cmake --build build --parallel
```

### Install System-Wide

```bash
sudo cmake --install build --prefix /usr/local
```

This installs:
- `/usr/local/bin/NIDS` — the executable
- `/usr/local/share/nids/model/model.onnx` — the ML model (if present)

### Running

```bash
# Requires root or NET_RAW capability for raw socket access
sudo /usr/local/bin/NIDS

# Or grant capability without running as root
sudo setcap cap_net_raw+eip /usr/local/bin/NIDS
/usr/local/bin/NIDS
```

## Package Installation

### Debian/Ubuntu (.deb)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --parallel
cd build && cpack -G DEB
sudo dpkg -i nids-*.deb
```

### RPM (Fedora/RHEL)

```bash
cd build && cpack -G RPM
sudo rpm -i nids-*.rpm
```

## Docker

### Quick Start

```bash
docker compose up --build
```

### Docker with GUI (X11 Forwarding)

The `docker-compose.yml` is configured for X11 forwarding:

```bash
# Allow local X connections
xhost +local:docker

# Start NIDS
docker compose up --build
```

### Docker Compose Configuration

```yaml
services:
  nids:
    build: .
    network_mode: host          # Required for packet capture
    cap_add:
      - NET_RAW                 # Required for raw sockets
      - NET_ADMIN
    environment:
      - DISPLAY=${DISPLAY}
    volumes:
      - /tmp/.X11-unix:/tmp/.X11-unix:rw
      - ./data/reports:/app/reports
      - ./data/captures:/app/captures
```

### Headless Docker (Future)

When the gRPC server is complete:

```bash
docker run -d --name nids \
    --net=host \
    --cap-add=NET_RAW \
    nids:latest --headless --grpc-port 50051
```

## Running as a systemd Service

Create `/etc/systemd/system/nids.service`:

```ini
[Unit]
Description=Network Intrusion Detection System
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/NIDS --headless
Restart=on-failure
RestartSec=5
User=nids
Group=nids
AmbientCapabilities=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nids
```

**Note**: The `--headless` flag requires the gRPC server (Phase planned, not yet
implemented). Currently NIDS runs as a GUI application only.

## Configuration

NIDS uses sensible defaults. To override, create a JSON config file:

```json
{
    "modelPath": "/usr/local/share/nids/model/model.onnx",
    "metadataPath": "/usr/local/share/nids/model/model_metadata.json",
    "onnxIntraOpThreads": 4,
    "flowTimeoutUs": 600000000,
    "idleThresholdUs": 5000000
}
```

Pass via: `NIDS --config /etc/nids/config.json` (when CLI arg parsing is implemented).

### Default Values

| Parameter           | Default              | Description                      |
|---------------------|----------------------|----------------------------------|
| `modelPath`         | `src/model/model.onnx` | Path to ONNX model file        |
| `metadataPath`      | `src/model/model_metadata.json` | Model metadata         |
| `onnxIntraOpThreads`| `1`                  | ONNX Runtime intra-op parallelism |
| `flowTimeoutUs`     | `600000000` (10 min) | Flow expiry timeout              |
| `idleThresholdUs`   | `5000000` (5 sec)    | Idle flow threshold              |
| `defaultDumpFile`   | `dump.pcap`          | Default pcap dump filename       |

## Troubleshooting

### "Permission denied" on capture
Run with `sudo` or set `CAP_NET_RAW` capability on the binary.

### "Failed to load ONNX model"
Ensure `model.onnx` exists at the configured path. The default expects it relative
to the working directory.

### X11 display errors in Docker
Run `xhost +local:docker` on the host before starting the container.

### Qt platform plugin error
Install Qt6 platform plugins: `sudo apt install qt6-base-dev` or ensure
`QT_QPA_PLATFORM=xcb` is set.
