# NIDS Deployment Guide

## System Requirements

- **OS**: Linux (Ubuntu 22.04+, Fedora 38+, RHEL 9+) or Windows 10+
- **CPU**: 4+ cores recommended for production
- **RAM**: 4 GB minimum, 8 GB recommended
- **Disk**: 10 GB for PCAP storage (configurable)
- **Network**: CAP_NET_RAW capability for packet capture

## Installation

### From packages (DEB/RPM)

```bash
# Debian/Ubuntu
sudo dpkg -i nids-0.2.0-Linux.deb

# Fedora/RHEL
sudo rpm -i nids-0.2.0-Linux.rpm
```

### From Docker

```bash
docker pull ghcr.io/cyblow/nids-server:latest
docker run -d --name nids \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  --network host \
  -v /etc/nids:/opt/nids \
  nids-server --config /opt/nids/config.json --interface eth0
```

### From source

```bash
# Prerequisites
sudo apt install gcc-14 g++-14 cmake ninja-build \
  libpcap-dev qt6-base-dev libyara-dev

# Conan dependencies
pip install conan
conan install . --build=missing -s build_type=Release -of build/Release

# Build
cmake --preset ci-gcc
cmake --build build/Release -j$(nproc)

# Install
sudo cmake --install build/Release
```

## Configuration

Create `/etc/nids/config.json`:

```json
{
  "model": {
    "path": "/opt/nids/models/model.onnx",
    "metadata_path": "/opt/nids/models/model_metadata.json"
  },
  "hybrid_detection": {
    "weight_ml": 0.35,
    "weight_threat_intel": 0.20,
    "weight_heuristic": 0.10
  },
  "output": {
    "syslog": {
      "enabled": true,
      "host": "siem.example.com",
      "port": 514,
      "format": "cef"
    },
    "json_file": {
      "enabled": true,
      "path": "/var/log/nids/alerts.jsonl",
      "max_size_mb": 100,
      "max_files": 10
    }
  },
  "hunting": {
    "enabled": true,
    "flow_database_path": "/var/lib/nids/flows.db",
    "pcap_storage": {
      "storage_dir": "/var/lib/nids/pcap",
      "max_total_size_bytes": 10737418240,
      "max_retention_hours": 168
    }
  },
  "signatures": {
    "enabled": true,
    "rules_directory": "/opt/nids/rules"
  }
}
```

## Running as a systemd service

```bash
sudo cp deploy/nids-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nids-server
sudo systemctl status nids-server
journalctl -u nids-server -f
```

## CLI Client

```bash
# Check server status
nids-cli status

# Health check
nids-cli health

# List network interfaces
nids-cli interfaces

# Start capture on eth0
nids-cli capture start eth0

# Stream detection results (flagged only)
nids-cli stream --filter flagged

# Stop capture
nids-cli capture stop

# Search flow database
nids-cli search --ip 10.0.0.1 --flagged

# IOC indicator search
nids-cli ioc 10.0.0.1 192.168.1.100

# Load Snort/YARA rules
nids-cli rules load /opt/nids/rules/

# Show rule statistics
nids-cli rules stats
```

## gRPC API

The server listens on `localhost:50051` by default (insecure). 15 RPCs:

| RPC | Description | Status |
|-----|-------------|--------|
| `ListInterfaces` | List available network interfaces | Implemented |
| `StartCapture` | Start live capture + detection | Implemented |
| `StopCapture` | Stop the current session | Implemented |
| `GetStatus` | Get server/session status | Implemented |
| `StreamDetections` | Stream real-time detection events | Implemented |
| `HealthCheck` | Health probe for monitoring | Implemented |
| `SearchFlows` | Search historical flow database | Implemented (requires flow index) |
| `IocSearch` | Search for IOC indicators | Implemented (requires flow index) |
| `LoadRules` | Load Snort/YARA rules | Implemented (requires engine) |
| `GetRuleStats` | Get loaded rule statistics | Implemented |
| `BlockFlow` | Manually block a 5-tuple | Implemented (requires verdict engine) |
| `UnblockFlow` | Remove a manual block | Implemented (requires verdict engine) |
| `GetInlineStats` | Get inline IPS statistics | Implemented |
| `StreamPackets` | Stream raw captured packets | Planned |
| `AnalyzeCapture` | Batch analysis of a PCAP file | Planned |

## Docker Sandbox (Testing)

```bash
cd docker/sandbox
docker compose up -d

# Generate attack traffic
docker compose exec attacker /scripts/generate-attacks.sh all

# Generate benign traffic
docker compose exec attacker /scripts/generate-benign.sh

# Watch detections
docker compose exec attacker nids-cli --server nids-server:50051 stream
```

## Security Considerations

- Run as a dedicated `nids` user (not root)
- Use `AmbientCapabilities=CAP_NET_RAW` instead of root
- Enable TLS for gRPC in production (currently insecure)
- Validate all external input (PCAP files, rule files)
- Monitor `/var/log/nids/` for disk usage
