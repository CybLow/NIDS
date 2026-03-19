# Production Dockerfile for nids-server
# Multi-stage build: compile in builder, deploy minimal runtime image.
#
# Build:  docker build -t nids-server -f docker/server/Dockerfile .
# Run:    docker run --cap-add NET_RAW --network host nids-server

# ── Stage 1: Build ───────────────────────────────────────────────────
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc-14 g++-14 cmake ninja-build \
    python3-pip pipx pkg-config \
    libpcap-dev libqt6core6 qt6-base-dev \
    libyara-dev \
    && pipx install conan && pipx ensurepath \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.local/bin:$PATH"

WORKDIR /src
COPY conanfile.py .

# Install Conan deps (cacheable layer).
RUN conan profile detect --force \
    && conan install . --build=missing -s build_type=Release \
       -s compiler=gcc -s compiler.version=14 \
       -of build/Release

COPY . .

# Configure and build server only.
RUN cmake --preset ci-gcc \
    -DNIDS_BUILD_TESTS=OFF \
    -DNIDS_BUILD_SERVER=ON \
    -DNIDS_ENABLE_YARA=ON \
    -DNIDS_ENABLE_SIGNATURES=ON \
    && cmake --build build/Release --target nids-server -j$(nproc)

# ── Stage 2: Runtime ─────────────────────────────────────────────────
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 libstdc++6 libyara10 \
    && useradd -r -s /usr/sbin/nologin nids \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/nids

# Copy server binary.
COPY --from=builder /src/build/Release/src/server/nids-server /usr/local/bin/

# Copy ONNX Runtime shared libs.
COPY --from=builder /src/build/Release/_deps/onnxruntime-src/lib/*.so* /usr/local/lib/
RUN ldconfig

# Copy model and data files.
COPY models/ /opt/nids/models/
COPY data/ /opt/nids/data/

# Default config.
COPY config.json /opt/nids/config.json

USER nids

EXPOSE 50051

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["nids-server", "--health-check"] || exit 1

ENTRYPOINT ["nids-server"]
CMD ["--config", "/opt/nids/config.json"]
