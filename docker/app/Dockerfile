# Stage 1: Build
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-13 g++-13 \
    cmake ninja-build \
    libpcap-dev \
    qt6-base-dev \
    ca-certificates \
    curl \
    tar \
    pkg-config \
    python3-pip \
    && pip3 install --break-system-packages conan \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency manifests and Conan profiles first for layer caching
COPY conanfile.py CMakePresets.json ./
COPY conan/ conan/

# Install Conan deps using in-repo profile
ENV CC=gcc-13 CXX=g++-13
RUN conan profile detect --force && \
    conan install . -pr:h conan/profiles/linux-ci -s build_type=Release --build=missing

COPY . .

# Configure and build using preset (toolchain embedded in preset)
RUN cmake --preset ci-gcc -DNIDS_BUILD_TESTS=OFF && \
    cmake --build --preset ci-gcc

# Stage 2: Runtime
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8t64 \
    libqt6core6t64 libqt6gui6t64 libqt6widgets6t64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the built binary and ONNX Runtime shared library
COPY --from=builder /app/build/ci-gcc/NIDS /app/NIDS
COPY --from=builder /app/build/ci-gcc/_deps/onnxruntime-src/lib/*.so* /usr/local/lib/
COPY --from=builder /app/models/model.onnx /app/model/model.onnx
RUN ldconfig

RUN useradd -m -s /bin/bash nids
USER nids

ENTRYPOINT ["/app/NIDS"]
