# Stage 1: Build
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    ONNXRUNTIME_VERSION=1.20.1

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-13 g++-13 \
    cmake ninja-build \
    git \
    libpcap-dev \
    qt6-base-dev \
    ca-certificates \
    curl \
    zip \
    unzip \
    tar \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install ONNX Runtime from pre-built binaries
RUN curl -sSfL -o /tmp/onnxruntime.tgz \
        "https://github.com/microsoft/onnxruntime/releases/download/v${ONNXRUNTIME_VERSION}/onnxruntime-linux-x64-${ONNXRUNTIME_VERSION}.tgz" && \
    tar -xzf /tmp/onnxruntime.tgz -C /usr/local --strip-components=1 && \
    ldconfig && rm /tmp/onnxruntime.tgz

# Install vcpkg for dependency management
WORKDIR /opt
RUN git clone --depth 1 https://github.com/microsoft/vcpkg.git && \
    ./vcpkg/bootstrap-vcpkg.sh -disableMetrics

WORKDIR /app
COPY vcpkg.json .

# Install dependencies via vcpkg
RUN /opt/vcpkg/vcpkg install --triplet x64-linux

COPY . .

RUN cmake -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=gcc-13 \
        -DCMAKE_CXX_COMPILER=g++-13 \
        -DCMAKE_TOOLCHAIN_FILE=/opt/vcpkg/scripts/buildsystems/vcpkg.cmake \
        -DNIDS_BUILD_TESTS=OFF && \
    cmake --build build --parallel

# Stage 2: Runtime
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8t64 \
    libqt6widgets6 \
    libqt6gui6 \
    libqt6core6 \
    && rm -rf /var/lib/apt/lists/*

# Copy ONNX Runtime shared libs from builder
COPY --from=builder /usr/local/lib/libonnxruntime* /usr/local/lib/
RUN ldconfig

WORKDIR /app

COPY --from=builder /app/build/NIDS /app/NIDS
COPY --from=builder /app/models/model.onnx /app/model/model.onnx

RUN useradd -m -s /bin/bash nids
USER nids

ENTRYPOINT ["/app/NIDS"]
