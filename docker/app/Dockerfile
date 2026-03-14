# Stage 1: Build
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-14 g++-14 \
    cmake ninja-build mold \
    qt6-base-dev \
    ca-certificates curl tar pkg-config \
    python3-pip \
    && pip3 install --break-system-packages conan \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency manifests first for layer caching
COPY conanfile.py CMakePresets.json ./
COPY conan/ conan/

ENV CC=gcc-14 CXX=g++-14
RUN ln -sf /usr/bin/gcc-14 /usr/local/bin/cc && \
    ln -sf /usr/bin/gcc-14 /usr/local/bin/gcc && \
    conan profile detect --force && \
    conan install . -pr:h conan/profiles/linux-ci -s build_type=Release --build=missing

COPY . .

RUN cmake --preset ci-gcc -DNIDS_BUILD_TESTS=OFF && \
    cmake --build --preset ci-gcc

# Stage 2: Runtime
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libqt6core6t64 libqt6gui6t64 libqt6widgets6t64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/build/ci-gcc/NIDS /app/NIDS
COPY --from=builder /app/build/ci-gcc/_deps/onnxruntime-src/lib/*.so* /usr/local/lib/
RUN ldconfig

COPY --from=builder /app/models/model.onnx /app/models/model.onnx

RUN useradd -m -s /bin/bash nids
USER nids

ENTRYPOINT ["/app/NIDS"]
