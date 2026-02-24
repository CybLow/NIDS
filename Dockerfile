# Stage 1: Build
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    libpcap-dev \
    qtbase5-dev \
    qtchooser \
    qt5-qmake \
    qtbase5-dev-tools \
    libeigen3-dev \
    nlohmann-json3-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /deps

RUN git clone -b 'v0.4.20-p0' --single-branch --depth 1 \
    https://github.com/Dobiasd/FunctionalPlus && \
    cd FunctionalPlus && mkdir build && cd build && \
    cmake .. && make -j$(nproc) && make install && \
    cd /deps

RUN git clone https://github.com/Dobiasd/frugally-deep && \
    cd frugally-deep && mkdir build && cd build && \
    cmake .. && make -j$(nproc) && make install && \
    cd /deps

WORKDIR /app
COPY . .

RUN mkdir -p build && cd build && \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DNIDS_BUILD_TESTS=OFF && \
    make -j$(nproc)

# Stage 2: Runtime
FROM ubuntu:22.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    libqt5widgets5 \
    libqt5gui5 \
    libqt5core5a \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/build/NIDS /app/NIDS
COPY --from=builder /app/src/model/model.json /app/model/model.json

RUN useradd -m -s /bin/bash nids
USER nids

ENTRYPOINT ["/app/NIDS"]
