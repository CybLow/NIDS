# Dockerfile.ci -- CI builder image for NIDS
#
# Multi-stage image that:
#  1. Installs all build and analysis dependencies (gcc, clang-tidy, cppcheck, gcovr)
#  2. Installs Conan and pre-installs project dependencies using in-repo profile
#  3. Provides entrypoints for build, test, lint, coverage, and scan stages

FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# System dependencies (build + lint + coverage tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-13 g++-13 clang-17 clang-tidy-17 clang-tools-17 \
    cmake ninja-build make \
    libpcap-dev \
    qt6-base-dev \
    cppcheck \
    lcov python3-pip \
    git ca-certificates curl tar pkg-config \
    && pip3 install --break-system-packages conan gcovr \
    && rm -rf /var/lib/apt/lists/*

# Pre-install Conan deps for cache efficiency using in-repo profile
WORKDIR /workspace
COPY conanfile.py CMakePresets.json ./
COPY conan/ conan/
RUN conan profile detect --force && \
    conan install . -pr:h conan/profiles/linux-ci -s build_type=Debug --build=missing && \
    conan install . -pr:h conan/profiles/linux-ci -s build_type=Release --build=missing

ENV CC=gcc-13 CXX=g++-13

COPY . .

CMD ["/bin/bash"]
