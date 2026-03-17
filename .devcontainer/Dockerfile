# Devcontainer image for NIDS
#
# Provides a complete C++23/Qt6 development environment with all dependencies
# pre-installed. Works with CLion Dev Containers and VS Code Remote Containers.

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# System dependencies (build + lint + debug tools) and Python tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-13 g++-13 clang-17 clang-tidy-17 clang-tools-17 \
    cmake ninja-build make \
    qt6-base-dev qt6-base-dev-tools \
    libpcap-dev \
    cppcheck valgrind \
    lcov \
    python3 python3-pip python3-venv \
    git ca-certificates curl tar pkg-config \
    gdb lldb-17 \
    bash-completion sudo openssh-server rsync \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --break-system-packages conan gcovr

# Create non-root user (generic name, works with any IDE)
ARG USERNAME=dev
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME 2>/dev/null || true \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME -s /bin/bash 2>/dev/null \
       || usermod -l $USERNAME -d /home/$USERNAME -m $(getent passwd $USER_UID | cut -d: -f1) \
    && echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# Switch to non-root user for Conan profile
USER $USERNAME

# Configure Conan default profile
RUN conan profile detect --force

# Set default compiler
ENV CC=gcc-13 CXX=g++-13

WORKDIR /workspace
