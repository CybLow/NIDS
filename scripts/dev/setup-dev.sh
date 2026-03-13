#!/usr/bin/env bash
# setup-dev.sh -- Automated developer environment setup for NIDS (Linux)
#
# Detects Fedora/Ubuntu/Debian, installs all system dependencies, configures
# Conan 2 with the in-repo profile, and runs conan install for Debug + Release.
#
# Usage:
#   ./scripts/dev/setup-dev.sh            # Full setup (install packages + configure)
#   ./scripts/dev/setup-dev.sh --no-install  # Skip package installation (Conan only)
#   ./scripts/dev/setup-dev.sh --help
#
# Requirements:
#   - Root/sudo access (for system package installation)
#   - Internet connection (for Conan package downloads)

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()   { error "$@"; exit 1; }

# ── Defaults ─────────────────────────────────────────────────────
SKIP_INSTALL=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONAN_PROFILE="$PROJECT_ROOT/conan/profiles/linux-gcc13"

# ── Parse arguments ──────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --no-install) SKIP_INSTALL=true ;;
        --help|-h)
            echo "Usage: $0 [--no-install] [--help]"
            echo ""
            echo "  --no-install   Skip system package installation (Conan setup only)"
            echo "  --help         Show this message"
            exit 0
            ;;
        *) die "Unknown argument: $arg" ;;
    esac
done

# ── Detect distro ───────────────────────────────────────────────
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    else
        die "Cannot detect Linux distribution (no /etc/os-release)"
    fi
}

# ── Install system packages ─────────────────────────────────────
install_fedora() {
    info "Installing system packages for Fedora..."
    sudo dnf install -y \
        gcc gcc-c++ \
        cmake ninja-build \
        qt6-qtbase-devel \
        libpcap-devel \
        python3 python3-pip \
        git curl tar pkg-config
    ok "Fedora system packages installed"
}

install_ubuntu() {
    info "Installing system packages for Ubuntu/Debian..."
    sudo apt-get update
    sudo apt-get install -y --no-install-recommends \
        gcc g++ \
        cmake ninja-build \
        qt6-base-dev qt6-base-dev-tools \
        libpcap-dev \
        python3 python3-pip python3-venv \
        git curl tar pkg-config \
        '^libxcb.*-dev' libx11-xcb-dev libglu1-mesa-dev libxrender-dev \
        libxi-dev libxkbcommon-dev libxkbcommon-x11-dev libegl1-mesa-dev
    ok "Ubuntu/Debian system packages installed"
}

install_packages() {
    local distro
    distro="$(detect_distro)"

    case "$distro" in
        fedora)     install_fedora ;;
        ubuntu|debian|linuxmint|pop)
                    install_ubuntu ;;
        *)          warn "Unsupported distro '$distro'. Install manually:"
                    echo "  - GCC (C++20), CMake >= 3.20, Ninja, Qt6 (Core/Gui/Widgets)"
                    echo "  - libpcap-dev, Python 3, pip"
                    echo ""
                    echo "Then re-run: $0 --no-install"
                    exit 1
                    ;;
    esac
}

# ── Install Conan ────────────────────────────────────────────────
install_conan() {
    if command -v conan &>/dev/null; then
        local ver
        ver="$(conan --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' || echo "unknown")"
        ok "Conan already installed (v${ver})"

        # Check it's Conan 2.x
        if [[ "$ver" == 1.* ]]; then
            warn "Conan 1.x detected. NIDS requires Conan 2. Upgrading..."
            pip3 install --break-system-packages --upgrade conan 2>/dev/null \
                || pip3 install --upgrade conan
        fi
    else
        info "Installing Conan 2..."
        pip3 install --break-system-packages conan 2>/dev/null \
            || pip3 install conan
        ok "Conan installed"
    fi

    # Verify
    conan --version || die "Conan installation failed"
}

# ── Configure Conan with in-repo profile ─────────────────────────
configure_conan() {
    info "Detecting Conan default profile..."
    conan profile detect --force >/dev/null 2>&1

    if [ ! -f "$CONAN_PROFILE" ]; then
        die "In-repo Conan profile not found: $CONAN_PROFILE"
    fi
    ok "Using in-repo Conan profile: $CONAN_PROFILE"
}

# ── Install Conan dependencies ───────────────────────────────────
install_conan_deps() {
    info "Installing Conan dependencies (Debug)..."
    conan install "$PROJECT_ROOT" \
        -pr:h "$CONAN_PROFILE" \
        -s build_type=Debug \
        --build=missing

    info "Installing Conan dependencies (Release)..."
    conan install "$PROJECT_ROOT" \
        -pr:h "$CONAN_PROFILE" \
        -s build_type=Release \
        --build=missing

    ok "Conan dependencies installed for Debug + Release"
}

# ── Print next steps ─────────────────────────────────────────────
print_next_steps() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  NIDS development environment is ready ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Conan has generated CMakeUserPresets.json. Use the committed presets"
    echo "in CMakePresets.json for development (Debug, Release)."
    echo ""
    echo "Quick start:"
    echo ""
    echo "  # Debug build (with ASan/UBSan):"
    echo "  cmake --preset Debug"
    echo "  cmake --build --preset Debug"
    echo "  ctest --preset Debug"
    echo ""
    echo "  # Release build:"
    echo "  cmake --preset Release"
    echo "  cmake --build --preset Release"
    echo "  ctest --preset Release"
    echo ""
    echo "  # Run (requires root or CAP_NET_RAW):"
    echo "  sudo ./build/Debug/NIDS"
    echo ""
}

# ── Main ─────────────────────────────────────────────────────────
main() {
    echo ""
    info "NIDS Developer Environment Setup"
    info "Project root: $PROJECT_ROOT"
    echo ""

    if [ "$SKIP_INSTALL" = false ]; then
        install_packages
    else
        info "Skipping system package installation (--no-install)"
    fi

    install_conan
    configure_conan
    install_conan_deps
    print_next_steps
}

main "$@"
