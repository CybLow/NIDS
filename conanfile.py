from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMakeDeps, cmake_layout


class NidsConan(ConanFile):
    """Conan 2 dependency file for the NIDS project.

    Manages lightweight C++ dependencies via Conan Center:
      - spdlog          (logging)
      - nlohmann_json   (JSON parsing)
      - pcapplusplus    (packet capture & parsing -- replaces raw libpcap)
      - gRPC            (server/client RPC framework -- Phase 9)
      - GoogleTest      (unit / integration tests)

    Fetched via CMake FetchContent (pre-built binaries):
      - ONNX Runtime    (ML inference -- Microsoft GitHub releases)

    System-provided (not managed by Conan):
      - Qt 6            (UI framework -- system package, too large for Conan binary cache)
    """

    name = "nids"
    version = "0.2.0"
    settings = "os", "compiler", "build_type", "arch"
    options = {"with_grpc": [True, False]}
    default_options = {"with_grpc": False}

    # ── Runtime dependencies ────────────────────────────────────────
    def requirements(self):
        self.requires("spdlog/1.15.1")
        self.requires("nlohmann_json/3.11.3")
        self.requires("pcapplusplus/25.05")
        self.requires("sqlite3/3.47.2")
        self.requires("pcre2/10.44")
        self.requires("bzip2/1.0.8")
        if self.options.with_grpc:
            self.requires("grpc/1.72.0")

    # ── Test-only dependencies ──────────────────────────────────────
    def build_requirements(self):
        self.test_requires("gtest/1.15.0")
        if self.options.with_grpc:
            self.tool_requires("grpc/1.72.0")

    # ── Build-directory layout (matches CMake presets) ──────────────
    def layout(self):
        cmake_layout(self)

    # ── CMake generators ────────────────────────────────────────────
    def generate(self):
        tc = CMakeToolchain(self)
        tc.generate()
        deps = CMakeDeps(self)
        deps.generate()
