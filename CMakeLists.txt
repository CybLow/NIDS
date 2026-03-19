cmake_minimum_required(VERSION 3.20)

if(DEFINED PROJECT_VERSION_OVERRIDE)
    project(NIDS
        VERSION ${PROJECT_VERSION_OVERRIDE}
        DESCRIPTION "Network Intrusion Detection System"
        LANGUAGES CXX
    )
else()
    project(NIDS
        VERSION 0.2.0
        DESCRIPTION "Network Intrusion Detection System"
        LANGUAGES CXX
    )
endif()

# ── Global settings ──────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

# ── Project options ──────────────────────────────────────────────
option(NIDS_BUILD_TESTS  "Build unit tests"                    ON)
option(NIDS_BUILD_SERVER "Build headless server"               OFF)
option(NIDS_COVERAGE     "Enable code coverage instrumentation" OFF)
option(NIDS_ENABLE_YARA  "Enable YARA content scanning"        OFF)
option(NIDS_ENABLE_SIGNATURES "Enable Snort signature matching"  OFF)

# ── CMake module path ────────────────────────────────────────────
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(NidsTargetDefaults)

# ── Dependencies ─────────────────────────────────────────────────
# System packages
find_package(PcapPlusPlus CONFIG REQUIRED)
find_package(Threads REQUIRED)
find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

# Pre-built binary (FetchContent)
include(FetchOnnxRuntime)

# Conan-managed packages
find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(SQLite3 CONFIG REQUIRED)
find_package(PCRE2 CONFIG REQUIRED)

# YARA (system package, optional)
if(NIDS_ENABLE_YARA)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(YARA REQUIRED IMPORTED_TARGET yara)
    message(STATUS "YARA ${YARA_VERSION} found")
endif()

# ── Layer libraries ──────────────────────────────────────────────
add_subdirectory(src/core)
add_subdirectory(src/infra)
add_subdirectory(src/app)
add_subdirectory(src/ui)

# ── Main executable ──────────────────────────────────────────────
add_executable(NIDS src/main.cpp)

target_link_libraries(NIDS PRIVATE
    nids_ui
    nids_app
    nids_infra
    nids_core
    spdlog::spdlog
    Qt::Widgets
)

nids_set_target_defaults(NIDS)

# ── Server (headless daemon) ──────────────────────────────────────
if(NIDS_BUILD_SERVER)
    # ── gRPC / Protobuf code generation ──────────────────────────
    find_package(gRPC CONFIG REQUIRED)
    find_package(Protobuf CONFIG REQUIRED)

    # Locate protoc and grpc_cpp_plugin executables.
    # Conan's gRPC build module defines GRPC_CPP_PLUGIN_PROGRAM and
    # Protobuf provides Protobuf_PROTOC_EXECUTABLE.  Fall back to
    # CMAKE_PROGRAM_PATH (set by conan_toolchain.cmake) if unavailable.
    if(TARGET protobuf::protoc)
        get_target_property(_PROTOC protobuf::protoc IMPORTED_LOCATION)
    endif()
    if(NOT _PROTOC)
        find_program(_PROTOC protoc REQUIRED)
    endif()

    if(GRPC_CPP_PLUGIN_PROGRAM)
        set(_GRPC_CPP_PLUGIN "${GRPC_CPP_PLUGIN_PROGRAM}")
    else()
        find_program(_GRPC_CPP_PLUGIN grpc_cpp_plugin REQUIRED)
    endif()

    message(STATUS "protoc: ${_PROTOC}")
    message(STATUS "grpc_cpp_plugin: ${_GRPC_CPP_PLUGIN}")

    set(NIDS_PROTO_DIR "${CMAKE_SOURCE_DIR}/proto")
    set(NIDS_PROTO_FILE "${NIDS_PROTO_DIR}/nids.proto")
    set(NIDS_PROTO_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/proto_gen")
    file(MAKE_DIRECTORY "${NIDS_PROTO_GEN_DIR}")

    set(NIDS_PROTO_SRCS "${NIDS_PROTO_GEN_DIR}/nids.pb.cc")
    set(NIDS_PROTO_HDRS "${NIDS_PROTO_GEN_DIR}/nids.pb.h")
    set(NIDS_GRPC_SRCS  "${NIDS_PROTO_GEN_DIR}/nids.grpc.pb.cc")
    set(NIDS_GRPC_HDRS  "${NIDS_PROTO_GEN_DIR}/nids.grpc.pb.h")

    add_custom_command(
        OUTPUT ${NIDS_PROTO_SRCS} ${NIDS_PROTO_HDRS}
               ${NIDS_GRPC_SRCS} ${NIDS_GRPC_HDRS}
        COMMAND ${_PROTOC}
            --proto_path=${NIDS_PROTO_DIR}
            --cpp_out=${NIDS_PROTO_GEN_DIR}
            --grpc_out=${NIDS_PROTO_GEN_DIR}
            --plugin=protoc-gen-grpc=${_GRPC_CPP_PLUGIN}
            ${NIDS_PROTO_FILE}
        DEPENDS ${NIDS_PROTO_FILE}
        COMMENT "Generating gRPC/Protobuf C++ stubs from nids.proto"
        VERBATIM
    )

    # Library for generated proto stubs (shared by server + client)
    add_library(nids_proto STATIC
        ${NIDS_PROTO_SRCS}
        ${NIDS_GRPC_SRCS}
    )
    target_include_directories(nids_proto SYSTEM PUBLIC "${NIDS_PROTO_GEN_DIR}")
    target_link_libraries(nids_proto PUBLIC
        gRPC::grpc++
        protobuf::libprotobuf
    )
    # Suppress warnings in generated code
    target_compile_options(nids_proto PRIVATE -w)

    add_subdirectory(src/server)
    add_subdirectory(src/client)

    install(TARGETS nids-server nids-cli nids-server-lib nids-client-lib
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        ARCHIVE DESTINATION lib
    )
endif()

# ── Install rules ────────────────────────────────────────────────
include(GNUInstallDirs)

install(TARGETS NIDS RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(FILES models/model.onnx
    DESTINATION ${CMAKE_INSTALL_DATADIR}/nids/model OPTIONAL)
install(FILES models/model_metadata.json
    DESTINATION ${CMAKE_INSTALL_DATADIR}/nids/model OPTIONAL)

install(DIRECTORY data/threat_intel/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/nids/threat_intel
    FILES_MATCHING PATTERN "*.txt" PATTERN "*.csv" PATTERN "*.list"
    PATTERN ".gitkeep" EXCLUDE)

if(UNIX)
    install(PROGRAMS scripts/ops/update_threat_feeds.sh
        DESTINATION ${CMAKE_INSTALL_DATADIR}/nids/scripts OPTIONAL)
    install(FILES deploy/nids-server.service
        DESTINATION lib/systemd/system OPTIONAL)
endif()

if(WIN32 AND TARGET onnxruntime::onnxruntime)
    get_target_property(_ort_dll onnxruntime::onnxruntime IMPORTED_LOCATION)
    if(_ort_dll)
        install(FILES "${_ort_dll}" DESTINATION ${CMAKE_INSTALL_BINDIR})
    endif()
endif()

# ── Packaging (CPack) ───────────────────────────────────────────
set(CPACK_PACKAGE_NAME "nids")
set(CPACK_PACKAGE_VENDOR "NIDS Project")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_CONTACT "nids-dev@users.noreply.github.com")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")

if(WIN32)
    set(CPACK_GENERATOR "NSIS;ZIP")
    set(CPACK_NSIS_DISPLAY_NAME "NIDS ${PROJECT_VERSION}")
    set(CPACK_NSIS_PACKAGE_NAME "NIDS")
    set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)
    set(CPACK_NSIS_MUI_ICON "${CMAKE_SOURCE_DIR}/src/ui/logo.ico")
elseif(APPLE)
    set(CPACK_GENERATOR "DragNDrop;TGZ")
else()
    set(CPACK_GENERATOR "DEB;RPM;TGZ")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libpcap0.8, libstdc++6")
    set(CPACK_DEBIAN_PACKAGE_SECTION "net")
    set(CPACK_RPM_PACKAGE_REQUIRES
        "libpcap, libstdc++")
endif()

include(CPack)

# ── Documentation (Doxygen) ──────────────────────────────────────
find_package(Doxygen QUIET)
if(DOXYGEN_FOUND)
    add_custom_target(docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_SOURCE_DIR}/docs/Doxyfile
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM
    )
else()
    message(STATUS "Doxygen not found -- 'docs' target unavailable")
endif()

# ── Tests ────────────────────────────────────────────────────────
if(NIDS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
