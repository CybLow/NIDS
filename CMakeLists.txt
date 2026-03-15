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
    add_library(nids-server-lib STATIC
        src/server/NidsServer.cpp
    )
    target_link_libraries(nids-server-lib PRIVATE
        nids_core
        Threads::Threads
        spdlog::spdlog
    )
    nids_set_target_defaults(nids-server-lib)

    add_executable(nids-server src/server/server_main.cpp)
    target_link_libraries(nids-server PRIVATE
        nids_app
        nids_infra
        nids_core
        spdlog::spdlog
    )
    nids_set_target_defaults(nids-server)

    add_library(nids-client-lib STATIC
        src/client/NidsClient.cpp
    )
    target_link_libraries(nids-client-lib PRIVATE
        nids_core
        Threads::Threads
        spdlog::spdlog
    )
    nids_set_target_defaults(nids-client-lib)

    install(TARGETS nids-server nids-server-lib nids-client-lib
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
        "libqt6widgets6 (>= 6.2), libqt6gui6 (>= 6.2), libqt6core6 (>= 6.2)")
    set(CPACK_DEBIAN_PACKAGE_SECTION "net")
    set(CPACK_RPM_PACKAGE_REQUIRES
        "qt6-qtbase")
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
