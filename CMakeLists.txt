cmake_minimum_required(VERSION 3.20)

project(NIDS
    VERSION 0.2.0
    DESCRIPTION "Network Intrusion Detection System"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

option(NIDS_BUILD_TESTS "Build unit tests" OFF)
option(NIDS_BUILD_SERVER "Build headless server" OFF)
option(NIDS_COVERAGE "Enable code coverage instrumentation" OFF)

include(${CMAKE_SOURCE_DIR}/cmake/FindPCAP.cmake)

find_package(Threads REQUIRED)
find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)
find_package(onnxruntime CONFIG REQUIRED)
find_package(spdlog CONFIG QUIET)

set(NIDS_CORE_SOURCES
    src/core/model/PacketInfo.cpp
    src/core/model/CaptureSession.cpp
    src/core/services/PacketFilter.cpp
    src/core/services/ServiceRegistry.cpp
    src/core/services/Configuration.cpp
)

set(NIDS_INFRA_SOURCES
    src/infra/capture/PcapCapture.cpp
    src/infra/analysis/OnnxAnalyzer.cpp
    src/infra/analysis/AnalyzerFactory.cpp
    src/infra/flow/NativeFlowExtractor.cpp
    src/infra/platform/SocketInit.cpp
)

set(NIDS_APP_SOURCES
    src/app/CaptureController.cpp
    src/app/AnalysisService.cpp
    src/app/ReportGenerator.cpp
)

set(NIDS_UI_SOURCES
    src/ui/MainWindow.cpp
    src/ui/PacketTableModel.cpp
    src/ui/HexView.cpp
    src/ui/FilterPanel.cpp
    src/ui/dialogs/ServiceDialog.cpp
)

set(NIDS_RESOURCES
    src/ui/resources.qrc
)

add_executable(NIDS
    src/main.cpp
    ${NIDS_CORE_SOURCES}
    ${NIDS_INFRA_SOURCES}
    ${NIDS_APP_SOURCES}
    ${NIDS_UI_SOURCES}
    ${NIDS_RESOURCES}
)

target_include_directories(NIDS PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${PCAP_INCLUDE_DIR}
)

target_link_libraries(NIDS PRIVATE
    ${PCAP_LIBRARY}
    Threads::Threads
    Qt::Widgets
    Qt::Core
    Qt::Gui
    onnxruntime::onnxruntime
)

if(spdlog_FOUND)
    target_link_libraries(NIDS PRIVATE spdlog::spdlog)
    target_compile_definitions(NIDS PRIVATE NIDS_HAS_SPDLOG)
endif()

target_compile_definitions(NIDS PRIVATE
    NIDS_HAS_ONNX
    $<$<CONFIG:Debug>:NIDS_DEBUG>
)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(NIDS PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
    )
    target_link_options(NIDS PRIVATE
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
    )
endif()

install(TARGETS NIDS RUNTIME DESTINATION bin)
install(FILES src/model/model.onnx DESTINATION share/nids/model OPTIONAL)

# Packaging
include(CPack)
set(CPACK_PACKAGE_NAME "nids")
set(CPACK_PACKAGE_VENDOR "NIDS Project")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_CONTACT "nids-dev")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set(CPACK_GENERATOR "DEB;RPM;TGZ")
set(CPACK_DEBIAN_PACKAGE_DEPENDS
    "libpcap0.8, libqt6widgets6 (>= 6.2), libqt6gui6 (>= 6.2), libqt6core6 (>= 6.2)")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_RPM_PACKAGE_REQUIRES
    "libpcap, qt6-qtbase")

if(NIDS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
