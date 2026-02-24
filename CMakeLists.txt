cmake_minimum_required(VERSION 3.20)

project(NIDS
    VERSION 0.2.0
    DESCRIPTION "Network Intrusion Detection System"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

option(NIDS_BUILD_TESTS "Build unit tests" OFF)
option(NIDS_BUILD_SERVER "Build headless server" OFF)

include(${CMAKE_SOURCE_DIR}/cmake/FindPCAP.cmake)

find_package(Threads REQUIRED)
find_package(Qt5 COMPONENTS Core Gui Widgets REQUIRED)
find_package(frugally-deep CONFIG REQUIRED)
find_package(spdlog CONFIG QUIET)

set(NIDS_CORE_SOURCES
    src/core/model/PacketInfo.cpp
    src/core/model/CaptureSession.cpp
    src/core/services/PacketFilter.cpp
    src/core/services/ServiceRegistry.cpp
)

set(NIDS_INFRA_SOURCES
    src/infra/capture/PcapCapture.cpp
    src/infra/analysis/FdeepAnalyzer.cpp
    src/infra/flow/CsvFlowProcessor.cpp
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

add_executable(NIDS
    src/main.cpp
    ${NIDS_CORE_SOURCES}
    ${NIDS_INFRA_SOURCES}
    ${NIDS_APP_SOURCES}
    ${NIDS_UI_SOURCES}
)

target_include_directories(NIDS PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${PCAP_INCLUDE_DIR}
)

target_link_libraries(NIDS PRIVATE
    ${PCAP_LIBRARY}
    Threads::Threads
    Qt5::Widgets
    Qt5::Core
    Qt5::Gui
    frugally-deep::fdeep
)

if(spdlog_FOUND)
    target_link_libraries(NIDS PRIVATE spdlog::spdlog)
    target_compile_definitions(NIDS PRIVATE NIDS_HAS_SPDLOG)
endif()

target_compile_definitions(NIDS PRIVATE
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
install(FILES src/model/model.json DESTINATION share/nids/model)

if(NIDS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
