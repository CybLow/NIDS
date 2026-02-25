find_package(GTest CONFIG REQUIRED)
find_package(Qt6 COMPONENTS Core Test QUIET)
find_package(onnxruntime CONFIG QUIET)
find_package(spdlog CONFIG QUIET)

include(GoogleTest)

# ── Core/App tests (no Qt, no ONNX Runtime) ──────────────────────────

set(TEST_SOURCES
    unit/test_PacketFilter.cpp
    unit/test_ServiceRegistry.cpp
    unit/test_CaptureSession.cpp
    unit/test_AttackType.cpp
    unit/test_ReportGenerator.cpp
    unit/test_NativeFlowExtractor.cpp
    unit/test_Configuration.cpp
)

set(TESTED_SOURCES
    ${CMAKE_SOURCE_DIR}/src/core/services/PacketFilter.cpp
    ${CMAKE_SOURCE_DIR}/src/core/services/ServiceRegistry.cpp
    ${CMAKE_SOURCE_DIR}/src/core/services/Configuration.cpp
    ${CMAKE_SOURCE_DIR}/src/core/model/CaptureSession.cpp
    ${CMAKE_SOURCE_DIR}/src/core/model/PacketInfo.cpp
    ${CMAKE_SOURCE_DIR}/src/app/ReportGenerator.cpp
    ${CMAKE_SOURCE_DIR}/src/infra/flow/NativeFlowExtractor.cpp
)

add_executable(nids_tests ${TEST_SOURCES} ${TESTED_SOURCES})

target_include_directories(nids_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${PCAP_INCLUDE_DIR}
)

target_link_libraries(nids_tests PRIVATE
    GTest::gtest
    GTest::gtest_main
    GTest::gmock
    Threads::Threads
    ${PCAP_LIBRARY}
)

target_compile_features(nids_tests PRIVATE cxx_std_20)

if(NIDS_COVERAGE)
    target_compile_options(nids_tests PRIVATE --coverage -fprofile-arcs -ftest-coverage)
    target_link_options(nids_tests PRIVATE --coverage)
endif()

gtest_discover_tests(nids_tests)

# ── Qt-dependent tests (CaptureController, AnalysisService, Pipeline) ─

if(Qt6_FOUND)
    set(QT_TEST_SOURCES
        unit/test_CaptureController.cpp
        unit/test_AnalysisService.cpp
        integration/test_Pipeline.cpp
    )

    set(QT_TESTED_SOURCES
        ${CMAKE_SOURCE_DIR}/src/app/CaptureController.cpp
        ${CMAKE_SOURCE_DIR}/src/app/AnalysisService.cpp
        ${CMAKE_SOURCE_DIR}/src/core/model/CaptureSession.cpp
        ${CMAKE_SOURCE_DIR}/src/core/model/PacketInfo.cpp
        ${CMAKE_SOURCE_DIR}/src/core/services/PacketFilter.cpp
        ${CMAKE_SOURCE_DIR}/src/core/services/Configuration.cpp
    )

    add_executable(nids_qt_tests ${QT_TEST_SOURCES} ${QT_TESTED_SOURCES})

    target_include_directories(nids_qt_tests PRIVATE
        ${CMAKE_SOURCE_DIR}/src
    )

    target_link_libraries(nids_qt_tests PRIVATE
        GTest::gtest
        GTest::gtest_main
        GTest::gmock
        Threads::Threads
        Qt::Core
    )

    if(spdlog_FOUND)
        target_link_libraries(nids_qt_tests PRIVATE spdlog::spdlog)
    endif()

    target_compile_features(nids_qt_tests PRIVATE cxx_std_20)

    if(NIDS_COVERAGE)
        target_compile_options(nids_qt_tests PRIVATE --coverage -fprofile-arcs -ftest-coverage)
        target_link_options(nids_qt_tests PRIVATE --coverage)
    endif()

    gtest_discover_tests(nids_qt_tests)
else()
    message(STATUS "Qt6 not found — skipping Qt-dependent tests")
endif()

# ── ONNX Runtime tests (OnnxAnalyzer, AnalyzerFactory) ────────────────

if(onnxruntime_FOUND)
    set(ONNX_TEST_SOURCES
        unit/test_OnnxAnalyzer.cpp
    )

    set(ONNX_TESTED_SOURCES
        ${CMAKE_SOURCE_DIR}/src/infra/analysis/OnnxAnalyzer.cpp
        ${CMAKE_SOURCE_DIR}/src/infra/analysis/AnalyzerFactory.cpp
        ${CMAKE_SOURCE_DIR}/src/core/services/Configuration.cpp
    )

    add_executable(nids_onnx_tests ${ONNX_TEST_SOURCES} ${ONNX_TESTED_SOURCES})

    target_include_directories(nids_onnx_tests PRIVATE
        ${CMAKE_SOURCE_DIR}/src
    )

    target_link_libraries(nids_onnx_tests PRIVATE
        GTest::gtest
        GTest::gtest_main
        GTest::gmock
        Threads::Threads
        onnxruntime::onnxruntime
    )

    if(spdlog_FOUND)
        target_link_libraries(nids_onnx_tests PRIVATE spdlog::spdlog)
    endif()

    target_compile_features(nids_onnx_tests PRIVATE cxx_std_20)

    if(NIDS_COVERAGE)
        target_compile_options(nids_onnx_tests PRIVATE --coverage -fprofile-arcs -ftest-coverage)
        target_link_options(nids_onnx_tests PRIVATE --coverage)
    endif()

    gtest_discover_tests(nids_onnx_tests)
else()
    message(STATUS "onnxruntime not found — skipping ONNX analyzer tests")
endif()
