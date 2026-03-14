# tests/CMakeLists.txt
# All test targets link pre-built layer libraries instead of re-compiling sources.

find_package(GTest CONFIG REQUIRED)
find_package(Qt6 COMPONENTS Core Test QUIET)

include(GoogleTest)

# ── Helper: apply coverage flags to test targets ─────────────────
function(nids_test_coverage target)
    if(NIDS_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE
            --coverage -fprofile-arcs -ftest-coverage)
        target_link_options(${target} PRIVATE --coverage)
    endif()
endfunction()

# ── Helper: register gtest with platform-aware discovery ─────────
# On Windows, DLLs aren't in PATH at build time, so POST_BUILD
# discovery fails. PRE_TEST defers to ctest; TARGET_RUNTIME_DLLS
# copies CMake-known DLLs next to the test exe.
function(nids_register_gtest target)
    if(WIN32)
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    $<TARGET_RUNTIME_DLLS:${target}>
                    $<TARGET_FILE_DIR:${target}>
            COMMAND_EXPAND_LISTS
        )

        gtest_discover_tests(${target}
            DISCOVERY_MODE PRE_TEST
            WORKING_DIRECTORY $<TARGET_FILE_DIR:${target}>
            ${ARGN}
        )
    else()
        gtest_discover_tests(${target} ${ARGN})
    endif()
endfunction()

# ══════════════════════════════════════════════════════════════════
#  Unit tests
#  Note: transitively links PcapPlusPlus, ONNX Runtime, Qt Core via nids_infra.
# ══════════════════════════════════════════════════════════════════

add_executable(nids_tests
    unit/test_PacketFilter.cpp
    unit/test_ServiceRegistry.cpp
    unit/test_CaptureSession.cpp
    unit/test_AttackType.cpp
    unit/test_ReportGenerator.cpp
    unit/test_NativeFlowExtractor.cpp
    unit/test_Configuration.cpp
    unit/test_DetectionResult.cpp
    unit/test_PredictionResult.cpp
    unit/test_ThreatIntelProvider.cpp
    unit/test_HeuristicRuleEngine.cpp
    unit/test_HybridDetectionService.cpp
    unit/test_FeatureNormalizer.cpp
)

target_link_libraries(nids_tests PRIVATE
    GTest::gtest
    GTest::gtest_main
    GTest::gmock
    nids_core
    nids_infra
    nids_app
)

nids_set_target_defaults(nids_tests)
nids_test_coverage(nids_tests)
nids_register_gtest(nids_tests)

# ══════════════════════════════════════════════════════════════════
#  Qt-dependent tests
# ══════════════════════════════════════════════════════════════════

if(Qt6_FOUND)
    add_executable(nids_qt_tests
        unit/test_CaptureController.cpp
        unit/test_AnalysisService.cpp
        integration/test_Pipeline.cpp
    )

    target_link_libraries(nids_qt_tests PRIVATE
        GTest::gtest
        GTest::gtest_main
        GTest::gmock
        nids_core
        nids_infra
        nids_app
        Qt::Core
        Qt::Test
    )

    nids_set_target_defaults(nids_qt_tests)
    nids_test_coverage(nids_qt_tests)
    nids_register_gtest(nids_qt_tests)
else()
    message(STATUS "Qt6 not found -- skipping Qt-dependent tests")
endif()

# ══════════════════════════════════════════════════════════════════
#  Stress / performance tests
#  Pcap-dependent performance tests.
# ══════════════════════════════════════════════════════════════════

add_executable(nids_stress_tests
    stress/test_PacketThroughput.cpp
    stress/test_FlowExtractionLoad.cpp
    stress/test_MlInferenceLatency.cpp
    stress/test_ConcurrentAnalysis.cpp
    stress/test_MemoryStress.cpp
)

target_include_directories(nids_stress_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/tests
)

target_link_libraries(nids_stress_tests PRIVATE
    GTest::gtest
    GTest::gtest_main
    GTest::gmock
    nids_core
    nids_infra
    nids_app
    spdlog::spdlog
)

nids_set_target_defaults(nids_stress_tests)
nids_test_coverage(nids_stress_tests)
nids_register_gtest(nids_stress_tests
    PROPERTIES TIMEOUT 120
)

# ══════════════════════════════════════════════════════════════════
#  ONNX Runtime tests
# ══════════════════════════════════════════════════════════════════

if(TARGET onnxruntime::onnxruntime)
    add_executable(nids_onnx_tests
        unit/test_OnnxAnalyzer.cpp
    )

    target_link_libraries(nids_onnx_tests PRIVATE
        GTest::gtest
        GTest::gtest_main
        GTest::gmock
        nids_core
        nids_infra
        onnxruntime::onnxruntime
    )

    nids_set_target_defaults(nids_onnx_tests)
    nids_test_coverage(nids_onnx_tests)
    nids_register_gtest(nids_onnx_tests)
else()
    message(STATUS "onnxruntime target not available -- skipping ONNX analyzer tests")
endif()
