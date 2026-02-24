find_package(GTest CONFIG REQUIRED)

include(GoogleTest)

set(TEST_SOURCES
    unit/test_PacketFilter.cpp
    unit/test_ServiceRegistry.cpp
    unit/test_CaptureSession.cpp
    unit/test_AttackType.cpp
    unit/test_ReportGenerator.cpp
)

set(TESTED_SOURCES
    ${CMAKE_SOURCE_DIR}/src/core/services/PacketFilter.cpp
    ${CMAKE_SOURCE_DIR}/src/core/services/ServiceRegistry.cpp
    ${CMAKE_SOURCE_DIR}/src/core/model/CaptureSession.cpp
    ${CMAKE_SOURCE_DIR}/src/core/model/PacketInfo.cpp
    ${CMAKE_SOURCE_DIR}/src/app/ReportGenerator.cpp
)

add_executable(nids_tests ${TEST_SOURCES} ${TESTED_SOURCES})

target_include_directories(nids_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(nids_tests PRIVATE
    GTest::gtest
    GTest::gtest_main
    GTest::gmock
    Threads::Threads
)

target_compile_features(nids_tests PRIVATE cxx_std_17)

gtest_discover_tests(nids_tests)
