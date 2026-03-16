# src/core/CMakeLists.txt
# Domain layer — pure C++23, zero external dependencies.

add_library(nids_core STATIC
    model/CaptureSession.cpp
    model/PacketFilter.cpp
    services/ServiceRegistry.cpp
    services/Configuration.cpp
)

target_include_directories(nids_core PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

nids_set_target_defaults(nids_core)
