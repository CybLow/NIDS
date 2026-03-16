# ── Server library ──────────────────────────────────────────────
add_library(nids-server-lib STATIC
    GrpcStreamSink.cpp
    NidsServiceImpl.cpp
    NidsServer.cpp
)
target_link_libraries(nids-server-lib PUBLIC
    nids_proto
    nids_app
    nids_infra
    nids_core
    Threads::Threads
    spdlog::spdlog
)
target_include_directories(nids-server-lib PUBLIC "${CMAKE_SOURCE_DIR}/src")
nids_set_target_defaults(nids-server-lib)

# ── Server executable ──────────────────────────────────────────
add_executable(nids-server server_main.cpp)
target_link_libraries(nids-server PRIVATE
    nids-server-lib
    nids_app
    nids_infra
    nids_core
    spdlog::spdlog
)
nids_set_target_defaults(nids-server)
