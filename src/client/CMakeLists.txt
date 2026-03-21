# ── Client library ──────────────────────────────────────────────
add_library(nids-client-lib STATIC
    NidsClient.cpp
)
target_link_libraries(nids-client-lib PUBLIC
    nids_proto
    nids_core
    Threads::Threads
    spdlog::spdlog
)
target_include_directories(nids-client-lib PUBLIC "${CMAKE_SOURCE_DIR}/src")
nids_set_target_defaults(nids-client-lib)

# ── CLI client executable ──────────────────────────────────────
add_executable(nids-cli cli_main.cpp)
target_link_libraries(nids-cli PRIVATE
    nids-client-lib
    nids_app
    spdlog::spdlog
)
nids_set_target_defaults(nids-cli)
