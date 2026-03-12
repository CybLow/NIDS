# NidsTargetDefaults.cmake
# Shared function applying consistent compiler flags, warnings, sanitizers,
# and coverage instrumentation to all NIDS targets.
#
# Usage:
#   include(NidsTargetDefaults)
#   nids_set_target_defaults(<target_name>)

function(nids_set_target_defaults target)
    # ── C++20 standard ───────────────────────────────────────────
    target_compile_features(${target} PRIVATE cxx_std_20)
    set_target_properties(${target} PROPERTIES
        CXX_EXTENSIONS OFF
    )

    # ── Compiler warnings ────────────────────────────────────────
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
        )
    elseif(MSVC)
        target_compile_options(${target} PRIVATE
            /W4          # High warning level
            /permissive- # Standards conformance mode
            /utf-8       # Source and execution character set
            /Zc:__cplusplus  # Report correct __cplusplus value
        )
    endif()

    # ── Sanitizers (Debug only, GCC/Clang) ───────────────────────
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE
            $<$<CONFIG:Debug>:-fsanitize=address,undefined>
        )
        target_link_options(${target} PRIVATE
            $<$<CONFIG:Debug>:-fsanitize=address,undefined>
        )
    endif()

    # ── Code coverage (opt-in, GCC/Clang only) ──────────────────
    if(NIDS_COVERAGE)
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(${target} PRIVATE
                --coverage -fprofile-arcs -ftest-coverage
            )
            target_link_options(${target} PRIVATE --coverage)
        endif()
    endif()

    # ── Debug definition ─────────────────────────────────────────
    target_compile_definitions(${target} PRIVATE
        $<$<CONFIG:Debug>:NIDS_DEBUG>
    )
endfunction()
