# NidsTargetDefaults.cmake
# Shared function applying consistent compiler flags, warnings, sanitizers,
# and coverage instrumentation to all NIDS targets.
#
# Usage:
#   include(NidsTargetDefaults)
#   nids_set_target_defaults(<target_name>)

function(nids_set_target_defaults target)
    # ── C++23 standard ───────────────────────────────────────────
    target_compile_features(${target} PRIVATE cxx_std_23)
    set_target_properties(${target} PROPERTIES
        CXX_EXTENSIONS OFF
    )

    # ── Compiler warnings ────────────────────────────────────────
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
            -Wshadow                # Variable shadowing
            -Wnon-virtual-dtor      # Virtual methods with non-virtual dtor
            -Wold-style-cast        # C-style casts
            -Woverloaded-virtual    # Accidental hiding of base virtual functions
            -Wformat=2              # Format string issues
        )
        if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            target_compile_options(${target} PRIVATE
                -Wmisleading-indentation  # GCC-only: indentation doesn't match control flow
                -Wduplicated-cond         # GCC-only: duplicated if/else-if conditions
                -Wlogical-op              # GCC-only: suspicious use of logical operators
            )
        endif()
    elseif(MSVC)
        target_compile_options(${target} PRIVATE
            /W4          # High warning level
            /permissive- # Standards conformance mode
            /utf-8       # Source and execution character set
            /Zc:__cplusplus  # Report correct __cplusplus value
        )
    endif()

    # ── Sanitizers (Debug only, GCC/Clang, disabled when coverage is on) ─
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND NOT NIDS_COVERAGE)
        target_compile_options(${target} PRIVATE
            $<$<CONFIG:Debug>:-fsanitize=address,undefined -fno-omit-frame-pointer>
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

    # ── Warnings as errors (CI only) ──────────────────────────────
    if(NIDS_WERROR)
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(${target} PRIVATE -Werror)
        elseif(MSVC)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    endif()

    # ── Debug definition ─────────────────────────────────────────
    target_compile_definitions(${target} PRIVATE
        $<$<CONFIG:Debug>:NIDS_DEBUG>
    )
endfunction()
