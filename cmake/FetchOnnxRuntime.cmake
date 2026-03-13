# FetchOnnxRuntime.cmake -- Download pre-built ONNX Runtime binaries
#
# Downloads official release binaries from Microsoft's GitHub releases
# instead of building from source. This avoids:
#   - GCC 15 + Eigen template incompatibilities
#   - 20+ transitive build dependencies (abseil, protobuf, flatbuffers, ...)
#   - 30+ minute build times
#
# Creates an IMPORTED target: onnxruntime::onnxruntime
# Supported: Linux x64, Windows x64, macOS x64/arm64

include(FetchContent)

set(ORT_VERSION "1.23.2")

# ── Platform / architecture dispatch ────────────────────────────
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    set(ORT_PLATFORM "linux-x64")
    set(ORT_EXT "tgz")
    set(ORT_SHA512
        "ac836c937ec30aecad03360ebc338338641a3421143d51c8eb45c71b346fd6e3ab3f680ce52ee99582cee27c051418789064543ec3361d574b1940c9c49a8a7c")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows" AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64|x64")
    set(ORT_PLATFORM "win-x64")
    set(ORT_EXT "zip")
    set(ORT_SHA512
        "3f3aecea57a38fca987401306e72cde4058828a41ee57e16cc9ff3363eaaba16c43ae65545a280f0fd485da535d6e18541838cf5ccd12c13374f8f0a66704d0d")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    set(ORT_PLATFORM "osx-x86_64")
    set(ORT_EXT "tgz")
    set(ORT_SHA512
        "a063a33583c54148894459087e57463bf2b71212540ac1e4c6d8ea6b3d98986380d0f9a70cb1bd9321558c309cbeb8ca5a89eb0e853877769ed744485a23777e")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
    set(ORT_PLATFORM "osx-arm64")
    set(ORT_EXT "tgz")
    set(ORT_SHA512
        "1857377ec646de358241f293f3215dfb60e4ad82638d378b3fd704ac9d84ddd70783c944fec39b7517fb8b8d9627c230e8a7a16caa3a4ee20638876d7514359f")
else()
    message(FATAL_ERROR
        "ONNX Runtime pre-built binaries not available for "
        "${CMAKE_SYSTEM_NAME}/${CMAKE_SYSTEM_PROCESSOR}. "
        "See https://github.com/microsoft/onnxruntime/releases")
endif()

# ── Download via FetchContent ───────────────────────────────────
set(ORT_FILENAME "onnxruntime-${ORT_PLATFORM}-${ORT_VERSION}.${ORT_EXT}")
set(ORT_URL "https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/${ORT_FILENAME}")

FetchContent_Declare(onnxruntime
    URL      "${ORT_URL}"
    URL_HASH SHA512=${ORT_SHA512}
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_MakeAvailable(onnxruntime)

# ── Create IMPORTED target ──────────────────────────────────────
if(NOT TARGET onnxruntime::onnxruntime)
    add_library(onnxruntime::onnxruntime SHARED IMPORTED GLOBAL)

    set_target_properties(onnxruntime::onnxruntime PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${onnxruntime_SOURCE_DIR}/include"
    )

    if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        set_property(TARGET onnxruntime::onnxruntime APPEND PROPERTY
            IMPORTED_CONFIGURATIONS RELEASE)
        set_target_properties(onnxruntime::onnxruntime PROPERTIES
            IMPORTED_IMPLIB_RELEASE "${onnxruntime_SOURCE_DIR}/lib/onnxruntime.lib"
            IMPORTED_LOCATION_RELEASE "${onnxruntime_SOURCE_DIR}/lib/onnxruntime.dll"
        )
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        set_target_properties(onnxruntime::onnxruntime PROPERTIES
            IMPORTED_LOCATION "${onnxruntime_SOURCE_DIR}/lib/libonnxruntime.dylib"
        )
    else()
        set_target_properties(onnxruntime::onnxruntime PROPERTIES
            IMPORTED_LOCATION "${onnxruntime_SOURCE_DIR}/lib/libonnxruntime.so"
            IMPORTED_SONAME "libonnxruntime.so.1"
        )
    endif()
endif()

message(STATUS "ONNX Runtime ${ORT_VERSION} (${ORT_PLATFORM}) -- pre-built binary")
