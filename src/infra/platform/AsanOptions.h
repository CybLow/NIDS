#pragma once

/// Shared ASan default options for all NIDS executables.
///
/// gRPC 1.72.0 has use-after-poison false positives in its epoll/thread-pool
/// internals (abseil StatusRep::SetPayload) when compiled with GCC 15 + ASan.
/// Disable user-poisoning detection to avoid false aborts from gRPC's arena.
///
/// Include this header in exactly one translation unit per executable that
/// links gRPC (typically *_main.cpp).  The extern "C" definition must appear
/// at file scope, not inside a namespace.

#if defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer)
extern "C" const char* __asan_default_options() {  // NOLINT
    return "allow_user_poisoning=0";
}
#endif
