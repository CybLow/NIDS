#pragma once

/// gRPC Server stub for the NIDS headless daemon.
///
/// This file provides the scaffolding for the server-side gRPC implementation.
/// To build, enable NIDS_BUILD_SERVER in CMake and ensure grpc/protobuf are
/// available via the system package manager (e.g., `dnf install grpc-devel`).
///
/// Implementation steps (Phase 9 — see docs/roadmap.md):
///   1. Define proto/nids.proto service
///   2. Generate C++ stubs with protoc + grpc_cpp_plugin
///   3. Implement NidsServiceImpl using CaptureController, AnalysisService,
///      and HybridDetectionService
///   4. Wire Configuration::instance() for model path, thread count, etc.

#include <memory>
#include <string>
#include <atomic>

namespace nids::server {

struct ServerConfig {
    std::string listenAddress = "0.0.0.0:50051";
    int maxConcurrentSessions = 4;
};

class NidsServer {
public:
    explicit NidsServer(const ServerConfig& config);
    ~NidsServer();

    void start();
    void stop();
    void waitForShutdown();

private:
    ServerConfig config_;
    std::atomic<bool> running_{false};
};

} // namespace nids::server
