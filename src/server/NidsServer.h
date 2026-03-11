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

/** Configuration for the gRPC server. */
struct ServerConfig {
    /** Address and port to listen on (e.g. "0.0.0.0:50051"). */
    std::string listenAddress = "0.0.0.0:50051";
    /** Maximum number of concurrent capture/analysis sessions. */
    int maxConcurrentSessions = 4;
};

/** gRPC server that exposes NIDS capture and analysis as a headless daemon. */
class NidsServer {
public:
    /** Construct with the given server configuration. */
    explicit NidsServer(const ServerConfig& config);
    /** Shut down the server and release resources. */
    ~NidsServer();

    /** Start the gRPC server and begin accepting connections. */
    void start();
    /** Initiate a graceful shutdown of the server. */
    void stop();
    /** Block the calling thread until the server has fully shut down. */
    static void waitForShutdown();

private:
    ServerConfig config_;
    std::atomic<bool> running_{false};
};

} // namespace nids::server
