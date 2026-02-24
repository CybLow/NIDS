#pragma once

// gRPC Server stub for the NIDS headless daemon.
//
// This file provides the scaffolding for the server-side gRPC implementation.
// To build, enable NIDS_BUILD_SERVER in CMake and ensure grpc/protobuf are
// available via vcpkg.
//
// Implementation steps:
// 1. Generate C++ sources from proto/nids.proto using protoc + grpc_cpp_plugin
// 2. Implement NidsServiceImpl below
// 3. Wire CaptureController and AnalysisService into the gRPC handlers
//
// Example CMake integration:
//   find_package(gRPC CONFIG REQUIRED)
//   find_package(Protobuf CONFIG REQUIRED)
//   add_executable(nids-server src/server/main.cpp src/server/NidsServer.cpp ...)
//   target_link_libraries(nids-server PRIVATE gRPC::grpc++ protobuf::libprotobuf ...)

#include "app/CaptureController.h"
#include "app/AnalysisService.h"

#include <memory>
#include <string>
#include <atomic>

namespace nids::server {

struct ServerConfig {
    std::string listenAddress = "0.0.0.0:50051";
    std::string modelPath = "../src/model/model.json";
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
    // gRPC server handle would go here once grpc is added as dependency
    // std::unique_ptr<grpc::Server> server_;
};

} // namespace nids::server
