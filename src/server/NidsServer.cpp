#include "server/NidsServer.h"

#include <spdlog/spdlog.h>

namespace nids::server {

NidsServer::NidsServer(const ServerConfig& config)
    : config_(config) {}

NidsServer::~NidsServer() {
    stop();
}

void NidsServer::start() {
    if (running_.load()) return;
    running_.store(true);

    spdlog::info("NIDS Server starting on {}", config_.listenAddress);
    spdlog::warn("gRPC integration pending. Add grpc to vcpkg.json and "
                 "generate proto stubs to complete server implementation.");

    // TODO: Build and register gRPC service
    // grpc::ServerBuilder builder;
    // builder.AddListeningPort(config_.listenAddress, grpc::InsecureServerCredentials());
    // NidsServiceImpl service(controller, analysisService);
    // builder.RegisterService(&service);
    // server_ = builder.BuildAndStart();
}

void NidsServer::stop() {
    if (!running_.load()) return;
    running_.store(false);

    // server_->Shutdown();
    spdlog::info("NIDS Server stopped");
}

void NidsServer::waitForShutdown() {
    // server_->Wait();
}

} // namespace nids::server
