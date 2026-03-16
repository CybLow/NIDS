#include "server/NidsServer.h"

#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>

#include <chrono>

namespace nids::server {

NidsServer::NidsServer(const ServerConfig& config) : config_(config) {}

NidsServer::~NidsServer() noexcept {
    try {
        stop();
    } catch (...) {
        spdlog::error("Exception in NidsServer destructor during stop()");
    }
}

void NidsServer::setService(std::unique_ptr<NidsServiceImpl> service) {
    service_ = std::move(service);
}

void NidsServer::start() {
    if (running_.load()) {
        return;
    }
    if (!service_) {
        spdlog::error("NidsServer::start() called without a service");
        return;
    }

    grpc::ServerBuilder builder;
    builder.AddListeningPort(config_.listenAddress,
                             grpc::InsecureServerCredentials());
    builder.RegisterService(service_.get());

    builder.SetSyncServerOption(
        grpc::ServerBuilder::SyncServerOption::NUM_CQS,
        config_.maxConcurrentSessions);

    server_ = builder.BuildAndStart();
    if (!server_) {
        spdlog::critical("Failed to start gRPC server on {}",
                         config_.listenAddress);
        return;
    }

    running_.store(true);
    spdlog::info("NIDS gRPC server listening on {}", config_.listenAddress);
}

void NidsServer::stop() {
    if (!running_.load()) {
        return;
    }
    running_.store(false);

    if (server_) {
        auto deadline = std::chrono::system_clock::now() +
                        std::chrono::seconds(5);
        server_->Shutdown(deadline);
        spdlog::info("NIDS gRPC server stopped");
    }
}

void NidsServer::waitForShutdown() {
    if (server_) {
        server_->Wait();
    }
}

} // namespace nids::server
