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
    spdlog::warn("gRPC integration pending — see Phase 9 in docs/roadmap.md");
}

void NidsServer::stop() {
    if (!running_.load()) return;
    running_.store(false);
    spdlog::info("NIDS Server stopped");
}

void NidsServer::waitForShutdown() {
    // Will block on gRPC server once implemented
}

} // namespace nids::server
