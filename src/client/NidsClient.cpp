#include "client/NidsClient.h"

#include <spdlog/spdlog.h>

namespace nids::client {

NidsClient::NidsClient(const ClientConfig& config)
    : config_(config) {}

NidsClient::~NidsClient() {
    disconnect();
}

bool NidsClient::connect() {
    spdlog::info("Connecting to NIDS server at {}", config_.serverAddress);
    spdlog::warn("gRPC integration pending — see Phase 9 in docs/roadmap.md");
    return false;
}

void NidsClient::disconnect() {
    connected_ = false;
}

std::vector<std::string> NidsClient::listInterfaces() {
    if (!connected_)
        return {};
    return {};
}

std::string NidsClient::startCapture(const std::string& /*interface*/,
                                      const CaptureFilter& /*filter*/) {
    if (!connected_)
        return "";
    return "";
}

bool NidsClient::stopCapture(const std::string& /*sessionId*/) {
    if (!connected_)
        return false;
    return false;
}

void NidsClient::streamPackets(const std::string& /*sessionId*/,
                                PacketCallback /*callback*/) {
    if (!connected_)
        return;
}

bool NidsClient::analyzeCapture(const std::string& /*sessionId*/) {
    if (!connected_)
        return false;
    return false;
}

NidsClient::ReportResult NidsClient::generateReport(const std::string& /*sessionId*/,
                                                      const std::string& /*outputPath*/) {
    if (!connected_)
        return {};
    return {};
}

} // namespace nids::client
