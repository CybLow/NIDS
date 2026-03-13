#include "client/NidsClient.h"

#include <spdlog/spdlog.h>

namespace nids::client {

NidsClient::NidsClient(const ClientConfig &config) : config_(config) {}

NidsClient::~NidsClient() { disconnect(); }

bool NidsClient::connect() {
  spdlog::info("Connecting to NIDS server at {}", config_.serverAddress);
  spdlog::warn("gRPC integration pending — see Phase 9 in docs/roadmap.md");
  return false;
}

void NidsClient::disconnect() { connected_ = false; }

std::vector<std::string> NidsClient::listInterfaces() const {
  // TODO: implement via gRPC stub (Phase 9)
  return {};
}

std::string NidsClient::startCapture(const std::string & /*interface*/,
                                     const CaptureFilter & /*filter*/) const {
  // TODO: implement via gRPC stub (Phase 9)
  return "";
}

bool NidsClient::stopCapture(const std::string & /*sessionId*/) const {
  // TODO: implement via gRPC stub (Phase 9)
  return false;
}

void NidsClient::streamPackets(const std::string & /*sessionId*/,
                               const PacketCallback & /*callback*/) const {
  // TODO: implement via gRPC stub (Phase 9)
}

bool NidsClient::analyzeCapture(const std::string & /*sessionId*/) const {
  // TODO: implement via gRPC stub (Phase 9)
  return false;
}

NidsClient::ReportResult
NidsClient::generateReport(const std::string & /*sessionId*/,
                           const std::string & /*outputPath*/) const {
  // TODO: implement via gRPC stub (Phase 9)
  return {};
}

} // namespace nids::client
