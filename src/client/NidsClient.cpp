#include "client/NidsClient.h"

#include <iostream>

namespace nids::client {

NidsClient::NidsClient(const ClientConfig& config)
    : config_(config) {}

NidsClient::~NidsClient() {
    disconnect();
}

bool NidsClient::connect() {
    std::cout << "Connecting to NIDS server at " << config_.serverAddress << std::endl;
    std::cout << "NOTE: gRPC integration pending. Add grpc dependency to complete." << std::endl;

    // auto channel = grpc::CreateChannel(config_.serverAddress,
    //                                     grpc::InsecureChannelCredentials());
    // stub_ = nids::NidsService::NewStub(channel);
    // connected_ = true;

    return false;
}

void NidsClient::disconnect() {
    connected_ = false;
    // stub_.reset();
}

std::vector<std::string> NidsClient::listInterfaces() {
    if (!connected_) return {};
    // Implement using stub_->ListInterfaces()
    return {};
}

std::string NidsClient::startCapture(const std::string& /*interface*/,
                                      const CaptureFilter& /*filter*/) {
    if (!connected_) return "";
    // Implement using stub_->StartCapture()
    return "";
}

bool NidsClient::stopCapture(const std::string& /*sessionId*/) {
    if (!connected_) return false;
    // Implement using stub_->StopCapture()
    return false;
}

void NidsClient::streamPackets(const std::string& /*sessionId*/,
                                PacketCallback /*callback*/) {
    if (!connected_) return;
    // Implement using stub_->StreamPackets() with server-streaming
}

bool NidsClient::analyzeCapture(const std::string& /*sessionId*/,
                                 const std::string& /*modelPath*/) {
    if (!connected_) return false;
    // Implement using stub_->AnalyzeCapture()
    return false;
}

NidsClient::ReportResult NidsClient::generateReport(const std::string& /*sessionId*/,
                                                      const std::string& /*outputPath*/) {
    if (!connected_) return {};
    // Implement using stub_->GenerateReport()
    return {};
}

} // namespace nids::client
