#include "client/NidsClient.h"

#include <spdlog/spdlog.h>

#include <chrono>
#include <sstream>

namespace nids::client {

NidsClient::NidsClient(const ClientConfig& config) : config_(config) {}

NidsClient::~NidsClient() { disconnect(); }

bool NidsClient::connect() {
    channel_ = grpc::CreateChannel(config_.serverAddress,
                                   grpc::InsecureChannelCredentials());
    if (!channel_) {
        spdlog::error("Failed to create gRPC channel to {}",
                      config_.serverAddress);
        return false;
    }

    // Wait for channel to become ready (with timeout)
    auto deadline = std::chrono::system_clock::now() +
                    std::chrono::seconds(config_.connectTimeoutSec);
    if (!channel_->WaitForConnected(deadline)) {
        spdlog::error("Timeout connecting to gRPC server at {}",
                      config_.serverAddress);
        return false;
    }

    stub_ = NidsService::NewStub(channel_);
    spdlog::info("Connected to NIDS server at {}", config_.serverAddress);
    return true;
}

void NidsClient::disconnect() {
    stub_.reset();
    channel_.reset();
}

std::vector<std::string> NidsClient::listInterfaces() const {
    if (!stub_) {
        return {};
    }

    grpc::ClientContext context;
    ListInterfacesRequest request;
    ListInterfacesResponse response;

    auto status = stub_->ListInterfaces(&context, request, &response);
    if (!status.ok()) {
        spdlog::error("ListInterfaces RPC failed: {}", status.error_message());
        return {};
    }

    std::vector<std::string> interfaces;
    interfaces.reserve(static_cast<std::size_t>(response.interfaces_size()));
    for (const auto& iface : response.interfaces()) {
        interfaces.push_back(iface);
    }
    return interfaces;
}

std::string NidsClient::startCapture(const std::string& interface,
                                     const std::string& bpfFilter,
                                     const std::string& dumpFile) const {
    if (!stub_) {
        return {};
    }

    grpc::ClientContext context;
    StartCaptureRequest request;
    request.set_interface(interface);
    request.set_enable_live_detection(true);
    if (!bpfFilter.empty()) {
        request.mutable_filter()->set_custom_bpf(bpfFilter);
    }
    if (!dumpFile.empty()) {
        request.set_dump_file(dumpFile);
    }

    StartCaptureResponse response;
    auto status = stub_->StartCapture(&context, request, &response);
    if (!status.ok()) {
        spdlog::error("StartCapture RPC failed: {}", status.error_message());
        return {};
    }

    if (!response.success()) {
        spdlog::error("StartCapture failed: {}", response.message());
        return {};
    }

    spdlog::info("Capture started: {}", response.message());
    return response.session_id();
}

std::string NidsClient::stopCapture(const std::string& sessionId) const {
    if (!stub_) {
        return "Not connected";
    }

    grpc::ClientContext context;
    StopCaptureRequest request;
    request.set_session_id(sessionId);

    StopCaptureResponse response;
    auto status = stub_->StopCapture(&context, request, &response);
    if (!status.ok()) {
        spdlog::error("StopCapture RPC failed: {}", status.error_message());
        return "RPC failed: " + status.error_message();
    }

    std::ostringstream oss;
    oss << "Capture stopped — "
        << response.total_packets() << " packets, "
        << response.total_flows() << " flows, "
        << response.flagged_flows() << " flagged, "
        << response.dropped_flows() << " dropped";
    return oss.str();
}

NidsClient::StatusInfo NidsClient::getStatus() const {
    StatusInfo info;
    if (!stub_) {
        return info;
    }

    grpc::ClientContext context;
    GetStatusRequest request;
    GetStatusResponse response;

    auto status = stub_->GetStatus(&context, request, &response);
    if (!status.ok()) {
        spdlog::error("GetStatus RPC failed: {}", status.error_message());
        return info;
    }

    info.capturing = response.capturing();
    info.currentInterface = response.current_interface();
    info.sessionId = response.session_id();
    info.packetsCaptured = response.packets_captured();
    info.flowsDetected = response.flows_detected();
    info.flowsFlagged = response.flows_flagged();
    info.flowsDropped = response.flows_dropped();
    return info;
}

void NidsClient::streamDetections(
    const std::string& sessionId,
    DetectionFilter filter,
    const DetectionCallback& callback,
    const std::atomic<bool>& stopFlag) const {

    if (!stub_) {
        return;
    }

    grpc::ClientContext context;
    StreamDetectionsRequest request;
    request.set_session_id(sessionId);
    request.set_filter(filter);

    auto reader = stub_->StreamDetections(&context, request);
    DetectionEvent event;

    while (!stopFlag.load() && reader->Read(&event)) {
        callback(event);
    }

    auto status = reader->Finish();
    if (!status.ok() && status.error_code() != grpc::StatusCode::CANCELLED) {
        spdlog::error("StreamDetections ended with error: {}",
                      status.error_message());
    }
}

SearchFlowsResponse NidsClient::searchFlows(
    const SearchFlowsRequest& request) const {
    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() +
                         std::chrono::seconds(config_.rpcTimeoutSec));
    SearchFlowsResponse response;
    auto status = stub_->SearchFlows(&context, request, &response);
    if (!status.ok()) {
        spdlog::error("SearchFlows failed: {}", status.error_message());
    }
    return response;
}

IocSearchResponse NidsClient::iocSearch(
    const IocSearchRequest& request) const {
    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() +
                         std::chrono::seconds(config_.rpcTimeoutSec));
    IocSearchResponse response;
    auto status = stub_->IocSearch(&context, request, &response);
    if (!status.ok()) {
        spdlog::error("IocSearch failed: {}", status.error_message());
    }
    return response;
}

LoadRulesResponse NidsClient::loadRules(const std::string& path) const {
    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() +
                         std::chrono::seconds(config_.rpcTimeoutSec));
    LoadRulesRequest request;
    request.set_path(path);
    LoadRulesResponse response;
    auto status = stub_->LoadRules(&context, request, &response);
    if (!status.ok()) {
        spdlog::error("LoadRules failed: {}", status.error_message());
    }
    return response;
}

GetRuleStatsResponse NidsClient::getRuleStats() const {
    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() +
                         std::chrono::seconds(config_.rpcTimeoutSec));
    GetRuleStatsRequest request;
    GetRuleStatsResponse response;
    auto status = stub_->GetRuleStats(&context, request, &response);
    if (!status.ok()) {
        spdlog::error("GetRuleStats failed: {}", status.error_message());
    }
    return response;
}

NidsClient::HealthInfo NidsClient::healthCheck() const {
    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() +
                         std::chrono::seconds(config_.rpcTimeoutSec));
    HealthCheckRequest request;
    HealthCheckResponse response;

    auto status = stub_->HealthCheck(&context, request, &response);
    if (!status.ok()) {
        return {false, "", 0, 0, 0};
    }

    return {response.healthy(), response.version(),
            response.uptime_seconds(), response.total_flows_processed(),
            response.total_alerts()};
}

} // namespace nids::client
