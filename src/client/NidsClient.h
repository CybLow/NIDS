#pragma once

/// gRPC Client for connecting to the NIDS headless daemon.
///
/// Provides a typed C++ API around the NidsService gRPC stub.
/// Used by the CLI client (cli_main.cpp) and potentially by
/// a future remote Qt GUI client.

#include "core/model/AttackType.h"

#include <nids.grpc.pb.h>
#include <nids.pb.h>

#include <grpcpp/grpcpp.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace nids::client {

/** Configuration for connecting to a NIDS gRPC server. */
struct ClientConfig {
    /** Server address and port (e.g. "localhost:50051"). */
    std::string serverAddress = "localhost:50051";
    /** Connection timeout in seconds. */
    int connectTimeoutSec = 5;
    /** Per-RPC deadline in seconds. */
    int rpcTimeoutSec = 30;
};

/** gRPC client for connecting to a NIDS headless daemon. */
class NidsClient {
public:
    explicit NidsClient(const ClientConfig& config);
    ~NidsClient();

    NidsClient(const NidsClient&) = delete;
    NidsClient& operator=(const NidsClient&) = delete;
    NidsClient(NidsClient&&) = default;
    NidsClient& operator=(NidsClient&&) = default;

    /** Establish a connection to the server. Returns false on failure. */
    [[nodiscard]] bool connect();

    /** Disconnect from the server. */
    void disconnect();

    /** Query available network interfaces on the server. */
    [[nodiscard]] std::vector<std::string> listInterfaces() const;

    /** Start a capture session on the server.
     *  @return Session ID, or empty string on failure. */
    [[nodiscard]] std::string startCapture(const std::string& interface,
                                           const std::string& bpfFilter = {},
                                           const std::string& dumpFile = {}) const;

    /** Stop the current capture session. Returns summary message. */
    [[nodiscard]] std::string stopCapture(const std::string& sessionId) const;

    /** Get current server status. */
    struct StatusInfo {
        bool capturing = false;
        std::string currentInterface;
        std::string sessionId;
        std::uint64_t packetsCaptured = 0;
        std::uint64_t flowsDetected = 0;
        std::uint64_t flowsFlagged = 0;
        std::uint64_t flowsDropped = 0;
    };
    [[nodiscard]] StatusInfo getStatus() const;

    /** Callback type for streamed detection events. */
    using DetectionCallback = std::function<void(const DetectionEvent&)>;

    /** Stream detection events from the server. Blocks until cancelled or
     *  stream ends. Call from a dedicated thread. */
    void streamDetections(const std::string& sessionId,
                          DetectionFilter filter,
                          const DetectionCallback& callback,
                          const std::atomic<bool>& stopFlag) const;

    /** Search flows in the flow database. */
    [[nodiscard]] SearchFlowsResponse searchFlows(
        const SearchFlowsRequest& request) const;

    /** Search for IOC indicators. */
    [[nodiscard]] IocSearchResponse iocSearch(
        const IocSearchRequest& request) const;

    /** Load signature/YARA rules from a path. */
    [[nodiscard]] LoadRulesResponse loadRules(const std::string& path) const;

    /** Get rule statistics. */
    [[nodiscard]] GetRuleStatsResponse getRuleStats() const;

    /** Health check. */
    struct HealthInfo {
        bool healthy = false;
        std::string version;
        std::uint64_t uptimeSeconds = 0;
        std::uint64_t totalFlows = 0;
        std::uint64_t totalAlerts = 0;
    };
    [[nodiscard]] HealthInfo healthCheck() const;

private:
    ClientConfig config_;
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<NidsService::Stub> stub_;
};

} // namespace nids::client
