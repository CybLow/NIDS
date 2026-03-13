#pragma once

/// gRPC Client stub for connecting to the NIDS headless daemon.
///
/// This client can be used by:
///   1. A CLI tool for scripted capture/analysis sessions
///   2. The Qt GUI application (as an alternative to local PcapCapture)
///   3. Other services that need NIDS functionality remotely
///
/// Implementation steps (Phase 9 — see docs/roadmap.md):
///   1. Generate C++ stubs from proto/nids.proto
///   2. Implement the methods below using the generated stub
///   3. Create a CLI main() that uses this client

#include "core/model/PacketInfo.h"
#include "core/model/AttackType.h"

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace nids::client {

/** Configuration for connecting to a NIDS gRPC server. */
struct ClientConfig {
    /** Server address and port (e.g. "localhost:50051"). */
    std::string serverAddress = "localhost:50051";
    /** RPC timeout in milliseconds. */
    int timeoutMs = 30000;
};

/** gRPC client for connecting to a NIDS headless daemon. */
class NidsClient {
public:
    /** Construct with the given client configuration. */
    explicit NidsClient(const ClientConfig& config);
    /** Disconnect and release resources. */
    ~NidsClient();

    /** Establish a connection to the server. Returns false on failure. */
    [[nodiscard]] bool connect();
    /** Disconnect from the server. */
    void disconnect();

    /** Query available network interfaces on the server. */
    [[nodiscard]] std::vector<std::string> listInterfaces();

    /** BPF filter parameters for a capture session. */
    struct CaptureFilter {
        /** Protocol filter (e.g. "tcp", "udp"). */
        std::string protocol;
        /** Source IP address filter. */
        std::string sourceIp;
        /** Destination IP address filter. */
        std::string destinationIp;
        /** Source port filter. */
        std::string sourcePort;
        /** Destination port filter. */
        std::string destinationPort;
        /** Raw BPF filter expression (overrides other fields if set). */
        std::string customBpf;
    };

    /**
     * Start a capture session on the server.
     * @param interface  Network interface to capture on.
     * @param filter     Capture filter parameters.
     * @return Session ID for the new capture, or empty string on failure.
     */
    [[nodiscard]] std::string startCapture(const std::string& interface,
                                            const CaptureFilter& filter);
    /** Stop a running capture session. Returns false on failure. */
    [[nodiscard]] bool stopCapture(const std::string& sessionId);

    /** Callback type for receiving streamed packets. */
    using PacketCallback = std::function<void(const nids::core::PacketInfo&)>;
    /** Stream captured packets from the server, invoking the callback for each. */
    void streamPackets(const std::string& sessionId, PacketCallback callback);

    /** Trigger ML analysis on a completed capture session. */
    [[nodiscard]] bool analyzeCapture(const std::string& sessionId);

    /** Result of a report generation request. */
    struct ReportResult {
        /** Whether the report was generated successfully. */
        bool success = false;
        /** Path to the generated report on the server. */
        std::string filePath;
        /** Time taken to generate the report, in milliseconds. */
        std::int64_t generationTimeMs = 0;
    };
    /**
     * Generate an analysis report for a completed session.
     * @param sessionId   The capture session to report on.
     * @param outputPath  Desired output file path.
     */
    [[nodiscard]] ReportResult generateReport(const std::string& sessionId,
                                               const std::string& outputPath);

private:
    ClientConfig config_;
    bool connected_ = false;
};

} // namespace nids::client
