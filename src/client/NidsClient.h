#pragma once

// gRPC Client stub for connecting to the NIDS headless daemon.
//
// This client can be used by:
// 1. The Qt GUI application (replacing direct PcapCapture usage)
// 2. A CLI tool for scripted capture sessions
// 3. Other services that need NIDS functionality
//
// Implementation steps:
// 1. Generate C++ sources from proto/nids.proto
// 2. Implement the methods below using the generated stub
// 3. Create a CLI main() that uses this client

#include "core/model/PacketInfo.h"
#include "core/model/AttackType.h"

#include <string>
#include <vector>
#include <functional>

namespace nids::client {

struct ClientConfig {
    std::string serverAddress = "localhost:50051";
    int timeoutMs = 30000;
};

class NidsClient {
public:
    explicit NidsClient(const ClientConfig& config);
    ~NidsClient();

    [[nodiscard]] bool connect();
    void disconnect();

    [[nodiscard]] std::vector<std::string> listInterfaces();

    struct CaptureFilter {
        std::string protocol;
        std::string sourceIp;
        std::string destinationIp;
        std::string sourcePort;
        std::string destinationPort;
        std::string customBpf;
    };

    [[nodiscard]] std::string startCapture(const std::string& interface,
                                            const CaptureFilter& filter);
    [[nodiscard]] bool stopCapture(const std::string& sessionId);

    using PacketCallback = std::function<void(const nids::core::PacketInfo&)>;
    void streamPackets(const std::string& sessionId, PacketCallback callback);

    [[nodiscard]] bool analyzeCapture(const std::string& sessionId,
                                       const std::string& modelPath);

    struct ReportResult {
        bool success = false;
        std::string filePath;
        int64_t generationTimeMs = 0;
    };
    [[nodiscard]] ReportResult generateReport(const std::string& sessionId,
                                               const std::string& outputPath);

private:
    ClientConfig config_;
    bool connected_ = false;
    // std::unique_ptr<nids::NidsService::Stub> stub_;
};

} // namespace nids::client
