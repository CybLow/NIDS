#pragma once

// Native C++ flow feature extractor to replace CICFlowMeter (Java).
//
// This implements the CIC flow feature extraction algorithm directly in C++,
// eliminating the dependency on the Java-based CICFlowMeter tool.
//
// Features computed per flow (79 features matching CIC-IDS2017 dataset):
// - Flow duration, total/fwd/bwd packets, total/fwd/bwd bytes
// - Packet length stats (min, max, mean, std) per direction
// - Inter-arrival time stats per direction
// - Flow flags (PSH, URG, FIN, SYN, RST, ACK counts)
// - Header length, packet/byte rate
// - Subflow metrics, active/idle time stats
//
// Implementation status: SCAFFOLD (not yet implemented)
// The interface is ready; implement compute logic based on CICFlowMeter's
// Java source: https://github.com/ahlashkari/CICFlowMeter

#include "core/services/IFlowExtractor.h"

#include <string>
#include <vector>
#include <map>
#include <cstdint>

namespace nids::infra {

struct FlowKey {
    std::string srcIp;
    std::string dstIp;
    std::uint16_t srcPort;
    std::uint16_t dstPort;
    std::uint8_t protocol;

    bool operator<(const FlowKey& other) const;
};

struct FlowStats {
    std::int64_t startTimeUs = 0;
    std::int64_t lastTimeUs = 0;
    std::uint64_t totalFwdPackets = 0;
    std::uint64_t totalBwdPackets = 0;
    std::uint64_t totalFwdBytes = 0;
    std::uint64_t totalBwdBytes = 0;
    std::vector<std::uint32_t> fwdPacketLengths;
    std::vector<std::uint32_t> bwdPacketLengths;
    std::vector<std::int64_t> fwdIatUs;
    std::vector<std::int64_t> bwdIatUs;
    std::uint32_t fwdPshFlags = 0;
    std::uint32_t bwdPshFlags = 0;
    std::uint32_t fwdUrgFlags = 0;
    std::uint32_t bwdUrgFlags = 0;
    std::uint32_t finCount = 0;
    std::uint32_t synCount = 0;
    std::uint32_t rstCount = 0;
    std::uint32_t ackCount = 0;

    [[nodiscard]] std::vector<float> toFeatureVector() const;
};

class NativeFlowExtractor : public nids::core::IFlowExtractor {
public:
    [[nodiscard]] bool extractFlows(const std::string& pcapPath,
                                    const std::string& outputCsvPath) override;

    [[nodiscard]] std::vector<std::vector<float>> loadFeatures(
        const std::string& csvPath) override;

private:
    std::map<FlowKey, FlowStats> flows_;

    void processPacket(const std::uint8_t* data, std::uint32_t len,
                       std::int64_t timestampUs);
    void writeCsv(const std::string& outputPath) const;
};

} // namespace nids::infra
