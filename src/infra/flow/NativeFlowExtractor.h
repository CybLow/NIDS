#pragma once

// Native C++ flow feature extractor for LSNM2024-compatible flow analysis.
//
// Extracts CICFlowMeter-compatible bidirectional flow features directly from
// pcap files, eliminating the Java dependency. Features are computed per-flow
// and output as named columns matching the CICFlowMeter convention.
//
// The feature set covers:
// - Flow duration, packet counts, byte counts (per direction)
// - Packet length statistics (min, max, mean, std) per direction
// - Inter-arrival time statistics per direction
// - TCP flag counts (FIN, SYN, RST, PSH, ACK, URG, CWR, ECE)
// - Header length, packet/byte rates
// - Bulk transfer metrics
// - Subflow metrics, active/idle time statistics
// - Initial TCP window sizes

#include "core/services/IFlowExtractor.h"

#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <cstdint>

namespace nids::infra {

/// Number of flow features produced by toFeatureVector().
inline constexpr int kFlowFeatureCount = 77;

/// Maximum packets per flow before forced split.  Prevents mega-flows
/// (e.g. DDoS where millions of packets share a single 5-tuple) from
/// collapsing into a single sample.  Must match Python preprocessing.
inline constexpr std::uint64_t kMaxFlowPackets = 200;

/// Returns the ordered list of feature column names matching toFeatureVector() output.
[[nodiscard]] const std::vector<std::string>& flowFeatureNames();

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
    std::vector<std::uint32_t> allPacketLengths;
    std::vector<std::int64_t> flowIatUs;
    std::vector<std::int64_t> fwdIatUs;
    std::vector<std::int64_t> bwdIatUs;
    std::int64_t lastFwdTimeUs = -1;
    std::int64_t lastBwdTimeUs = -1;
    std::uint32_t fwdPshFlags = 0;
    std::uint32_t bwdPshFlags = 0;
    std::uint32_t fwdUrgFlags = 0;
    std::uint32_t bwdUrgFlags = 0;
    std::uint32_t finCount = 0;
    std::uint32_t synCount = 0;
    std::uint32_t rstCount = 0;
    std::uint32_t pshCount = 0;
    std::uint32_t ackCount = 0;
    std::uint32_t urgCount = 0;
    std::uint32_t cwrCount = 0;
    std::uint32_t eceCount = 0;
    std::uint32_t fwdHeaderBytes = 0;
    std::uint32_t bwdHeaderBytes = 0;
    std::uint32_t fwdInitWinBytes = 0;
    std::uint32_t bwdInitWinBytes = 0;
    std::uint32_t actDataPktFwd = 0;
    std::uint32_t minSegSizeForward = 0;
    std::vector<std::int64_t> activePeriodsUs;
    std::vector<std::int64_t> idlePeriodsUs;
    std::int64_t lastActiveTimeUs = -1;
    std::int64_t lastIdleTimeUs = -1;
    std::vector<std::uint32_t> fwdBulkBytes;
    std::vector<std::uint32_t> bwdBulkBytes;
    std::vector<std::uint32_t> fwdBulkPackets;
    std::vector<std::uint32_t> bwdBulkPackets;

    std::uint32_t curFwdBulkPkts = 0;
    std::uint32_t curFwdBulkBytes = 0;
    std::uint32_t curBwdBulkPkts = 0;
    std::uint32_t curBwdBulkBytes = 0;
    bool lastPacketWasFwd = false;

    /// Convert accumulated stats to a flat feature vector of kFlowFeatureCount floats.
    [[nodiscard]] std::vector<float> toFeatureVector(std::uint16_t dstPort) const;
};

class NativeFlowExtractor : public nids::core::IFlowExtractor {
public:
    NativeFlowExtractor();

    void setFlowTimeout(std::int64_t timeoutUs);

    [[nodiscard]] bool extractFlows(const std::string& pcapPath,
                                    const std::string& outputCsvPath) override;

    [[nodiscard]] std::vector<std::vector<float>> loadFeatures(
        const std::string& csvPath) override;

    [[nodiscard]] const std::vector<nids::core::FlowInfo>& flowMetadata() const noexcept override;

private:
    std::map<FlowKey, FlowStats> flows_;
    std::vector<std::pair<FlowKey, FlowStats>> completedFlows_;
    std::vector<nids::core::FlowInfo> flowMetadata_;   ///< Populated by extractFlows()
    std::int64_t flowTimeoutUs_ = 600'000'000;  // 600 seconds default

    void processPacket(const std::uint8_t* data, std::uint32_t len,
                       std::int64_t timestampUs);
    void finalizeBulks();
    void writeCsv(const std::string& outputPath) const;
    void buildFlowMetadata();   ///< Populate flowMetadata_ from completed + active flows
};

} // namespace nids::infra
