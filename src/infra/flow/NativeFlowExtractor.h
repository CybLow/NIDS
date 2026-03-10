#pragma once

// Native C++ flow feature extractor for LSNM2024-compatible flow analysis.
//
// Extracts 77 bidirectional flow features directly from pcap files.
// Features are computed per-flow and returned as in-memory feature vectors
// (no intermediate CSV).
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
#include <unordered_map>
#include <cstdint>
#include <functional>

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

    bool operator==(const FlowKey& other) const = default;
};

/// Hash functor for FlowKey, combining all five tuple fields.
struct FlowKeyHash {
    std::size_t operator()(const FlowKey& k) const noexcept {
        std::size_t h = std::hash<std::string>{}(k.srcIp);
        h ^= std::hash<std::string>{}(k.dstIp) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<std::uint16_t>{}(k.srcPort) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<std::uint16_t>{}(k.dstPort) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<std::uint8_t>{}(k.protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
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

class NativeFlowExtractor : public core::IFlowExtractor {
public:
    NativeFlowExtractor();

    void setFlowTimeout(std::int64_t timeoutUs);

    [[nodiscard]] std::vector<std::vector<float>> extractFeatures(
        const std::string& pcapPath) override;

    [[nodiscard]] const std::vector<core::FlowInfo>& flowMetadata() const noexcept override;

private:
    std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flows_;
    std::vector<std::pair<FlowKey, FlowStats>> completedFlows_;
    std::vector<core::FlowInfo> flowMetadata_;   ///< Populated by extractFeatures()
    std::int64_t flowTimeoutUs_ = 600'000'000;  // 600 seconds default

    void processPacket(const std::uint8_t* data, std::uint32_t len,
                       std::int64_t timestampUs);
    void finalizeBulks();
    void buildFlowMetadata();   ///< Populate flowMetadata_ from completed + active flows

    /// Build feature vectors from completed + active flows (same order as flowMetadata_).
    [[nodiscard]] std::vector<std::vector<float>> buildFeatureVectors() const;
};

} // namespace nids::infra
