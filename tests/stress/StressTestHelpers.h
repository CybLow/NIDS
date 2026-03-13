#pragma once

/**
 * Shared helpers for NIDS stress / performance tests.
 *
 * Provides pcap file generation utilities, timing helpers, memory measurement,
 * and mock implementations tuned for high-throughput stress scenarios.
 */

#include "infra/flow/NativeFlowExtractor.h"
#include "core/model/PacketInfo.h"
#include "core/model/AttackType.h"
#include "core/model/PredictionResult.h"
#include "core/services/IPacketAnalyzer.h"
#include "core/services/IFeatureNormalizer.h"
#include "core/services/IThreatIntelligence.h"
#include "core/services/IRuleEngine.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

namespace nids::test {

// ── Timing helper ────────────────────────────────────────────────────

/** RAII timer that records elapsed wall-clock time in milliseconds. */
class ScopedTimer {
public:
    explicit ScopedTimer(double& outMs)
        : out_(outMs), start_(std::chrono::steady_clock::now()) {}
    ~ScopedTimer() {
        auto end = std::chrono::steady_clock::now();
        out_ = std::chrono::duration<double, std::milli>(end - start_).count();
    }

    ScopedTimer(const ScopedTimer&) = delete;
    ScopedTimer& operator=(const ScopedTimer&) = delete;

private:
    double& out_;
    std::chrono::steady_clock::time_point start_;
};

// ── Memory tracking (Linux-only via /proc/self/status) ──────────────

/** Read current VmRSS (resident set size) in kilobytes from /proc. Returns 0 on failure. */
inline std::size_t currentRssKb() {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.compare(0, 6, "VmRSS:") == 0) {
            std::size_t kb = 0;
            // Format: "VmRSS:    12345 kB"
            auto pos = line.find_first_of("0123456789");
            if (pos != std::string::npos) {
                kb = std::stoull(line.substr(pos));
            }
            return kb;
        }
    }
    return 0;
}

// ── Pcap file generator ─────────────────────────────────────────────

/**
 * Generate a pcap file containing `packetCount` synthetic TCP packets spread
 * across `flowCount` distinct 5-tuple flows.
 *
 * Each packet is a minimal Ethernet(14) + IPv4(20) + TCP(20) + optional payload.
 * Source IPs rotate through 10.0.{flowId/256}.{flowId%256}, dest is always 10.1.0.1.
 * Source port is 40000 + flowId, dest port is 80.
 * Timestamps increment by `iatUs` microseconds between packets.
 *
 * @param outPath      Path to write the pcap file.
 * @param packetCount  Total number of packets to generate.
 * @param flowCount    Number of distinct flows (packets round-robin across flows).
 * @param payloadSize  Optional payload size per packet (default 0).
 * @param iatUs        Inter-arrival time in microseconds (default 1000 = 1ms).
 */
inline void generatePcap(const std::string& outPath,
                          std::uint32_t packetCount,
                          std::uint32_t flowCount,
                          std::uint32_t payloadSize = 0,
                          std::int64_t iatUs = 1000) {
    std::ofstream ofs(outPath, std::ios::binary);

    // Pcap global header (24 bytes): magic, v2.4, snaplen=65535, linktype=ETHERNET
    const std::uint8_t globalHeader[] = {
        0xd4, 0xc3, 0xb2, 0xa1,  // magic (little-endian)
        0x02, 0x00, 0x04, 0x00,  // version 2.4
        0x00, 0x00, 0x00, 0x00,  // thiszone
        0x00, 0x00, 0x00, 0x00,  // sigfigs
        0xff, 0xff, 0x00, 0x00,  // snaplen 65535
        0x01, 0x00, 0x00, 0x00,  // linktype: Ethernet
    };
    ofs.write(reinterpret_cast<const char*>(globalHeader), sizeof(globalHeader));

    // Packet template: Ethernet(14) + IPv4(20) + TCP(20) + payload
    const std::uint32_t pktLen = 14 + 20 + 20 + payloadSize;
    std::vector<std::uint8_t> pkt(pktLen, 0);

    // Ethernet header
    pkt[12] = 0x08;  // EtherType = IPv4
    pkt[13] = 0x00;

    // IPv4 header
    pkt[14] = 0x45;  // version=4, IHL=5
    auto ipTotalLen = static_cast<std::uint16_t>(20 + 20 + payloadSize);
    pkt[16] = static_cast<std::uint8_t>(ipTotalLen >> 8);
    pkt[17] = static_cast<std::uint8_t>(ipTotalLen & 0xff);
    pkt[20] = 0x40;  // Don't Fragment
    pkt[22] = 64;    // TTL
    pkt[23] = 6;     // Protocol = TCP

    // Destination IP: 10.1.0.1
    pkt[30] = 10; pkt[31] = 1; pkt[32] = 0; pkt[33] = 1;

    // TCP header: data offset = 5 (20 bytes), SYN+ACK flags
    pkt[46] = 0x50;  // data offset = 5 words
    pkt[47] = 0x12;  // SYN + ACK
    pkt[48] = 0x20;  // window = 8192
    pkt[49] = 0x00;

    // Destination port: 80 (0x0050) at byte offset 36-37
    pkt[36] = 0x00;
    pkt[37] = 0x50;

    // Fill payload with pattern if requested
    for (std::uint32_t i = 0; i < payloadSize; ++i) {
        pkt[54 + i] = static_cast<std::uint8_t>(i & 0xff);
    }

    std::int64_t timestampUs = 0;

    for (std::uint32_t i = 0; i < packetCount; ++i) {
        std::uint32_t flowId = i % flowCount;

        // Source IP: 10.0.{flowId/256}.{flowId%256}
        pkt[26] = 10;
        pkt[27] = 0;
        pkt[28] = static_cast<std::uint8_t>((flowId >> 8) & 0xff);
        pkt[29] = static_cast<std::uint8_t>(flowId & 0xff);

        // Source port: 40000 + flowId (big-endian)
        auto srcPort = static_cast<std::uint16_t>(40000 + flowId);
        pkt[34] = static_cast<std::uint8_t>(srcPort >> 8);
        pkt[35] = static_cast<std::uint8_t>(srcPort & 0xff);

        // Pcap packet header (16 bytes): ts_sec, ts_usec, caplen, len
        auto tsSec = static_cast<std::uint32_t>(timestampUs / 1'000'000);
        auto tsUsec = static_cast<std::uint32_t>(timestampUs % 1'000'000);
        std::uint8_t pktHeader[16];
        std::memcpy(pktHeader + 0, &tsSec, 4);
        std::memcpy(pktHeader + 4, &tsUsec, 4);
        std::memcpy(pktHeader + 8, &pktLen, 4);
        std::memcpy(pktHeader + 12, &pktLen, 4);
        ofs.write(reinterpret_cast<const char*>(pktHeader), 16);
        ofs.write(reinterpret_cast<const char*>(pkt.data()), static_cast<std::streamsize>(pktLen));

        timestampUs += iatUs;
    }
}

// ── Mock analyzer for stress tests (no ONNX dependency) ─────────────

/** Lightweight mock analyzer that returns deterministic results without ONNX Runtime. */
class StubAnalyzer : public core::IPacketAnalyzer {
public:
    [[nodiscard]] bool loadModel(const std::string& /*modelPath*/) override {
        return true;
    }

    [[nodiscard]] core::AttackType predict(const std::vector<float>& features) override {
        // Deterministic: if first feature (dst port) > 1024, classify as benign
        if (!features.empty() && features[0] <= 1024.0f) {
            return core::AttackType::SynFlood;
        }
        return core::AttackType::Benign;
    }

    [[nodiscard]] core::PredictionResult predictWithConfidence(
        const std::vector<float>& features) override {
        core::PredictionResult result;
        result.classification = predict(features);
        result.confidence = 0.85f;
        if (result.classification != core::AttackType::Benign
            && result.classification != core::AttackType::Unknown) {
            auto idx = static_cast<std::size_t>(result.classification);
            if (idx < result.probabilities.size()) {
                result.probabilities[idx] = 0.85f;
            }
        } else {
            result.probabilities[0] = 0.85f;  // Benign index
        }
        return result;
    }
};

/** Stub normalizer that returns features unchanged. */
class StubNormalizer : public core::IFeatureNormalizer {
public:
    [[nodiscard]] bool loadMetadata(const std::string& /*metadataPath*/) override {
        return true;
    }
    [[nodiscard]] std::vector<float> normalize(
        const std::vector<float>& features) const override {
        return features;
    }
    [[nodiscard]] bool isLoaded() const noexcept override { return true; }
    [[nodiscard]] std::size_t featureCount() const noexcept override {
        return static_cast<std::size_t>(infra::kFlowFeatureCount);
    }
};

/** Stub TI provider that matches a configurable set of IPs. */
class StubThreatIntel : public core::IThreatIntelligence {
public:
    explicit StubThreatIntel(std::vector<std::string> blacklist = {})
        : blacklist_(std::move(blacklist)) {}

    [[nodiscard]] std::size_t loadFeeds(const std::string& /*dir*/) override {
        return blacklist_.size();
    }
    [[nodiscard]] core::ThreatIntelLookup lookup(std::string_view ip) const override {
        bool found = std::ranges::any_of(blacklist_,
            [ip](const auto& entry) { return entry == ip; });
        return found ? core::ThreatIntelLookup{true, "test_feed"}
                     : core::ThreatIntelLookup{false, ""};
    }
    [[nodiscard]] core::ThreatIntelLookup lookup(std::uint32_t /*ip*/) const override {
        return {false, ""};
    }
    [[nodiscard]] std::size_t entryCount() const noexcept override { return blacklist_.size(); }
    [[nodiscard]] std::size_t feedCount() const noexcept override { return 1; }
    [[nodiscard]] std::vector<std::string> feedNames() const override { return {"test_feed"}; }

private:
    std::vector<std::string> blacklist_;
};

/** Stub rule engine that fires on high packet rates. */
class StubRuleEngine : public core::IRuleEngine {
public:
    [[nodiscard]] std::vector<core::HeuristicRuleResult> evaluate(
        const core::FlowMetadata& flow) const override {
        std::vector<core::HeuristicRuleResult> results;
        if (flow.fwdPacketsPerSecond > 10000.0) {
            results.push_back({"high_rate", "High packet rate", 0.8f});
        }
        return results;
    }
    [[nodiscard]] std::vector<core::HeuristicRuleResult> evaluatePortScan(
        std::string_view /*srcIp*/,
        const std::vector<std::uint16_t>& ports) const override {
        std::vector<core::HeuristicRuleResult> results;
        if (ports.size() > 100) {
            results.push_back({"port_scan", "Port scan detected", 0.9f});
        }
        return results;
    }
    [[nodiscard]] std::size_t ruleCount() const noexcept override { return 2; }
};

} // namespace nids::test
