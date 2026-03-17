#pragma once

/// Shared test helpers and utilities.
///
/// Consolidates duplicated helpers found across multiple test files:
///   - SKIP_IF_NO_PCAP() macro
///   - waitFor() polling helper
///   - makePrediction() / makeBenignPrediction()
///   - makeFlowInfo()

#include "core/model/AttackType.h"
#include "core/model/FlowInfo.h"
#include "core/model/PredictionResult.h"

#include <chrono>
#include <string>
#include <thread>

// ── Platform macros ─────────────────────────────────────────────────

/// Skip pcap-dependent tests on Windows CI where npcap is unavailable.
/// PcapPlusPlus uses pcap_open_offline_with_tstamp_precision (npcap-only).
#ifdef _WIN32
#define SKIP_IF_NO_PCAP()                                                      \
    GTEST_SKIP() << "npcap runtime not available on Windows CI"
#else
#define SKIP_IF_NO_PCAP()                                                      \
    do {                                                                        \
    } while (0)
#endif

namespace nids::testing {

// ── Polling helper ──────────────────────────────────────────────────

/// Wait for a predicate to become true, polling every 5ms.
/// Returns true if the predicate was satisfied before the deadline.
template <typename Pred>
bool waitFor(Pred pred,
             std::chrono::milliseconds timeout = std::chrono::milliseconds(2000)) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!pred()) {
        if (std::chrono::steady_clock::now() > deadline)
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return true;
}

// ── Factory helpers ─────────────────────────────────────────────────

/// Build a PredictionResult with the given attack type and confidence.
inline core::PredictionResult makePrediction(core::AttackType type,
                                             float confidence = 0.9f) {
    core::PredictionResult pr;
    pr.classification = type;
    pr.confidence = confidence;
    return pr;
}

/// Build a benign PredictionResult with high confidence.
inline core::PredictionResult makeBenignPrediction(float confidence = 0.95f) {
    return makePrediction(core::AttackType::Benign, confidence);
}

/// Build a FlowInfo with default test values.
inline core::FlowInfo makeFlowInfo(const std::string& srcIp = "10.0.0.1",
                                   const std::string& dstIp = "10.0.0.2",
                                   std::uint16_t srcPort = 12345,
                                   std::uint16_t dstPort = 80,
                                   std::uint8_t protocol = 6) {
    core::FlowInfo info;
    info.srcIp = srcIp;
    info.dstIp = dstIp;
    info.srcPort = srcPort;
    info.dstPort = dstPort;
    info.protocol = protocol;
    return info;
}

} // namespace nids::testing
