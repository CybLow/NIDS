#pragma once

/// Shared test fixture helpers for constructing FlowInfo and DetectionResult.
/// Eliminates the 8+ duplicated makeFlow/makeResult functions across tests.

#include "core/model/AttackType.h"
#include "core/model/DetectionResult.h"
#include "core/model/DetectionSource.h"
#include "core/model/FlowInfo.h"
#include "core/model/PredictionResult.h"

#include <cstdint>
#include <string>

namespace nids::testing {

/// Construct a FlowInfo with a 5-tuple.
[[nodiscard]] inline core::FlowInfo makeFlow(
    const std::string& srcIp, const std::string& dstIp,
    std::uint16_t srcPort, std::uint16_t dstPort,
    std::uint8_t protocol = 6) {
    core::FlowInfo f;
    f.srcIp = srcIp;
    f.dstIp = dstIp;
    f.srcPort = srcPort;
    f.dstPort = dstPort;
    f.protocol = protocol;
    f.totalFwdPackets = 10;
    f.totalBwdPackets = 5;
    f.flowDurationUs = 1000000.0;
    f.avgPacketSize = 256.0;
    return f;
}

/// Construct a DetectionResult with ML + hybrid fields.
[[nodiscard]] inline core::DetectionResult makeResult(
    core::AttackType type, float confidence, float combinedScore,
    core::DetectionSource source = core::DetectionSource::MlOnly) {
    core::DetectionResult r;
    r.mlResult.classification = type;
    r.mlResult.confidence = confidence;
    r.finalVerdict = type;
    r.combinedScore = combinedScore;
    r.detectionSource = source;
    return r;
}

} // namespace nids::testing
