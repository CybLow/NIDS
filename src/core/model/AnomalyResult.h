#pragma once

/// AnomalyResult — statistical anomalies detected against a traffic baseline.
///
/// StatisticalBaseline computes "normal" traffic patterns from historical
/// flows, then compares current traffic to flag deviations.

#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace nids::core {

/// Summarised traffic metrics over a time window.
struct BaselineMetrics {
    double avgFlowsPerMinute = 0.0;
    double avgBytesPerMinute = 0.0;
    double avgPacketsPerMinute = 0.0;
    std::unordered_map<std::uint16_t, double> portFrequency;
    std::unordered_map<std::string, double> ipFrequency;
    double avgFlowDurationUs = 0.0;
    std::chrono::system_clock::time_point computedAt;
    int64_t windowUs = 0; ///< Time window used for computation
};

/// Classification of a traffic anomaly.
enum class AnomalyType : std::uint8_t {
    TrafficVolumeSpike,
    NewDestinationPort,
    NewExternalIp,
    UnusualProtocol,
    FlowDurationAnomaly,
    ByteRatioAnomaly,
};

/// A single detected anomaly.
struct AnomalyResult {
    std::string description;
    double deviationSigma = 0.0; ///< Standard deviations from baseline
    double baselineValue = 0.0;
    double observedValue = 0.0;
    AnomalyType type = AnomalyType::TrafficVolumeSpike;
};

} // namespace nids::core
