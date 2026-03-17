#pragma once

#include <cstdint>
#include <string_view>

namespace nids::core {

/// Identifies which detection layer drove the final verdict.
enum class DetectionSource : std::uint8_t {
    MlOnly,          ///< ML classifier alone (high confidence, no TI/rule match)
    ThreatIntel,     ///< Threat intelligence match overrode or confirmed ML
    HeuristicRule,   ///< Heuristic rule fired
    MlPlusThreatIntel,   ///< ML + TI corroboration
    MlPlusHeuristic,     ///< ML + heuristic corroboration
    Ensemble,        ///< All three layers contributed
    None             ///< No detection (benign, no flags)
};

/**
 * Convert a DetectionSource to its human-readable display string.
 * @param source The detection source to convert.
 * @return Display name of the detection source.
 */
[[nodiscard]] constexpr std::string_view detectionSourceToString(
    DetectionSource source) noexcept {
    using enum DetectionSource;
    switch (source) {
        case MlOnly:           return "ML Classifier";
        case ThreatIntel:      return "Threat Intelligence";
        case HeuristicRule:     return "Heuristic Rule";
        case MlPlusThreatIntel: return "ML + Threat Intel";
        case MlPlusHeuristic:  return "ML + Heuristic";
        case Ensemble:         return "Ensemble (ML + TI + Rules)";
        case None:             return "None";
    }
    return "Unknown";
}

} // namespace nids::core
