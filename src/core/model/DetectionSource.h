#pragma once

#include <cstdint>
#include <string_view>

namespace nids::core {

/// Identifies which detection layer drove the final verdict.
enum class DetectionSource : std::uint8_t {
    MlOnly,          ///< ML classifier alone (high confidence, no TI/rule match)
    ThreatIntel,     ///< Threat intelligence match overrode or confirmed ML
    HeuristicRule,   ///< Heuristic rule fired
    ContentScan,     ///< YARA content scan match (Phase 14)
    SignatureMatch,  ///< Snort signature match (Phase 15)
    MlPlusThreatIntel,   ///< ML + TI corroboration
    MlPlusHeuristic,     ///< ML + heuristic corroboration
    Ensemble,        ///< Multiple layers contributed
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
        case ContentScan:      return "Content Scan (YARA)";
        case SignatureMatch:   return "Signature Match (Snort)";
        case MlPlusThreatIntel: return "ML + Threat Intel";
        case MlPlusHeuristic:  return "ML + Heuristic";
        case Ensemble:         return "Ensemble";
        case None:             return "None";
    }
    return "Unknown";
}

/**
 * Reverse lookup: convert a display string to a DetectionSource.
 * Returns None if the string does not match any known source.
 */
[[nodiscard]] inline DetectionSource
detectionSourceFromString(std::string_view name) noexcept {
    using enum DetectionSource;
    if (name == "ML Classifier") return MlOnly;
    if (name == "Threat Intelligence") return ThreatIntel;
    if (name == "Heuristic Rule") return HeuristicRule;
    if (name == "Content Scan (YARA)") return ContentScan;
    if (name == "Signature Match (Snort)") return SignatureMatch;
    if (name == "ML + Threat Intel") return MlPlusThreatIntel;
    if (name == "ML + Heuristic") return MlPlusHeuristic;
    if (name == "Ensemble") return Ensemble;
    return None;
}

} // namespace nids::core
