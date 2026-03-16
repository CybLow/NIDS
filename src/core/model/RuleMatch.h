#pragma once

#include <string>

namespace nids::core {

/// Describes a single heuristic rule match.
struct RuleMatch {
    std::string ruleName;    ///< Machine-readable rule ID (e.g., "suspicious_port")
    std::string description; ///< Human-readable explanation
    float severity = 0.0f;  ///< Severity score [0.0, 1.0]
};

} // namespace nids::core
