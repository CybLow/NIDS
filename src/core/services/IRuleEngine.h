#pragma once

/// Interface for heuristic rule-based detection.
///
/// Evaluates flow metadata against a set of predefined heuristic rules
/// (suspicious ports, scan patterns, brute-force indicators, flood signatures).
/// Rules operate on connection-level metadata only -- NO packet payload inspection.
///
/// Defined in core/ so that app/ layer code can depend on this interface
/// without pulling in infrastructure details (Clean Architecture).

#include "core/services/IFlowExtractor.h"

#include <string>
#include <string_view>
#include <vector>
#include <cstdint>

namespace nids::core {

/// Result of evaluating a single heuristic rule.
struct HeuristicRuleResult {
    std::string ruleName;         ///< Machine-readable ID (e.g., "suspicious_port")
    std::string description;      ///< Human-readable explanation
    float severity = 0.0f;       ///< Severity [0.0, 1.0]
};

/** Abstract interface for heuristic rule-based detection. */
class IRuleEngine {
public:
    virtual ~IRuleEngine() = default;

    /// Evaluate all rules against a single flow's metadata.
    /// Returns a (possibly empty) vector of rule matches.
    [[nodiscard]] virtual std::vector<HeuristicRuleResult> evaluate(
        const FlowInfo& flow) const = 0;

    /// Evaluate port-scan heuristic across multiple flows from the same source.
    /// Takes a source IP and the set of distinct destination ports observed.
    /// Returns a rule match if the port count exceeds the scan threshold.
    [[nodiscard]] virtual std::vector<HeuristicRuleResult> evaluatePortScan(
        std::string_view srcIp,
        const std::vector<std::uint16_t>& distinctDstPorts) const = 0;

    /// Returns the number of active rules.
    [[nodiscard]] virtual std::size_t ruleCount() const noexcept = 0;
};

} // namespace nids::core
