#pragma once

/// Interface for heuristic rule-based detection.
///
/// Evaluates flow metadata against a set of predefined heuristic rules
/// (suspicious ports, scan patterns, brute-force indicators, flood signatures).
/// Rules operate on connection-level metadata only -- NO packet payload inspection.
///
/// Defined in core/ so that app/ layer code can depend on this interface
/// without pulling in infrastructure details (Clean Architecture).

#include "core/model/RuleMatch.h"
#include "core/model/FlowInfo.h"

#include <string_view>
#include <vector>
#include <cstdint>

namespace nids::core {

/** Abstract interface for heuristic rule-based detection. */
class IRuleEngine {
public:
    virtual ~IRuleEngine() = default;

    /// Evaluate all rules against a single flow's metadata.
    /// Returns a (possibly empty) vector of rule matches.
    [[nodiscard]] virtual std::vector<RuleMatch> evaluate(
        const FlowInfo& flow) const = 0;

    /// Evaluate port-scan heuristic across multiple flows from the same source.
    /// Takes a source IP and the set of distinct destination ports observed.
    /// Returns a rule match if the port count exceeds the scan threshold.
    [[nodiscard]] virtual std::vector<RuleMatch> evaluatePortScan(
        std::string_view srcIp,
        const std::vector<std::uint16_t>& distinctDstPorts) const = 0;

    /// Returns the number of active rules.
    [[nodiscard]] virtual std::size_t ruleCount() const noexcept = 0;
};

} // namespace nids::core
