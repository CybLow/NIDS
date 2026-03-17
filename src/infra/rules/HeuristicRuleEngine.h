#pragma once

/// Heuristic rule engine for flow-level anomaly detection.
///
/// Evaluates flows against a set of predefined rules based on connection
/// metadata: suspicious ports, protocol anomalies, flood indicators, and
/// brute force patterns. No packet payload inspection.
///
/// Rules are hardcoded (not loaded from files) to keep the implementation
/// simple and auditable. Each rule has a name, description, and severity.

#include "core/services/IRuleEngine.h"

#include <optional>

namespace nids::infra {

/** Heuristic rule engine that evaluates flows against predefined anomaly rules. */
class HeuristicRuleEngine : public core::IRuleEngine {
public:
    HeuristicRuleEngine() = default;

    [[nodiscard]] std::vector<core::RuleMatch> evaluate(
        const core::FlowInfo& flow) const override;

    [[nodiscard]] std::vector<core::RuleMatch> evaluatePortScan(
        std::string_view srcIp,
        const std::vector<std::uint16_t>& distinctDstPorts) const override;

    [[nodiscard]] std::size_t ruleCount() const noexcept override;

private:
    // Individual rule evaluators -- each returns a result if the rule fires,
    // or std::nullopt if it doesn't.

    [[nodiscard]] static std::optional<core::RuleMatch>
    checkSuspiciousPort(const core::FlowInfo& flow);

    [[nodiscard]] static std::optional<core::RuleMatch>
    checkSynFlood(const core::FlowInfo& flow);

    [[nodiscard]] static std::optional<core::RuleMatch>
    checkIcmpFlood(const core::FlowInfo& flow);

    [[nodiscard]] static std::optional<core::RuleMatch>
    checkBruteForce(const core::FlowInfo& flow);

    [[nodiscard]] static std::optional<core::RuleMatch>
    checkHighPacketRate(const core::FlowInfo& flow);

    [[nodiscard]] static std::optional<core::RuleMatch>
    checkResetFlood(const core::FlowInfo& flow);

    /// Total number of single-flow rules.
    static constexpr std::size_t kSingleFlowRuleCount = 6;
    /// Plus the port scan rule (multi-flow).
    static constexpr std::size_t kTotalRuleCount = 7;
};

} // namespace nids::infra
