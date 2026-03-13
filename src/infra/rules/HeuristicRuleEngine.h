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
class HeuristicRuleEngine : public nids::core::IRuleEngine {
public:
    HeuristicRuleEngine() = default;

    [[nodiscard]] std::vector<nids::core::HeuristicRuleResult> evaluate(
        const nids::core::FlowMetadata& flow) const override;

    [[nodiscard]] std::vector<nids::core::HeuristicRuleResult> evaluatePortScan(
        std::string_view srcIp,
        const std::vector<std::uint16_t>& distinctDstPorts) const override;

    [[nodiscard]] std::size_t ruleCount() const noexcept override;

private:
    // Individual rule evaluators -- each returns a result if the rule fires,
    // or std::nullopt if it doesn't.

    [[nodiscard]] static std::optional<nids::core::HeuristicRuleResult>
    checkSuspiciousPort(const nids::core::FlowMetadata& flow);

    [[nodiscard]] static std::optional<nids::core::HeuristicRuleResult>
    checkSynFlood(const nids::core::FlowMetadata& flow);

    [[nodiscard]] static std::optional<nids::core::HeuristicRuleResult>
    checkIcmpFlood(const nids::core::FlowMetadata& flow);

    [[nodiscard]] static std::optional<nids::core::HeuristicRuleResult>
    checkBruteForce(const nids::core::FlowMetadata& flow);

    [[nodiscard]] static std::optional<nids::core::HeuristicRuleResult>
    checkHighPacketRate(const nids::core::FlowMetadata& flow);

    [[nodiscard]] static std::optional<nids::core::HeuristicRuleResult>
    checkResetFlood(const nids::core::FlowMetadata& flow);

    /// Total number of single-flow rules.
    static constexpr std::size_t kSingleFlowRuleCount = 6;
    /// Plus the port scan rule (multi-flow).
    static constexpr std::size_t kTotalRuleCount = 7;
};

} // namespace nids::infra
