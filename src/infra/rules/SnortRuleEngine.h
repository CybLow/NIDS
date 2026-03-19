#pragma once

/// SnortRuleEngine — Snort 3.x-compatible signature rule engine.
///
/// Orchestrates rule parsing, content matching, variable resolution,
/// and detection. Implements ISignatureEngine for clean integration
/// with the hybrid detection pipeline.

#include "core/services/ISignatureEngine.h"
#include "infra/rules/RuleVariableStore.h"
#include "infra/rules/SnortRuleParser.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace nids::infra {

class SnortRuleEngine final : public core::ISignatureEngine {
public:
    SnortRuleEngine();
    ~SnortRuleEngine() override = default;

    SnortRuleEngine(const SnortRuleEngine&) = delete;
    SnortRuleEngine& operator=(const SnortRuleEngine&) = delete;

    [[nodiscard]] bool loadRules(
        const std::filesystem::path& path) override;

    [[nodiscard]] bool reloadRules() override;

    [[nodiscard]] std::vector<core::SignatureMatch> inspect(
        std::span<const std::uint8_t> payload,
        const core::FlowInfo& flow) override;

    [[nodiscard]] std::size_t ruleCount() const noexcept override;
    [[nodiscard]] std::size_t fileCount() const noexcept override;

    void setVariable(std::string_view name,
                     std::string_view value) override;

private:
    /// Pre-filter rules by protocol and port.
    [[nodiscard]] std::vector<std::size_t> preFilter(
        const core::FlowInfo& flow) const;

    /// Evaluate a single rule against payload + flow.
    [[nodiscard]] bool evaluateRule(
        const core::SnortRule& rule,
        std::span<const std::uint8_t> payload,
        const core::FlowInfo& flow) const;

    /// Check content patterns against payload.
    [[nodiscard]] bool checkContents(
        const core::SnortRule& rule,
        std::span<const std::uint8_t> payload) const;

    /// Check a single content option.
    [[nodiscard]] bool matchContent(
        const core::SnortRule::ContentOption& opt,
        std::span<const std::uint8_t> payload,
        std::size_t& cursor) const;

    /// Convert a matched rule to a SignatureMatch result.
    [[nodiscard]] core::SignatureMatch toSignatureMatch(
        const core::SnortRule& rule) const;

    /// Compute severity from priority (1=1.0, 2=0.75, 3=0.5, 4=0.25).
    [[nodiscard]] static float severityFromPriority(int priority) noexcept;

    /// Build the port-group index for fast pre-filtering.
    void buildIndex();

    SnortRuleParser parser_;
    RuleVariableStore variables_;
    std::vector<core::SnortRule> rules_;
    std::vector<std::filesystem::path> loadedPaths_;

    /// Port-group index: protocol -> dst_port -> rule indices
    std::unordered_map<std::uint8_t,
        std::unordered_map<std::uint16_t,
            std::vector<std::size_t>>> portGroupIndex_;
    /// Rules matching "any" port
    std::unordered_map<std::uint8_t,
        std::vector<std::size_t>> anyPortRules_;

    mutable std::mutex mutex_;
};

} // namespace nids::infra
