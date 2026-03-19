#pragma once

/// SnortRuleParser — parses Snort 3.x rule syntax into SnortRule AST.
///
/// Handles rule headers (action, protocol, IPs, ports, direction),
/// content options (text/hex patterns with modifiers), PCRE patterns,
/// flow/flowbits options, threshold, and metadata.

#include "core/model/SnortRule.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace nids::infra {

class SnortRuleParser {
public:
    /// Parse a single rule line.
    [[nodiscard]] std::expected<core::SnortRule, std::string> parse(
        std::string_view ruleText) const;

    /// Parse all rules from a file.
    [[nodiscard]] std::vector<core::SnortRule> parseFile(
        const std::filesystem::path& path) const;

    /// Parse all .rules files in a directory.
    [[nodiscard]] std::vector<core::SnortRule> parseDirectory(
        const std::filesystem::path& dir) const;

    /// Statistics from last parse operation.
    struct ParseStats {
        std::size_t totalLines = 0;
        std::size_t parsedRules = 0;
        std::size_t skippedComments = 0;
        std::size_t parseErrors = 0;
    };
    [[nodiscard]] const ParseStats& lastStats() const noexcept;

private:
    [[nodiscard]] std::expected<void, std::string> parseHeader(
        std::string_view header, core::SnortRule& rule) const;

    [[nodiscard]] std::expected<void, std::string> parseOptions(
        std::string_view options, core::SnortRule& rule) const;

    [[nodiscard]] std::expected<void, std::string> parseOption(
        std::string_view key, std::string_view value,
        core::SnortRule& rule) const;

    [[nodiscard]] core::SnortRule::ContentOption parseContent(
        std::string_view value) const;

    [[nodiscard]] core::SnortRule::PcreOption parsePcre(
        std::string_view value) const;

    [[nodiscard]] core::SnortRule::FlowOption parseFlow(
        std::string_view value) const;

    [[nodiscard]] core::SnortRule::FlowbitsOption parseFlowbits(
        std::string_view value) const;

    [[nodiscard]] core::SnortRule::ThresholdOption parseThreshold(
        std::string_view value) const;

    [[nodiscard]] static std::vector<std::uint8_t> decodePattern(
        std::string_view raw);

    [[nodiscard]] static std::uint8_t protocolFromString(
        std::string_view proto) noexcept;

    mutable ParseStats stats_;
};

} // namespace nids::infra
