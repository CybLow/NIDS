#pragma once

/// ISignatureEngine — interface for signature-based packet inspection.
///
/// Abstracts Snort-compatible rule engines behind a clean interface.
/// Inspects packet payloads against loaded signature rules and returns
/// matching signatures with metadata (SID, severity, references).

#include "core/model/FlowInfo.h"
#include "core/model/SignatureMatch.h"

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace nids::core {

class ISignatureEngine {
public:
    virtual ~ISignatureEngine() = default;

    /// Load rules from a file or directory.
    [[nodiscard]] virtual bool loadRules(
        const std::filesystem::path& path) = 0;

    /// Reload all rules from previously loaded paths.
    [[nodiscard]] virtual bool reloadRules() = 0;

    /// Inspect a packet payload against loaded rules.
    [[nodiscard]] virtual std::vector<SignatureMatch> inspect(
        std::span<const std::uint8_t> payload,
        const FlowInfo& flow) = 0;

    /// Number of loaded rules.
    [[nodiscard]] virtual std::size_t ruleCount() const noexcept = 0;

    /// Number of loaded rule files.
    [[nodiscard]] virtual std::size_t fileCount() const noexcept = 0;

    /// Set a rule variable (e.g., $HOME_NET = "192.168.0.0/16").
    virtual void setVariable(std::string_view name,
                             std::string_view value) = 0;
};

} // namespace nids::core
