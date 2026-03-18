#pragma once

/// IContentScanner — interface for content/pattern scanning engines.
///
/// Abstracts YARA (or other pattern-matching engines) behind a clean
/// interface. Scans packet payloads and reassembled TCP streams for
/// malware signatures, exploit patterns, and protocol anomalies.

#include "core/model/ContentMatch.h"

#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

namespace nids::core {

class IContentScanner {
public:
    virtual ~IContentScanner() = default;

    /// Load rules from a file or directory.
    [[nodiscard]] virtual bool loadRules(
        const std::filesystem::path& path) = 0;

    /// Reload all previously loaded rules (hot reload).
    [[nodiscard]] virtual bool reloadRules() = 0;

    /// Scan a buffer (packet payload or reassembled stream).
    [[nodiscard]] virtual std::vector<ContentMatch> scan(
        std::span<const std::uint8_t> data) = 0;

    /// Number of loaded rules.
    [[nodiscard]] virtual std::size_t ruleCount() const noexcept = 0;

    /// Number of loaded rule files.
    [[nodiscard]] virtual std::size_t fileCount() const noexcept = 0;
};

} // namespace nids::core
