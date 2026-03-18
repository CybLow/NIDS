#pragma once

/// YaraScanner — RAII wrapper around libyara for content/pattern scanning.
///
/// Compiles YARA rules from files/directories and scans memory buffers
/// (packet payloads, reassembled TCP streams) for matches. Thread-safe
/// scanning (compilation requires exclusive access via mutex).

#include "core/services/IContentScanner.h"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <span>
#include <vector>

struct YR_RULES;

namespace nids::infra {

class YaraScanner final : public core::IContentScanner {
public:
    YaraScanner();
    ~YaraScanner() override;

    YaraScanner(const YaraScanner&) = delete;
    YaraScanner& operator=(const YaraScanner&) = delete;
    YaraScanner(YaraScanner&&) noexcept;
    YaraScanner& operator=(YaraScanner&&) noexcept;

    [[nodiscard]] bool loadRules(
        const std::filesystem::path& path) override;

    [[nodiscard]] bool reloadRules() override;

    [[nodiscard]] std::vector<core::ContentMatch> scan(
        std::span<const std::uint8_t> data) override;

    /// Scan with a timeout (milliseconds). 0 = no timeout.
    [[nodiscard]] std::vector<core::ContentMatch> scan(
        std::span<const std::uint8_t> data,
        int timeoutMs);

    [[nodiscard]] std::size_t ruleCount() const noexcept override;
    [[nodiscard]] std::size_t fileCount() const noexcept override;

private:
    /// RAII wrapper for yr_initialize() / yr_finalize().
    struct YaraGlobalInit {
        YaraGlobalInit();
        ~YaraGlobalInit();
        YaraGlobalInit(const YaraGlobalInit&) = delete;
        YaraGlobalInit& operator=(const YaraGlobalInit&) = delete;
    };
    static YaraGlobalInit& globalInit();

    /// Compile rules from all collected paths.
    [[nodiscard]] bool compileRules();

    /// Custom deleter for YR_RULES.
    struct RulesDeleter {
        void operator()(YR_RULES* rules) const noexcept;
    };

    std::vector<std::filesystem::path> rulePaths_;
    std::unique_ptr<YR_RULES, RulesDeleter> rules_;
    std::size_t ruleCount_ = 0;
    mutable std::mutex mutex_;
};

} // namespace nids::infra
