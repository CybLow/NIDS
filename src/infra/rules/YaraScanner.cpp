#include "infra/rules/YaraScanner.h"

#include <spdlog/spdlog.h>
#include <yara.h>

#include <algorithm>
#include <filesystem>
#include <ranges>
#include <string>
#include <utility>

namespace nids::infra {

namespace fs = std::filesystem;

// ── YaraGlobalInit (Meyers singleton) ───────────────────────────────

YaraScanner::YaraGlobalInit::YaraGlobalInit() {
    const int rc = yr_initialize();
    if (rc != ERROR_SUCCESS) {
        spdlog::critical("yr_initialize() failed with code {}", rc);
    } else {
        spdlog::debug("YaraScanner: libyara initialized");
    }
}

YaraScanner::YaraGlobalInit::~YaraGlobalInit() {
    yr_finalize();
}

YaraScanner::YaraGlobalInit& YaraScanner::globalInit() {
    static YaraGlobalInit init;
    return init;
}

// ── RulesDeleter ────────────────────────────────────────────────────

void YaraScanner::RulesDeleter::operator()(YR_RULES* rules) const noexcept {
    if (rules) yr_rules_destroy(rules);
}

// ── Construction / Destruction ──────────────────────────────────────

YaraScanner::YaraScanner() {
    globalInit(); // Ensure libyara is initialized.
}

YaraScanner::~YaraScanner() = default;

YaraScanner::YaraScanner(YaraScanner&& other) noexcept
    : rulePaths_(std::move(other.rulePaths_)),
      rules_(std::move(other.rules_)),
      ruleCount_(other.ruleCount_) {
    other.ruleCount_ = 0;
}

YaraScanner& YaraScanner::operator=(YaraScanner&& other) noexcept {
    if (this != &other) {
        std::scoped_lock lock{mutex_, other.mutex_};
        rulePaths_ = std::move(other.rulePaths_);
        rules_ = std::move(other.rules_);
        ruleCount_ = other.ruleCount_;
        other.ruleCount_ = 0;
    }
    return *this;
}

// ── loadRules() ─────────────────────────────────────────────────────

bool YaraScanner::loadRules(const fs::path& path) {
    std::scoped_lock lock{mutex_};

    if (fs::is_directory(path)) {
        std::error_code ec;
        for (const auto& entry :
             fs::recursive_directory_iterator(path, ec)) {
            if (entry.is_regular_file()) {
                const auto ext = entry.path().extension().string();
                if (ext == ".yar" || ext == ".yara") {
                    rulePaths_.push_back(entry.path());
                }
            }
        }
    } else if (fs::is_regular_file(path)) {
        rulePaths_.push_back(path);
    } else {
        spdlog::error("YaraScanner: path '{}' is neither file nor directory",
                      path.string());
        return false;
    }

    return compileRules();
}

// ── reloadRules() ───────────────────────────────────────────────────

bool YaraScanner::reloadRules() {
    std::scoped_lock lock{mutex_};
    return compileRules();
}

// ── compileRules() ──────────────────────────────────────────────────

bool YaraScanner::compileRules() {
    if (rulePaths_.empty()) {
        spdlog::warn("YaraScanner: no rule files to compile");
        rules_.reset();
        ruleCount_ = 0;
        return true; // Empty is valid.
    }

    YR_COMPILER* compiler = nullptr;
    int rc = yr_compiler_create(&compiler);
    if (rc != ERROR_SUCCESS || !compiler) {
        spdlog::error("YaraScanner: yr_compiler_create() failed: {}", rc);
        return false;
    }

    // Compile each rule file.
    int totalErrors = 0;
    for (const auto& rulePath : rulePaths_) {
        FILE* fp = std::fopen(rulePath.string().c_str(), "r");
        if (!fp) {
            spdlog::warn("YaraScanner: cannot open '{}'",
                         rulePath.string());
            ++totalErrors;
            continue;
        }
        const int errors = yr_compiler_add_file(
            compiler, fp, nullptr, rulePath.string().c_str());
        std::fclose(fp);

        if (errors > 0) {
            spdlog::warn("YaraScanner: {} errors compiling '{}'",
                         errors, rulePath.string());
            totalErrors += errors;
        }
    }

    // Get compiled rules.
    YR_RULES* rawRules = nullptr;
    rc = yr_compiler_get_rules(compiler, &rawRules);
    yr_compiler_destroy(compiler);

    if (rc != ERROR_SUCCESS || !rawRules) {
        spdlog::error("YaraScanner: yr_compiler_get_rules() failed: {}", rc);
        return false;
    }

    rules_.reset(rawRules);

    // Count rules.
    ruleCount_ = 0;
    YR_RULE* rule = nullptr;
    yr_rules_foreach(rules_.get(), rule) {
        ++ruleCount_;
    }

    spdlog::info("YaraScanner: compiled {} rules from {} files "
                 "({} compilation errors)",
                 ruleCount_, rulePaths_.size(), totalErrors);
    return totalErrors == 0;
}

// ── scan() ──────────────────────────────────────────────────────────

namespace {

/// Callback data passed through libyara's void* userData.
struct ScanContext {
    std::vector<core::ContentMatch>* results;
};

/// libyara scan callback — called for each matching rule.
int yaraCallbackFn(YR_SCAN_CONTEXT* context,
                   int message,
                   void* messageData,
                   void* userData) {
    if (message != CALLBACK_MSG_RULE_MATCHING) {
        return CALLBACK_CONTINUE;
    }

    auto* ctx = static_cast<ScanContext*>(userData);
    auto* rule = static_cast<YR_RULE*>(messageData);

    core::ContentMatch match;
    match.ruleName = rule->identifier;
    if (rule->ns && rule->ns->name) {
        match.ruleNamespace = rule->ns->name;
    }

    // Extract metadata.
    YR_META* meta = nullptr;
    yr_rule_metas_foreach(rule, meta) {
        if (meta->type == META_TYPE_STRING && meta->string) {
            match.metadata.emplace_back(meta->identifier, meta->string);
            if (std::string_view{meta->identifier} == "description") {
                match.description = meta->string;
            }
            if (std::string_view{meta->identifier} == "severity") {
                try {
                    match.severity = std::stof(meta->string);
                } catch (...) {
                    // Ignore malformed severity values.
                }
            }
        }
    }

    // Extract string matches.
    YR_STRING* str = nullptr;
    yr_rule_strings_foreach(rule, str) {
        YR_MATCH* m = nullptr;
        yr_string_matches_foreach(context, str, m) {
            core::ContentMatch::StringMatch sm;
            sm.identifier = str->identifier;
            sm.offset = static_cast<std::size_t>(m->offset);
            sm.length = static_cast<std::size_t>(m->match_length);
            match.strings.push_back(std::move(sm));
        }
    }

    ctx->results->push_back(std::move(match));
    return CALLBACK_CONTINUE;
}

} // anonymous namespace

std::vector<core::ContentMatch> YaraScanner::scan(
    std::span<const std::uint8_t> data) {
    return scan(data, 0);
}

std::vector<core::ContentMatch> YaraScanner::scan(
    std::span<const std::uint8_t> data, int timeoutMs) {

    std::vector<core::ContentMatch> results;
    if (!rules_ || data.empty()) return results;

    ScanContext ctx{&results};

    // yr_rules_scan_mem is thread-safe per YR_RULES instance.
    const int rc = yr_rules_scan_mem(
        rules_.get(),
        data.data(),
        data.size(),
        0, // flags
        yaraCallbackFn,
        &ctx,
        timeoutMs);

    if (rc != ERROR_SUCCESS && rc != ERROR_SCAN_TIMEOUT) {
        spdlog::warn("YaraScanner: scan failed with code {}", rc);
    }

    return results;
}

// ── ruleCount() / fileCount() ───────────────────────────────────────

std::size_t YaraScanner::ruleCount() const noexcept {
    return ruleCount_;
}

std::size_t YaraScanner::fileCount() const noexcept {
    return rulePaths_.size();
}

} // namespace nids::infra
