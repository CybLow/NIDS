#include "infra/rules/SnortRuleEngine.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <ranges>

namespace nids::infra {

SnortRuleEngine::SnortRuleEngine() {
    // Set default variables.
    variables_.set("HOME_NET", "any");
    variables_.set("EXTERNAL_NET", "any");
    variables_.set("HTTP_PORTS", "80,443,8080,8443");
    variables_.set("SSH_PORTS", "22");
    variables_.set("DNS_PORTS", "53");
}

// ── loadRules() / reloadRules() ─────────────────────────────────────

bool SnortRuleEngine::loadRules(const std::filesystem::path& path) {
    std::scoped_lock lock{mutex_};
    loadedPaths_.push_back(path);

    std::vector<core::SnortRule> newRules;
    if (std::filesystem::is_directory(path)) {
        newRules = parser_.parseDirectory(path);
    } else {
        newRules = parser_.parseFile(path);
    }

    rules_.insert(rules_.end(),
                  std::make_move_iterator(newRules.begin()),
                  std::make_move_iterator(newRules.end()));
    buildIndex();

    spdlog::info("SnortRuleEngine: loaded {} rules from '{}' (total: {})",
                 newRules.size(), path.string(), rules_.size());
    return true;
}

bool SnortRuleEngine::reloadRules() {
    std::scoped_lock lock{mutex_};
    auto paths = loadedPaths_;
    rules_.clear();
    portGroupIndex_.clear();
    anyPortRules_.clear();

    for (const auto& path : paths) {
        std::vector<core::SnortRule> newRules;
        if (std::filesystem::is_directory(path)) {
            newRules = parser_.parseDirectory(path);
        } else {
            newRules = parser_.parseFile(path);
        }
        rules_.insert(rules_.end(),
                      std::make_move_iterator(newRules.begin()),
                      std::make_move_iterator(newRules.end()));
    }
    buildIndex();
    return true;
}

// ── buildIndex() ────────────────────────────────────────────────────

void SnortRuleEngine::buildIndex() {
    portGroupIndex_.clear();
    anyPortRules_.clear();

    for (std::size_t i = 0; i < rules_.size(); ++i) {
        const auto& rule = rules_[i];
        if (!rule.isEnabled) continue;

        auto resolvedPort = variables_.resolve(rule.dstPort);

        if (resolvedPort == "any") {
            anyPortRules_[rule.protocol].push_back(i);
        } else {
            // Parse port spec into individual ports for indexing.
            std::string_view spec = resolvedPort;
            if (!spec.empty() && spec[0] == '[') spec.remove_prefix(1);
            if (!spec.empty() && spec.back() == ']') spec.remove_suffix(1);

            while (!spec.empty()) {
                auto comma = spec.find(',');
                auto token = spec.substr(0, comma);
                std::uint16_t port = 0;
                std::from_chars(token.data(), token.data() + token.size(), port);
                if (port > 0) {
                    portGroupIndex_[rule.protocol][port].push_back(i);
                }
                if (comma == std::string_view::npos) break;
                spec = spec.substr(comma + 1);
            }
        }
    }
}

// ── preFilter() ─────────────────────────────────────────────────────

std::vector<std::size_t> SnortRuleEngine::preFilter(
    const core::FlowInfo& flow) const {

    std::vector<std::size_t> candidates;

    // Add rules matching the exact protocol + dst port.
    auto protoIt = portGroupIndex_.find(flow.protocol);
    if (protoIt != portGroupIndex_.end()) {
        auto portIt = protoIt->second.find(flow.dstPort);
        if (portIt != protoIt->second.end()) {
            candidates.insert(candidates.end(),
                              portIt->second.begin(), portIt->second.end());
        }
    }

    // Add "any" port rules for this protocol.
    auto anyIt = anyPortRules_.find(flow.protocol);
    if (anyIt != anyPortRules_.end()) {
        candidates.insert(candidates.end(),
                          anyIt->second.begin(), anyIt->second.end());
    }

    // Also check protocol 0 (ip = any protocol).
    auto anyProtoPort = portGroupIndex_.find(0);
    if (anyProtoPort != portGroupIndex_.end()) {
        auto portIt = anyProtoPort->second.find(flow.dstPort);
        if (portIt != anyProtoPort->second.end()) {
            candidates.insert(candidates.end(),
                              portIt->second.begin(), portIt->second.end());
        }
    }
    auto anyProtoAny = anyPortRules_.find(0);
    if (anyProtoAny != anyPortRules_.end()) {
        candidates.insert(candidates.end(),
                          anyProtoAny->second.begin(), anyProtoAny->second.end());
    }

    // Deduplicate.
    std::ranges::sort(candidates);
    auto [first, last] = std::ranges::unique(candidates);
    candidates.erase(first, last);

    return candidates;
}

// ── inspect() ───────────────────────────────────────────────────────

std::vector<core::SignatureMatch> SnortRuleEngine::inspect(
    std::span<const std::uint8_t> payload,
    const core::FlowInfo& flow) {

    if (rules_.empty() || payload.empty()) return {};

    std::scoped_lock lock{mutex_};
    auto candidates = preFilter(flow);

    std::vector<core::SignatureMatch> matches;
    for (auto idx : candidates) {
        const auto& rule = rules_[idx];
        if (evaluateRule(rule, payload, flow)) {
            matches.push_back(toSignatureMatch(rule));
        }
    }
    return matches;
}

// ── evaluateRule() ──────────────────────────────────────────────────

bool SnortRuleEngine::evaluateRule(
    const core::SnortRule& rule,
    std::span<const std::uint8_t> payload,
    const core::FlowInfo& flow) const {

    // Check IP matches (simplified — uses variable resolution).
    auto resolvedSrcIp = variables_.resolve(rule.srcIp);
    auto resolvedDstIp = variables_.resolve(rule.dstIp);

    if (!variables_.ipMatches(flow.srcIp, resolvedSrcIp) &&
        !(rule.bidirectional && variables_.ipMatches(flow.dstIp, resolvedSrcIp))) {
        return false;
    }
    if (!variables_.ipMatches(flow.dstIp, resolvedDstIp) &&
        !(rule.bidirectional && variables_.ipMatches(flow.srcIp, resolvedDstIp))) {
        return false;
    }

    // Check content patterns.
    if (!rule.contents.empty() && !checkContents(rule, payload)) {
        return false;
    }

    return true;
}

// ── checkContents() ─────────────────────────────────────────────────

bool SnortRuleEngine::checkContents(
    const core::SnortRule& rule,
    std::span<const std::uint8_t> payload) const {

    std::size_t cursor = 0;
    for (const auto& content : rule.contents) {
        if (!matchContent(content, payload, cursor)) {
            return content.negated; // Negated content: match if NOT found.
        }
        if (content.negated) return false; // Found but negated = no match.
    }
    return true;
}

bool SnortRuleEngine::matchContent(
    const core::SnortRule::ContentOption& opt,
    std::span<const std::uint8_t> payload,
    std::size_t& cursor) const {

    if (opt.pattern.empty()) return true;

    std::size_t searchStart = cursor;
    std::size_t searchEnd = payload.size();

    // Apply position modifiers.
    if (opt.offset) searchStart = static_cast<std::size_t>(*opt.offset);
    if (opt.distance) searchStart = cursor + static_cast<std::size_t>(*opt.distance);
    if (opt.depth) searchEnd = std::min(searchEnd, searchStart + static_cast<std::size_t>(*opt.depth));
    if (opt.within) searchEnd = std::min(searchEnd, cursor + static_cast<std::size_t>(*opt.within));

    if (searchStart >= payload.size() || searchStart >= searchEnd) return false;
    if (searchEnd > payload.size()) searchEnd = payload.size();

    auto haystack = payload.subspan(searchStart, searchEnd - searchStart);
    const auto& needle = opt.pattern;

    if (needle.size() > haystack.size()) return false;

    // Search for the pattern.
    for (std::size_t i = 0; i <= haystack.size() - needle.size(); ++i) {
        bool found = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            auto h = haystack[i + j];
            auto n = needle[j];
            if (opt.nocase) {
                h = static_cast<std::uint8_t>(std::tolower(h));
                n = static_cast<std::uint8_t>(std::tolower(n));
            }
            if (h != n) { found = false; break; }
        }
        if (found) {
            cursor = searchStart + i + needle.size();
            return true;
        }
    }

    return false;
}

// ── Helpers ─────────────────────────────────────────────────────────

core::SignatureMatch SnortRuleEngine::toSignatureMatch(
    const core::SnortRule& rule) const {
    core::SignatureMatch match;
    match.sid = rule.sid;
    match.rev = rule.rev;
    match.msg = rule.msg;
    match.classtype = rule.classtype;
    match.priority = rule.priority;
    match.severity = severityFromPriority(rule.priority);
    match.metadata = rule.metadata;

    for (const auto& [type, value] : rule.references) {
        match.references.push_back({type, value});
    }

    return match;
}

float SnortRuleEngine::severityFromPriority(int priority) noexcept {
    switch (priority) {
        case 1: return 1.0f;
        case 2: return 0.75f;
        case 3: return 0.5f;
        case 4: return 0.25f;
        default: return 0.5f;
    }
}

std::size_t SnortRuleEngine::ruleCount() const noexcept {
    return rules_.size();
}

std::size_t SnortRuleEngine::fileCount() const noexcept {
    return loadedPaths_.size();
}

void SnortRuleEngine::setVariable(std::string_view name,
                                   std::string_view value) {
    variables_.set(name, value);
}

} // namespace nids::infra
