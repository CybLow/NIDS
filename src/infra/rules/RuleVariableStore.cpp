#include "infra/rules/RuleVariableStore.h"

#include <charconv>
#include <string>

namespace nids::infra {

void RuleVariableStore::set(std::string_view name, std::string_view value) {
    // Strip leading $ if present.
    if (!name.empty() && name[0] == '$') name.remove_prefix(1);
    vars_[std::string(name)] = std::string(value);
}

std::string RuleVariableStore::resolve(std::string_view ref) const {
    if (ref.empty() || ref[0] != '$') return std::string(ref);

    auto key = std::string(ref.substr(1)); // Strip $
    auto it = vars_.find(key);
    if (it != vars_.end()) return it->second;
    return std::string(ref); // Unresolved — return as-is.
}

bool RuleVariableStore::ipMatches(
    std::string_view ip, std::string_view spec) const {

    auto resolved = resolve(spec);

    // "any" matches everything.
    if (resolved == "any") return true;

    // Negation: !spec
    if (!resolved.empty() && resolved[0] == '!') {
        return !ipMatches(ip, resolved.substr(1));
    }

    // Simple exact match (no CIDR for now — CIDR would require
    // IP parsing + subnet math, deferred to a future enhancement).
    // Handle comma-separated groups: "10.0.0.0/8,192.168.0.0/16"
    std::string_view res = resolved;
    while (!res.empty()) {
        auto comma = res.find(',');
        auto token = res.substr(0, comma);
        // Strip brackets [...]
        if (!token.empty() && token[0] == '[') token.remove_prefix(1);
        if (!token.empty() && token.back() == ']') token.remove_suffix(1);

        if (token == ip) return true;

        if (comma == std::string_view::npos) break;
        res = res.substr(comma + 1);
    }

    return false;
}

bool RuleVariableStore::portMatches(
    std::uint16_t port, std::string_view spec) const {

    auto resolved = resolve(spec);
    if (resolved == "any") return true;

    // Negation
    if (!resolved.empty() && resolved[0] == '!') {
        return !portMatches(port, resolved.substr(1));
    }

    // Comma-separated or bracket groups: "80,443", "[80,443,8080]"
    std::string_view res = resolved;
    // Strip brackets
    if (!res.empty() && res[0] == '[') res.remove_prefix(1);
    if (!res.empty() && res.back() == ']') res.remove_suffix(1);

    while (!res.empty()) {
        auto comma = res.find(',');
        auto token = res.substr(0, comma);

        // Range: "1024:" or ":1024" or "1024:2048"
        auto colon = token.find(':');
        if (colon != std::string_view::npos) {
            auto lo = token.substr(0, colon);
            auto hi = token.substr(colon + 1);
            std::uint16_t loVal = 0;
            std::uint16_t hiVal = 65535;
            if (!lo.empty()) std::from_chars(lo.data(), lo.data() + lo.size(), loVal);
            if (!hi.empty()) std::from_chars(hi.data(), hi.data() + hi.size(), hiVal);
            if (port >= loVal && port <= hiVal) return true;
        } else {
            // Exact port match.
            std::uint16_t val = 0;
            std::from_chars(token.data(), token.data() + token.size(), val);
            if (val == port) return true;
        }

        if (comma == std::string_view::npos) break;
        res = res.substr(comma + 1);
    }

    return false;
}

} // namespace nids::infra
