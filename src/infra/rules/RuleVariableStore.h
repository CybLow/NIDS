#pragma once

/// RuleVariableStore — resolves Snort rule variables ($HOME_NET, etc.).

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

namespace nids::infra {

class RuleVariableStore {
public:
    /// Set a variable value.
    void set(std::string_view name, std::string_view value);

    /// Resolve a variable reference. Returns the value if it's a known
    /// variable (prefixed with $), otherwise returns the input unchanged.
    [[nodiscard]] std::string resolve(std::string_view ref) const;

    /// Check if an IP matches a spec (supports CIDR, groups, negation).
    [[nodiscard]] bool ipMatches(std::string_view ip,
                                  std::string_view spec) const;

    /// Check if a port matches a spec (supports ranges, groups, "any").
    [[nodiscard]] bool portMatches(std::uint16_t port,
                                    std::string_view spec) const;

private:
    std::unordered_map<std::string, std::string> vars_;
};

} // namespace nids::infra
