#pragma once

/// ContentMatch — result of a YARA (or other content scanner) rule match.
///
/// Returned by IContentScanner::scan() when a rule matches the scanned data.
/// Includes rule metadata, individual string match locations, and severity.

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace nids::core {

struct ContentMatch {
    std::string ruleName;       ///< YARA rule identifier
    std::string ruleNamespace;  ///< YARA namespace (e.g., "malware", "c2")
    std::string description;    ///< Rule description from meta
    float severity = 0.0f;      ///< Severity from meta (0.0-1.0)

    /// Individual string matches within the rule.
    struct StringMatch {
        std::string identifier; ///< String identifier (e.g., "$beacon")
        std::size_t offset = 0; ///< Byte offset in the scanned data
        std::size_t length = 0; ///< Length of the match
    };
    std::vector<StringMatch> strings;

    /// Rule metadata key-value pairs.
    std::vector<std::pair<std::string, std::string>> metadata;
};

} // namespace nids::core
