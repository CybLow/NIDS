#pragma once

#include <string>

namespace nids::core {

/// Describes a single threat intelligence match.
struct ThreatIntelMatch {
    std::string ip;          ///< The IP address that matched
    std::string feedName;    ///< Which feed it was found in (e.g., "feodo", "spamhaus")
    bool isSource = false;   ///< True if source IP matched, false if destination
};

} // namespace nids::core
