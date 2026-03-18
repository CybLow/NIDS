#pragma once

/// SignatureMatch — result of a Snort rule match against a packet payload.
///
/// Returned by ISignatureEngine::inspect() when a signature matches.
/// Includes rule metadata (SID, revision, classtype, priority) and
/// references (CVE, bugtraq, URL).

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace nids::core {

struct SignatureMatch {
    std::uint32_t sid = 0;       ///< Snort ID (unique rule identifier)
    std::uint32_t rev = 0;       ///< Rule revision
    std::string msg;             ///< Alert message
    std::string classtype;       ///< Classification (e.g., "web-application-attack")
    int priority = 3;            ///< Priority (1=highest, 4=lowest)
    float severity = 0.0f;       ///< Normalized severity (0.0-1.0)

    /// External reference (CVE, bugtraq, URL).
    struct Reference {
        std::string type;   ///< "cve", "bugtraq", "url"
        std::string value;  ///< "2024-1234", "http://..."
    };
    std::vector<Reference> references;

    /// Metadata key-value pairs.
    std::vector<std::pair<std::string, std::string>> metadata;
};

} // namespace nids::core
