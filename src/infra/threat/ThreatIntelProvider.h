#pragma once

/// Threat intelligence provider that loads plain-text IP blocklists.
///
/// Supports two entry formats:
/// - Individual IPv4 addresses: "192.168.1.1"
/// - CIDR ranges: "192.168.1.0/24"
///
/// Feed files are plain text, one entry per line, '#' comments, blank lines ignored.
/// The file's basename (without extension) becomes the feed name.
///
/// Performance:
/// - Individual IPs: O(1) lookup via unordered_map
/// - CIDR ranges: O(log N) via sorted vector + binary search
/// - Typical load time: <100ms for combined feeds (~50K entries)

#include "core/services/IThreatIntelligence.h"

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace nids::infra {

/** Threat intelligence provider backed by plain-text IP blocklist feeds. */
class ThreatIntelProvider : public core::IThreatIntelligence {
public:
    ThreatIntelProvider() = default;

    [[nodiscard]] std::size_t loadFeeds(const std::string& feedDirectory) override;
    [[nodiscard]] core::ThreatIntelLookup lookup(std::string_view ip) const override;
    [[nodiscard]] core::ThreatIntelLookup lookup(std::uint32_t ip) const override;
    [[nodiscard]] std::size_t entryCount() const noexcept override;
    [[nodiscard]] std::size_t feedCount() const noexcept override;
    [[nodiscard]] std::vector<std::string> feedNames() const override;

    /// Load a single feed file. Returns the number of entries loaded.
    [[nodiscard]] std::size_t loadFeedFile(const std::string& filePath,
                                           const std::string& feedName);

private:
    /// A CIDR range: network address + prefix length.
    struct CidrRange {
        std::uint32_t network = 0;  ///< Network address (host byte order)
        std::uint32_t mask = 0;     ///< Bitmask derived from prefix length
        std::string feedName;
    };

    /// Parse a dotted-decimal IPv4 string to a 32-bit host-byte-order integer.
    /// Returns 0 on failure (0.0.0.0 is not a meaningful blocklist entry).
    [[nodiscard]] static std::uint32_t parseIpv4(std::string_view ip) noexcept;

    /// Parse a CIDR notation string (e.g., "192.168.1.0/24").
    /// Returns true on success, populating network and mask.
    [[nodiscard]] static bool parseCidr(std::string_view cidr,
                                        std::uint32_t& network,
                                        std::uint32_t& mask) noexcept;

    /// Check if an IP matches any loaded CIDR range.
    [[nodiscard]] core::ThreatIntelLookup lookupCidr(std::uint32_t ip) const;

    /// Parse a single feed entry (IP or CIDR) and store it. Returns 1 on success, 0 on failure.
    std::size_t parseAndStoreEntry(const std::string& entry, const std::string& feedName);

    /// Individual IPs mapped to their feed name.
    std::unordered_map<std::uint32_t, std::string> ipEntries_;

    /// CIDR ranges, sorted by network address for binary search.
    std::vector<CidrRange> cidrRanges_;

    /// Number of distinct feeds loaded.
    std::size_t feedCount_ = 0;

    /// Names of all loaded feeds, in load order.
    std::vector<std::string> feedNames_;
};

} // namespace nids::infra
