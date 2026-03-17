#pragma once

/// Interface for threat intelligence lookups.
///
/// Abstracts IP reputation checking against external threat feeds. Concrete
/// implementations (ThreatIntelProvider) load blocklists from files and provide
/// O(1) lookups for individual IPs and O(log N) for CIDR range matching.
///
/// Defined in core/ so that app/ layer code can depend on this interface
/// without pulling in infrastructure details (Clean Architecture).

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace nids::core {

/// Result of a threat intelligence lookup for a single IP.
struct ThreatIntelLookup {
  /** True if the IP was found in at least one threat feed. */
  bool matched = false;
  std::string feedName; ///< Name of the feed that matched (empty if no match)
};

/** Abstract interface for threat intelligence IP reputation lookups. */
class IThreatIntelligence {
public:
  virtual ~IThreatIntelligence() = default;

  /// Load threat intelligence data from a directory containing feed files.
  /// Each file is a plain-text blocklist (one IP or CIDR per line, # comments).
  /// The file's basename (without extension) is used as the feed name.
  /// Returns the total number of IPs/ranges loaded across all feeds.
  [[nodiscard]] virtual std::size_t
  loadFeeds(const std::filesystem::path &feedDirectory) = 0;

  /// Check if an IPv4 address (dotted-decimal string) appears in any loaded
  /// feed.
  [[nodiscard]] virtual ThreatIntelLookup lookup(std::string_view ip) const = 0;

  /// Check if an IPv4 address (32-bit host-byte-order integer) appears in any
  /// feed.
  [[nodiscard]] virtual ThreatIntelLookup lookup(std::uint32_t ip) const = 0;

  /// Returns the total number of unique IPs and CIDR ranges loaded.
  [[nodiscard]] virtual std::size_t entryCount() const noexcept = 0;

  /// Returns the number of loaded feeds.
  [[nodiscard]] virtual std::size_t feedCount() const noexcept = 0;

  /// Returns the names of all loaded feeds.
  [[nodiscard]] virtual std::vector<std::string> feedNames() const = 0;
};

} // namespace nids::core
