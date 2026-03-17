#include "infra/threat/ThreatIntelProvider.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <ranges>
#include <string>

namespace fs = std::filesystem;

namespace nids::infra {

namespace {

/// Strip leading and trailing whitespace in-place. Returns false if the line is
/// blank.
bool stripWhitespace(std::string &line) {
  auto start = line.find_first_not_of(" \t\r\n");
  if (start == std::string::npos)
    return false;
  if (auto end = line.find_last_not_of(" \t\r\n");
      start > 0 || end < line.size() - 1) {
    line = line.substr(start, end - start + 1);
  }
  return true;
}

/// Extract the IP/CIDR portion from a feed line that may contain
/// delimiters like ';', ',' or spaces (e.g., "IP;port", "IP,description").
void extractIpField(std::string &line) {
  if (auto pos = line.find(';'); pos != std::string::npos) {
    line.resize(pos);
  }
  if (auto pos = line.find(','); pos != std::string::npos) {
    line.resize(pos);
  }
  if (auto pos = line.find(' '); pos != std::string::npos) {
    line.resize(pos);
  }
  // Strip trailing whitespace after truncation
  auto end = line.find_last_not_of(" \t\r\n");
  if (end == std::string::npos) {
    line.clear();
  } else {
    line.resize(end + 1);
  }
}

} // anonymous namespace

std::size_t ThreatIntelProvider::loadFeeds(const fs::path &feedDirectory) {
  if (!fs::exists(feedDirectory) || !fs::is_directory(feedDirectory)) {
    spdlog::warn(
        "Threat intel feed directory '{}' does not exist or is not a directory",
        feedDirectory.string());
    return 0;
  }

  std::size_t totalLoaded = 0;

  for (const auto &entry : fs::directory_iterator(feedDirectory)) {
    if (!entry.is_regular_file()) {
      continue;
    }

    const auto &path = entry.path();
    // Accept .txt, .csv, and extensionless files
    if (auto ext = path.extension().string();
        !ext.empty() && ext != ".txt" && ext != ".csv") {
      continue;
    }

    if (auto feedName = path.stem().string();
        auto loaded = loadFeedFile(path.string(), feedName)) {
      totalLoaded += loaded;
      ++feedCount_;
      feedNames_.push_back(feedName);
      spdlog::info("Loaded {} entries from threat feed '{}'", loaded, feedName);
    }
  }

  // Sort CIDR ranges by network address for efficient lookup
  std::ranges::sort(cidrRanges_, [](const CidrRange &a, const CidrRange &b) {
    return a.network < b.network;
  });

  spdlog::info("Threat intelligence loaded: {} total entries from {} feeds",
               totalLoaded, feedCount_);
  return totalLoaded;
}

std::size_t
ThreatIntelProvider::parseAndStoreEntry(const std::string &entry,
                                        const std::string &feedName) {
  // CIDR range (contains '/')
  if (entry.contains('/')) {
    std::uint32_t network = 0;
    if (std::uint32_t mask = 0; parseCidr(entry, network, mask)) {
      cidrRanges_.emplace_back(network, mask, feedName);
      return 1;
    }
    return 0;
  }

  // Individual IP
  if (auto ip = parseIpv4(entry); ip != 0) {
    ipEntries_[ip] = feedName;
    return 1;
  }
  return 0;
}

std::size_t ThreatIntelProvider::loadFeedFile(const std::string &filePath,
                                              const std::string &feedName) {
  std::ifstream file(filePath);
  if (!file.is_open()) {
    spdlog::warn("Failed to open threat feed file: {}", filePath);
    return 0;
  }

  std::size_t count = 0;
  std::string line;

  while (std::getline(file, line)) {
    if (!stripWhitespace(line))
      continue;

    // Skip comments (lines starting with # or ;)
    if (line[0] == '#' || line[0] == ';')
      continue;

    extractIpField(line);
    if (line.empty())
      continue;

    count += parseAndStoreEntry(line, feedName);
  }

  return count;
}

core::ThreatIntelLookup ThreatIntelProvider::lookup(std::string_view ip) const {
  auto ipNum = parseIpv4(ip);
  if (ipNum == 0) {
    return {};
  }
  return lookup(ipNum);
}

core::ThreatIntelLookup ThreatIntelProvider::lookup(std::uint32_t ip) const {
  // Check individual IPs first (O(1))
  if (auto it = ipEntries_.find(ip); it != ipEntries_.end()) {
    return {true, it->second};
  }

  // Check CIDR ranges (O(N) scan -- acceptable for typical feed sizes <1000
  // ranges)
  return lookupCidr(ip);
}

core::ThreatIntelLookup
ThreatIntelProvider::lookupCidr(std::uint32_t ip) const {
  if (const auto it = std::ranges::find_if(cidrRanges_,
                                           [ip](const CidrRange &range) {
                                             return (ip & range.mask) ==
                                                    range.network;
                                           });
      it != cidrRanges_.end()) {
    return {true, it->feedName};
  }
  return {};
}

std::size_t ThreatIntelProvider::entryCount() const noexcept {
  return ipEntries_.size() + cidrRanges_.size();
}

std::size_t ThreatIntelProvider::feedCount() const noexcept {
  return feedCount_;
}

std::vector<std::string> ThreatIntelProvider::feedNames() const {
  return feedNames_;
}

std::uint32_t ThreatIntelProvider::parseIpv4(std::string_view ip) noexcept {
  std::uint32_t result = 0;
  int octets = 0;

  auto remaining = ip;
  while (!remaining.empty() && octets < 4) {
    std::uint32_t octet = 0;
    auto [ptr, ec] = std::from_chars(
        remaining.data(), remaining.data() + remaining.size(), octet);
    if (ec != std::errc{} || octet > 255) {
      return 0;
    }

    result = (result << 8) | octet;
    ++octets;

    const auto consumed = static_cast<std::size_t>(ptr - remaining.data());
    remaining = remaining.substr(consumed);

    if (!remaining.empty() && remaining[0] == '.') {
      remaining = remaining.substr(1);
    }
  }

  if (octets != 4 || !remaining.empty()) {
    return 0;
  }

  return result;
}

bool ThreatIntelProvider::parseCidr(std::string_view cidr,
                                    std::uint32_t &network,
                                    std::uint32_t &mask) noexcept {
  auto slashPos = cidr.find('/');
  if (slashPos == std::string_view::npos || slashPos == 0) {
    return false;
  }

  const auto ipPart = cidr.substr(0, slashPos);
  const auto prefixPart = cidr.substr(slashPos + 1);

  const auto ip = parseIpv4(ipPart);
  if (ip == 0 && ipPart != "0.0.0.0") {
    return false;
  }

  std::uint32_t prefix = 0;
  auto [ptr, ec] = std::from_chars(
      prefixPart.data(), prefixPart.data() + prefixPart.size(), prefix);
  if (ec != std::errc{} || prefix > 32) {
    return false;
  }

  // A prefix of 0 means "all IPs" -- likely a mistake in the feed, skip it
  if (prefix == 0) {
    return false;
  }

  mask = prefix == 32 ? 0xFFFFFFFF : ~((1u << (32 - prefix)) - 1);
  network = ip & mask;

  return true;
}

} // namespace nids::infra
