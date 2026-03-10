#include "infra/threat/ThreatIntelProvider.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

namespace nids::infra {

std::size_t ThreatIntelProvider::loadFeeds(const std::string& feedDirectory) {
    if (!fs::exists(feedDirectory) || !fs::is_directory(feedDirectory)) {
        spdlog::warn("Threat intel feed directory '{}' does not exist or is not a directory",
                     feedDirectory);
        return 0;
    }

    std::size_t totalLoaded = 0;

    for (const auto& entry : fs::directory_iterator(feedDirectory)) {
        if (!entry.is_regular_file()) {
            continue;
        }

        const auto& path = entry.path();
        auto ext = path.extension().string();

        // Accept .txt, .csv, and extensionless files
        if (!ext.empty() && ext != ".txt" && ext != ".csv") {
            continue;
        }

        auto feedName = path.stem().string();
        auto loaded = loadFeedFile(path.string(), feedName);
        if (loaded > 0) {
            totalLoaded += loaded;
            ++feedCount_;
            spdlog::info("Loaded {} entries from threat feed '{}'", loaded, feedName);
        }
    }

    // Sort CIDR ranges by network address for efficient lookup
    std::ranges::sort(cidrRanges_, [](const CidrRange& a, const CidrRange& b) {
        return a.network < b.network;
    });

    spdlog::info("Threat intelligence loaded: {} total entries from {} feeds",
                 totalLoaded, feedCount_);
    return totalLoaded;
}

std::size_t ThreatIntelProvider::loadFeedFile(const std::string& filePath,
                                              const std::string& feedName) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        spdlog::warn("Failed to open threat feed file: {}", filePath);
        return 0;
    }

    std::size_t count = 0;
    std::string line;

    while (std::getline(file, line)) {
        // Strip leading/trailing whitespace
        auto start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) {
            continue;  // blank line
        }
        auto end = line.find_last_not_of(" \t\r\n");
        line = line.substr(start, end - start + 1);

        // Skip comments (lines starting with # or ;)
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }

        // Some feeds have IP;port or IP,description format -- extract just the IP/CIDR
        auto semicolonPos = line.find(';');
        if (semicolonPos != std::string::npos) {
            line = line.substr(0, semicolonPos);
        }
        auto commaPos = line.find(',');
        if (commaPos != std::string::npos) {
            line = line.substr(0, commaPos);
        }
        auto spacePos = line.find(' ');
        if (spacePos != std::string::npos) {
            line = line.substr(0, spacePos);
        }

        // Strip again after truncation
        end = line.find_last_not_of(" \t\r\n");
        if (end == std::string::npos) {
            continue;
        }
        line = line.substr(0, end + 1);

        // Check if it's a CIDR range
        if (line.find('/') != std::string::npos) {
            std::uint32_t network = 0;
            std::uint32_t mask = 0;
            if (parseCidr(line, network, mask)) {
                cidrRanges_.push_back({network, mask, feedName});
                ++count;
            }
        } else {
            // Individual IP
            auto ip = parseIpv4(line);
            if (ip != 0) {
                ipEntries_[ip] = feedName;
                ++count;
            }
        }
    }

    return count;
}

nids::core::ThreatIntelLookup ThreatIntelProvider::lookup(std::string_view ip) const {
    auto ipNum = parseIpv4(ip);
    if (ipNum == 0) {
        return {};
    }
    return lookup(ipNum);
}

nids::core::ThreatIntelLookup ThreatIntelProvider::lookup(std::uint32_t ip) const {
    // Check individual IPs first (O(1))
    auto it = ipEntries_.find(ip);
    if (it != ipEntries_.end()) {
        return {true, it->second};
    }

    // Check CIDR ranges (O(N) scan -- acceptable for typical feed sizes <1000 ranges)
    return lookupCidr(ip);
}

nids::core::ThreatIntelLookup ThreatIntelProvider::lookupCidr(std::uint32_t ip) const {
    for (const auto& range : cidrRanges_) {
        if ((ip & range.mask) == range.network) {
            return {true, range.feedName};
        }
    }
    return {};
}

std::size_t ThreatIntelProvider::entryCount() const noexcept {
    return ipEntries_.size() + cidrRanges_.size();
}

std::size_t ThreatIntelProvider::feedCount() const noexcept {
    return feedCount_;
}

std::uint32_t ThreatIntelProvider::parseIpv4(std::string_view ip) noexcept {
    std::uint32_t result = 0;
    int octets = 0;

    auto remaining = ip;
    while (!remaining.empty() && octets < 4) {
        std::uint32_t octet = 0;
        auto [ptr, ec] = std::from_chars(remaining.data(),
                                          remaining.data() + remaining.size(),
                                          octet);
        if (ec != std::errc{} || octet > 255) {
            return 0;
        }

        result = (result << 8) | octet;
        ++octets;

        auto consumed = static_cast<std::size_t>(ptr - remaining.data());
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
                                     std::uint32_t& network,
                                     std::uint32_t& mask) noexcept {
    auto slashPos = cidr.find('/');
    if (slashPos == std::string_view::npos || slashPos == 0) {
        return false;
    }

    auto ipPart = cidr.substr(0, slashPos);
    auto prefixPart = cidr.substr(slashPos + 1);

    auto ip = parseIpv4(ipPart);
    if (ip == 0 && ipPart != "0.0.0.0") {
        return false;
    }

    std::uint32_t prefix = 0;
    auto [ptr, ec] = std::from_chars(prefixPart.data(),
                                      prefixPart.data() + prefixPart.size(),
                                      prefix);
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
