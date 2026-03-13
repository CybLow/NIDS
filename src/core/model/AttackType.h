#pragma once

#include <string_view>
#include <cstdint>
#include <array>

namespace nids::core {

/**
 * Attack types corresponding to the LSNM2024 dataset classes.
 *
 * The 15 attack types + Benign are ordered to match the model's output
 * index mapping. Unknown is used for out-of-range or unclassifiable results.
 *
 * Reference: Q. Abu Al-Haija et al., "Revolutionizing Threat Hunting in
 * Communication Networks", ICICS 2024.
 */
enum class AttackType : std::uint8_t {
    Benign = 0,              /**< Normal, non-malicious traffic. */
    MitmArpSpoofing,         /**< Man-in-the-middle via ARP spoofing. */
    SshBruteForce,           /**< SSH credential brute-force attack. */
    FtpBruteForce,           /**< FTP credential brute-force attack. */
    DdosIcmp,                /**< Distributed denial-of-service using ICMP. */
    DdosRawIp,               /**< Distributed denial-of-service using raw IP packets. */
    DdosUdp,                 /**< Distributed denial-of-service using UDP flood. */
    Dos,                     /**< Denial-of-service (single source). */
    ExploitingFtp,           /**< FTP service exploitation. */
    Fuzzing,                 /**< Protocol fuzzing attack. */
    IcmpFlood,               /**< ICMP flood attack. */
    SynFlood,                /**< TCP SYN flood attack. */
    PortScanning,            /**< Network port scanning / reconnaissance. */
    RemoteCodeExecution,     /**< Remote code execution exploit. */
    SqlInjection,            /**< SQL injection attack. */
    Xss,                     /**< Cross-site scripting attack. */
    Unknown                  /**< Unclassifiable or out-of-range result. */
};

/// Total number of model output classes (excluding Unknown).
inline constexpr int kAttackTypeCount = 16;

/// Total number of AttackType enum values (including Unknown).
inline constexpr int kAttackTypeTotal = 17;

/// Lookup table mapping each AttackType to its display string.
inline constexpr std::array<std::string_view, kAttackTypeTotal> kAttackTypeNames = {{
    "Benign",                 // 0
    "MITM ARP Spoofing",     // 1
    "SSH Brute Force",       // 2
    "FTP Brute Force",       // 3
    "DDoS ICMP",             // 4
    "DDoS Raw IP",           // 5
    "DDoS UDP",              // 6
    "DoS",                   // 7
    "Exploiting FTP",        // 8
    "Fuzzing",               // 9
    "ICMP Flood",            // 10
    "SYN Flood",             // 11
    "Port Scanning",         // 12
    "Remote Code Execution", // 13
    "SQL Injection",         // 14
    "XSS",                   // 15
    "Unknown",               // 16
}};

/**
 * Convert an AttackType enum value to its human-readable display string.
 * @param type The attack type to convert.
 * @return Display name, or "Unknown" for out-of-range values.
 */
[[nodiscard]] constexpr std::string_view attackTypeToString(AttackType type) noexcept {
    if (auto idx = static_cast<std::size_t>(type); idx < kAttackTypeNames.size())
        return kAttackTypeNames[idx];
    return "Unknown";
}

/**
 * Convert a model output index (0..15) to an AttackType.
 * Returns Unknown for out-of-range indices.
 */
[[nodiscard]] constexpr AttackType attackTypeFromIndex(int index) noexcept {
    if (index >= 0 && index < kAttackTypeCount) {
        return static_cast<AttackType>(index);
    }
    return AttackType::Unknown;
}

} // namespace nids::core
