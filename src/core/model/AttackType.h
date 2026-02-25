#pragma once

#include <string_view>
#include <cstdint>

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
    Benign = 0,
    MitmArpSpoofing,
    SshBruteForce,
    FtpBruteForce,
    DdosIcmp,
    DdosRawIp,
    DdosUdp,
    Dos,
    ExploitingFtp,
    Fuzzing,
    IcmpFlood,
    SynFlood,
    PortScanning,
    RemoteCodeExecution,
    SqlInjection,
    Xss,
    Unknown
};

/// Total number of model output classes (excluding Unknown).
inline constexpr int kAttackTypeCount = 16;

[[nodiscard]] constexpr std::string_view attackTypeToString(AttackType type) noexcept {
    switch (type) {
        case AttackType::Benign:               return "Benign";
        case AttackType::MitmArpSpoofing:      return "MITM ARP Spoofing";
        case AttackType::SshBruteForce:        return "SSH Brute Force";
        case AttackType::FtpBruteForce:        return "FTP Brute Force";
        case AttackType::DdosIcmp:             return "DDoS ICMP";
        case AttackType::DdosRawIp:            return "DDoS Raw IP";
        case AttackType::DdosUdp:              return "DDoS UDP";
        case AttackType::Dos:                  return "DoS";
        case AttackType::ExploitingFtp:        return "Exploiting FTP";
        case AttackType::Fuzzing:              return "Fuzzing";
        case AttackType::IcmpFlood:            return "ICMP Flood";
        case AttackType::SynFlood:             return "SYN Flood";
        case AttackType::PortScanning:         return "Port Scanning";
        case AttackType::RemoteCodeExecution:  return "Remote Code Execution";
        case AttackType::SqlInjection:         return "SQL Injection";
        case AttackType::Xss:                  return "XSS";
        case AttackType::Unknown:              return "Unknown";
    }
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
