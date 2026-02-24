#pragma once

#include <string>
#include <cstdint>

namespace nids::core {

enum class AttackType : std::uint8_t {
    Benign = 0,
    Portscan,
    DosHulk,
    DDoS,
    InfiltrationPortscan,
    DosGoldenEye,
    FtpPatator,
    DosSlowloris,
    SshPatator,
    DosSlowHttpTest,
    Botnet,
    BruteForce,
    Infiltration,
    Xss,
    SqlInjection,
    Heartbleed,
    Unknown
};

inline std::string attackTypeToString(AttackType type) {
    switch (type) {
        case AttackType::Benign:               return "BENIGN";
        case AttackType::Portscan:             return "Portscan";
        case AttackType::DosHulk:              return "DoS Hulk";
        case AttackType::DDoS:                 return "DDoS";
        case AttackType::InfiltrationPortscan: return "Infiltration - Portscan";
        case AttackType::DosGoldenEye:         return "DoS GoldenEye";
        case AttackType::FtpPatator:           return "FTP-Patator";
        case AttackType::DosSlowloris:         return "DoS Slowloris";
        case AttackType::SshPatator:           return "SSH-Patator";
        case AttackType::DosSlowHttpTest:      return "DoS Slowhttptest";
        case AttackType::Botnet:               return "Botnet";
        case AttackType::BruteForce:           return "Brute Force";
        case AttackType::Infiltration:         return "Infiltration";
        case AttackType::Xss:                  return "XSS";
        case AttackType::SqlInjection:         return "SQL Injection";
        case AttackType::Heartbleed:           return "Heartbleed";
        case AttackType::Unknown:              return "Unknown";
    }
    return "Unknown";
}

inline AttackType attackTypeFromIndex(int index) {
    if (index >= 0 && index <= static_cast<int>(AttackType::Heartbleed)) {
        return static_cast<AttackType>(index);
    }
    return AttackType::Unknown;
}

} // namespace nids::core
