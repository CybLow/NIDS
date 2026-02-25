#include <gtest/gtest.h>
#include "core/model/AttackType.h"

using nids::core::AttackType;
using nids::core::attackTypeToString;
using nids::core::attackTypeFromIndex;
using nids::core::kAttackTypeCount;

TEST(AttackType, toStringCoversAllLsnm2024Types) {
    EXPECT_EQ(attackTypeToString(AttackType::Benign), "Benign");
    EXPECT_EQ(attackTypeToString(AttackType::MitmArpSpoofing), "MITM ARP Spoofing");
    EXPECT_EQ(attackTypeToString(AttackType::SshBruteForce), "SSH Brute Force");
    EXPECT_EQ(attackTypeToString(AttackType::FtpBruteForce), "FTP Brute Force");
    EXPECT_EQ(attackTypeToString(AttackType::DdosIcmp), "DDoS ICMP");
    EXPECT_EQ(attackTypeToString(AttackType::DdosRawIp), "DDoS Raw IP");
    EXPECT_EQ(attackTypeToString(AttackType::DdosUdp), "DDoS UDP");
    EXPECT_EQ(attackTypeToString(AttackType::Dos), "DoS");
    EXPECT_EQ(attackTypeToString(AttackType::ExploitingFtp), "Exploiting FTP");
    EXPECT_EQ(attackTypeToString(AttackType::Fuzzing), "Fuzzing");
    EXPECT_EQ(attackTypeToString(AttackType::IcmpFlood), "ICMP Flood");
    EXPECT_EQ(attackTypeToString(AttackType::SynFlood), "SYN Flood");
    EXPECT_EQ(attackTypeToString(AttackType::PortScanning), "Port Scanning");
    EXPECT_EQ(attackTypeToString(AttackType::RemoteCodeExecution), "Remote Code Execution");
    EXPECT_EQ(attackTypeToString(AttackType::SqlInjection), "SQL Injection");
    EXPECT_EQ(attackTypeToString(AttackType::Xss), "XSS");
    EXPECT_EQ(attackTypeToString(AttackType::Unknown), "Unknown");
}

TEST(AttackType, fromIndexValidRange) {
    EXPECT_EQ(attackTypeFromIndex(0), AttackType::Benign);
    EXPECT_EQ(attackTypeFromIndex(1), AttackType::MitmArpSpoofing);
    EXPECT_EQ(attackTypeFromIndex(7), AttackType::Dos);
    EXPECT_EQ(attackTypeFromIndex(12), AttackType::PortScanning);
    EXPECT_EQ(attackTypeFromIndex(15), AttackType::Xss);
}

TEST(AttackType, fromIndexOutOfRange) {
    EXPECT_EQ(attackTypeFromIndex(-1), AttackType::Unknown);
    EXPECT_EQ(attackTypeFromIndex(16), AttackType::Unknown);
    EXPECT_EQ(attackTypeFromIndex(100), AttackType::Unknown);
    EXPECT_EQ(attackTypeFromIndex(-100), AttackType::Unknown);
}

TEST(AttackType, kAttackTypeCountMatchesEnumSize) {
    // kAttackTypeCount should equal 16 (Benign + 15 attacks, excluding Unknown)
    EXPECT_EQ(kAttackTypeCount, 16);
    // The last valid index should be Xss (15)
    EXPECT_EQ(attackTypeFromIndex(kAttackTypeCount - 1), AttackType::Xss);
    // One past the last valid index should be Unknown
    EXPECT_EQ(attackTypeFromIndex(kAttackTypeCount), AttackType::Unknown);
}

TEST(AttackType, constexprEvaluation) {
    // Verify these functions work at compile time
    static_assert(attackTypeToString(AttackType::Benign) == "Benign");
    static_assert(attackTypeToString(AttackType::Xss) == "XSS");
    static_assert(attackTypeFromIndex(0) == AttackType::Benign);
    static_assert(attackTypeFromIndex(16) == AttackType::Unknown);
    static_assert(attackTypeFromIndex(-1) == AttackType::Unknown);
}
