#include <gtest/gtest.h>
#include "core/model/AttackType.h"

using nids::core::AttackType;
using nids::core::attackTypeToString;
using nids::core::attackTypeFromIndex;

TEST(AttackType, toStringCoversAllTypes) {
    EXPECT_EQ(attackTypeToString(AttackType::Benign), "BENIGN");
    EXPECT_EQ(attackTypeToString(AttackType::Portscan), "Portscan");
    EXPECT_EQ(attackTypeToString(AttackType::DosHulk), "DoS Hulk");
    EXPECT_EQ(attackTypeToString(AttackType::DDoS), "DDoS");
    EXPECT_EQ(attackTypeToString(AttackType::InfiltrationPortscan), "Infiltration - Portscan");
    EXPECT_EQ(attackTypeToString(AttackType::DosGoldenEye), "DoS GoldenEye");
    EXPECT_EQ(attackTypeToString(AttackType::FtpPatator), "FTP-Patator");
    EXPECT_EQ(attackTypeToString(AttackType::DosSlowloris), "DoS Slowloris");
    EXPECT_EQ(attackTypeToString(AttackType::SshPatator), "SSH-Patator");
    EXPECT_EQ(attackTypeToString(AttackType::DosSlowHttpTest), "DoS Slowhttptest");
    EXPECT_EQ(attackTypeToString(AttackType::Botnet), "Botnet");
    EXPECT_EQ(attackTypeToString(AttackType::BruteForce), "Brute Force");
    EXPECT_EQ(attackTypeToString(AttackType::Infiltration), "Infiltration");
    EXPECT_EQ(attackTypeToString(AttackType::Xss), "XSS");
    EXPECT_EQ(attackTypeToString(AttackType::SqlInjection), "SQL Injection");
    EXPECT_EQ(attackTypeToString(AttackType::Heartbleed), "Heartbleed");
    EXPECT_EQ(attackTypeToString(AttackType::Unknown), "Unknown");
}

TEST(AttackType, fromIndexValidRange) {
    EXPECT_EQ(attackTypeFromIndex(0), AttackType::Benign);
    EXPECT_EQ(attackTypeFromIndex(3), AttackType::DDoS);
    EXPECT_EQ(attackTypeFromIndex(15), AttackType::Heartbleed);
}

TEST(AttackType, fromIndexOutOfRange) {
    EXPECT_EQ(attackTypeFromIndex(-1), AttackType::Unknown);
    EXPECT_EQ(attackTypeFromIndex(100), AttackType::Unknown);
    EXPECT_EQ(attackTypeFromIndex(16), AttackType::Unknown);
}
