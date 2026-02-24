#include <gtest/gtest.h>
#include "core/services/PacketFilter.h"

using nids::core::PacketFilter;

TEST(PacketFilter, emptyFilterGeneratesEmptyString) {
    PacketFilter filter;
    EXPECT_EQ(filter.generateBpfString(), "");
}

TEST(PacketFilter, protocolOnly) {
    PacketFilter filter;
    filter.protocol = "TCP";
    EXPECT_EQ(filter.generateBpfString(), "proto TCP");
}

TEST(PacketFilter, protocolAllIsIgnored) {
    PacketFilter filter;
    filter.protocol = "ALL";
    EXPECT_EQ(filter.generateBpfString(), "");
}

TEST(PacketFilter, protocolUnknownIsIgnored) {
    PacketFilter filter;
    filter.protocol = "Unknown";
    EXPECT_EQ(filter.generateBpfString(), "");
}

TEST(PacketFilter, sourceIpOnly) {
    PacketFilter filter;
    filter.sourceIP = "192.168.1.1";
    EXPECT_EQ(filter.generateBpfString(), "src host 192.168.1.1");
}

TEST(PacketFilter, destinationIpOnly) {
    PacketFilter filter;
    filter.destinationIP = "10.0.0.1";
    EXPECT_EQ(filter.generateBpfString(), "dst host 10.0.0.1");
}

TEST(PacketFilter, sourcePortOnly) {
    PacketFilter filter;
    filter.sourcePort = "8080";
    EXPECT_EQ(filter.generateBpfString(), "src port 8080");
}

TEST(PacketFilter, destinationPortOnly) {
    PacketFilter filter;
    filter.destinationPort = "443";
    EXPECT_EQ(filter.generateBpfString(), "dst port 443");
}

TEST(PacketFilter, fullFilter) {
    PacketFilter filter;
    filter.protocol = "TCP";
    filter.sourceIP = "192.168.1.1";
    filter.destinationIP = "10.0.0.1";
    filter.sourcePort = "12345";
    filter.destinationPort = "443";
    EXPECT_EQ(filter.generateBpfString(),
              "proto TCP and src host 192.168.1.1 and dst host 10.0.0.1 "
              "and src port 12345 and dst port 443");
}

TEST(PacketFilter, customBpfOverridesEverything) {
    PacketFilter filter;
    filter.protocol = "TCP";
    filter.sourceIP = "192.168.1.1";
    filter.customBPFFilter = "port 80 or port 443";
    EXPECT_EQ(filter.generateBpfString(), "port 80 or port 443");
}

TEST(PacketFilter, partialFilterCombination) {
    PacketFilter filter;
    filter.protocol = "UDP";
    filter.destinationPort = "53";
    EXPECT_EQ(filter.generateBpfString(), "proto UDP and dst port 53");
}
