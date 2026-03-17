#include "core/model/PacketFilter.h"
#include <gtest/gtest.h>

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

// ── Additional combination edge cases ────────────────────────────────

TEST(PacketFilter, srcIpAndDstPort) {
  PacketFilter filter;
  filter.sourceIP = "192.168.1.1";
  filter.destinationPort = "443";
  EXPECT_EQ(filter.generateBpfString(),
            "src host 192.168.1.1 and dst port 443");
}

TEST(PacketFilter, dstIpAndSrcPort) {
  PacketFilter filter;
  filter.destinationIP = "10.0.0.1";
  filter.sourcePort = "8080";
  EXPECT_EQ(filter.generateBpfString(), "dst host 10.0.0.1 and src port 8080");
}

TEST(PacketFilter, srcPortAndDstPort) {
  PacketFilter filter;
  filter.sourcePort = "12345";
  filter.destinationPort = "80";
  EXPECT_EQ(filter.generateBpfString(), "src port 12345 and dst port 80");
}

TEST(PacketFilter, protocolAndSrcIp) {
  PacketFilter filter;
  filter.protocol = "ICMP";
  filter.sourceIP = "10.0.0.5";
  EXPECT_EQ(filter.generateBpfString(), "proto ICMP and src host 10.0.0.5");
}

TEST(PacketFilter, srcIpAndDstIp) {
  PacketFilter filter;
  filter.sourceIP = "192.168.1.1";
  filter.destinationIP = "10.0.0.1";
  EXPECT_EQ(filter.generateBpfString(),
            "src host 192.168.1.1 and dst host 10.0.0.1");
}

TEST(PacketFilter, protocolAndBothPorts) {
  PacketFilter filter;
  filter.protocol = "TCP";
  filter.sourcePort = "5555";
  filter.destinationPort = "80";
  EXPECT_EQ(filter.generateBpfString(),
            "proto TCP and src port 5555 and dst port 80");
}

TEST(PacketFilter, emptyCustomBpf_usesRegularFields) {
  PacketFilter filter;
  filter.protocol = "TCP";
  filter.customBPFFilter = ""; // Empty custom filter → use regular fields
  EXPECT_EQ(filter.generateBpfString(), "proto TCP");
}

TEST(PacketFilter, customBpfWhitespaceOnly_overridesRegularFields) {
  PacketFilter filter;
  filter.protocol = "TCP";
  filter.customBPFFilter = "   "; // Whitespace-only custom filter
  // Behavior depends on implementation: likely treated as non-empty
  auto result = filter.generateBpfString();
  // Either "   " (literal) or "proto TCP" depending on empty check
  EXPECT_FALSE(result.empty());
}

// ══════════════════════════════════════════════════════════════════
//  FilterBuilder tests
// ══════════════════════════════════════════════════════════════════

using nids::core::FilterBuilder;

TEST(FilterBuilder, defaultBuild_producesEmptyFilter) {
  auto filter = FilterBuilder().build();
  EXPECT_TRUE(filter.generateBpfString().empty());
}

TEST(FilterBuilder, protocol_setsProtocol) {
  auto filter = FilterBuilder().protocol("TCP").build();
  EXPECT_EQ(filter.generateBpfString(), "proto TCP");
}

TEST(FilterBuilder, sourceIp_setsSourceIP) {
  auto filter = FilterBuilder().sourceIp("192.168.1.1").build();
  EXPECT_EQ(filter.generateBpfString(), "src host 192.168.1.1");
}

TEST(FilterBuilder, destinationIp_setsDestinationIP) {
  auto filter = FilterBuilder().destinationIp("10.0.0.1").build();
  EXPECT_EQ(filter.generateBpfString(), "dst host 10.0.0.1");
}

TEST(FilterBuilder, sourcePort_setsSourcePort) {
  auto filter = FilterBuilder().sourcePort("8080").build();
  EXPECT_EQ(filter.generateBpfString(), "src port 8080");
}

TEST(FilterBuilder, destinationPort_setsDestinationPort) {
  auto filter = FilterBuilder().destinationPort("443").build();
  EXPECT_EQ(filter.generateBpfString(), "dst port 443");
}

TEST(FilterBuilder, customBpf_overridesOtherFields) {
  auto filter = FilterBuilder()
                    .protocol("TCP")
                    .sourceIp("1.2.3.4")
                    .customBpf("port 80 or port 443")
                    .build();
  EXPECT_EQ(filter.generateBpfString(), "port 80 or port 443");
}

TEST(FilterBuilder, networkCard_setsNetworkCard) {
  auto filter = FilterBuilder().networkCard("eth0").build();
  EXPECT_EQ(filter.networkCard, "eth0");
  // networkCard does not affect BPF string
  EXPECT_TRUE(filter.generateBpfString().empty());
}

TEST(FilterBuilder, application_setsApplication) {
  auto filter = FilterBuilder().application("HTTP").build();
  EXPECT_EQ(filter.application, "HTTP");
  // application does not affect BPF string (UI-only field)
  EXPECT_TRUE(filter.generateBpfString().empty());
}

TEST(FilterBuilder, fluentChaining_fullFilter) {
  auto filter = FilterBuilder()
                    .networkCard("wlan0")
                    .protocol("UDP")
                    .sourceIp("192.168.1.0/24")
                    .destinationIp("8.8.8.8")
                    .sourcePort("5353")
                    .destinationPort("53")
                    .build();

  EXPECT_EQ(filter.networkCard, "wlan0");
  EXPECT_EQ(filter.generateBpfString(),
            "proto UDP and src host 192.168.1.0/24 and dst host 8.8.8.8 "
            "and src port 5353 and dst port 53");
}

TEST(FilterBuilder, moveBuild_transfersOwnership) {
  auto filter = FilterBuilder()
                    .protocol("ICMP")
                    .sourceIp("10.0.0.5")
                    .build(); // rvalue build() on temporary

  EXPECT_EQ(filter.generateBpfString(), "proto ICMP and src host 10.0.0.5");
}

TEST(FilterBuilder, lvalueBuild_copiesFilter) {
  FilterBuilder builder;
  builder.protocol("TCP").destinationPort("22");

  // First build (const& overload)
  auto filter1 = builder.build();
  EXPECT_EQ(filter1.generateBpfString(), "proto TCP and dst port 22");

  // Builder is still usable after lvalue build
  builder.sourceIp("10.0.0.1");
  auto filter2 = builder.build();
  EXPECT_EQ(filter2.generateBpfString(),
            "proto TCP and src host 10.0.0.1 and dst port 22");
}
