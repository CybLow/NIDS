#include "core/services/ServiceRegistry.h"
#include <gtest/gtest.h>

using nids::core::ServiceRegistry;

class ServiceRegistryTest : public ::testing::Test {
protected: // NOSONAR
  ServiceRegistry registry;
};

TEST_F(ServiceRegistryTest, knownPortReturnsService) {
  EXPECT_EQ(registry.getServiceByPort(80), "HTTP");
  EXPECT_EQ(registry.getServiceByPort(443), "HTTPS");
  EXPECT_EQ(registry.getServiceByPort(22), "SSH/SCP/SFTP");
  EXPECT_EQ(registry.getServiceByPort(53), "DNS");
  EXPECT_EQ(registry.getServiceByPort(21), "FTP");
  EXPECT_EQ(registry.getServiceByPort(25), "SMTP");
}

TEST_F(ServiceRegistryTest, unknownPortReturnsUnknown) {
  EXPECT_EQ(registry.getServiceByPort(99999), "Unknown");
  EXPECT_EQ(registry.getServiceByPort(0), "Unknown");
  EXPECT_EQ(registry.getServiceByPort(-1), "Unknown");
}

TEST_F(ServiceRegistryTest, uniqueServicesNotEmpty) {
  auto services = registry.getUniqueServices();
  EXPECT_FALSE(services.empty());
  EXPECT_TRUE(services.count("HTTP") > 0);
  EXPECT_TRUE(services.count("HTTPS") > 0);
  EXPECT_TRUE(services.count("DNS") > 0);
}

TEST_F(ServiceRegistryTest, resolveApplication_destinationPortPriority) {
  auto result = registry.resolveApplication(80, 443, 53);
  EXPECT_EQ(result, "HTTPS");
}

TEST_F(ServiceRegistryTest, resolveApplication_sourcePortFallback) {
  auto result = registry.resolveApplication(80, 0, 53);
  EXPECT_EQ(result, "HTTP");
}

TEST_F(ServiceRegistryTest, resolveApplication_packetPortFallback) {
  auto result = registry.resolveApplication(0, 0, 53);
  EXPECT_EQ(result, "DNS");
}

TEST_F(ServiceRegistryTest, resolveApplication_allZero) {
  auto result = registry.resolveApplication(0, 0, 0);
  EXPECT_EQ(result, "Unknown");
}

// ── Additional port coverage ─────────────────────────────────────────

TEST_F(ServiceRegistryTest, knownPorts_moreServices) {
  EXPECT_EQ(registry.getServiceByPort(23), "Telnet");
  EXPECT_EQ(registry.getServiceByPort(110), "POP3");
  EXPECT_EQ(registry.getServiceByPort(143), "IMAP");
  EXPECT_EQ(registry.getServiceByPort(3306), "MySQL");
  EXPECT_EQ(registry.getServiceByPort(3389), "RDP");
  EXPECT_EQ(registry.getServiceByPort(5432), "PostgreSQL");
  EXPECT_EQ(registry.getServiceByPort(6379), "Redis");
  EXPECT_EQ(registry.getServiceByPort(27017), "MongoDB");
  EXPECT_EQ(registry.getServiceByPort(8080), "HTTP Proxy");
  EXPECT_EQ(registry.getServiceByPort(5900), "VNC");
  EXPECT_EQ(registry.getServiceByPort(1194), "OpenVPN");
  EXPECT_EQ(registry.getServiceByPort(5060), "SIP");
  EXPECT_EQ(registry.getServiceByPort(161), "SNMP");
  EXPECT_EQ(registry.getServiceByPort(389), "LDAP");
  EXPECT_EQ(registry.getServiceByPort(445), "Microsoft DS SMB");
}

TEST_F(ServiceRegistryTest, knownPorts_malwareAndGaming) {
  EXPECT_EQ(registry.getServiceByPort(4444), "Blaster Worm");
  EXPECT_EQ(registry.getServiceByPort(31337), "Back Orifice");
  EXPECT_EQ(registry.getServiceByPort(12345), "NetBus");
  EXPECT_EQ(registry.getServiceByPort(6881), "BitTorrent");
  EXPECT_EQ(registry.getServiceByPort(27015), "Half-Life");
  EXPECT_EQ(registry.getServiceByPort(3724), "World of Warcraft");
}

TEST_F(ServiceRegistryTest, knownPorts_infraPorts) {
  EXPECT_EQ(registry.getServiceByPort(88), "Kerberos");
  EXPECT_EQ(registry.getServiceByPort(123), "NTP");
  EXPECT_EQ(registry.getServiceByPort(636), "LDAP over SSL");
  EXPECT_EQ(registry.getServiceByPort(1812), "RADIUS Authentication");
  EXPECT_EQ(registry.getServiceByPort(1813), "RADIUS Accounting");
  EXPECT_EQ(registry.getServiceByPort(5353), "MDNS");
  EXPECT_EQ(registry.getServiceByPort(33434), "traceroute");
}

// ── resolveApplication exception cascades ────────────────────────────

TEST_F(ServiceRegistryTest, resolveApplication_dstPortZero_fallsToSrc) {
  // filterDstPort is 0 (unset), filterSrcPort 80 resolves to HTTP
  auto result = registry.resolveApplication(80, 0, 0);
  EXPECT_EQ(result, "HTTP");
}

TEST_F(ServiceRegistryTest, resolveApplication_srcPort_unknownPort) {
  // filterSrcPort is a valid number but not a known port
  auto result = registry.resolveApplication(60000, 0, 0);
  EXPECT_EQ(result, "Unknown");
}

TEST_F(ServiceRegistryTest, resolveApplication_allValid_dstPortWins) {
  // All three are valid ports, destination port has priority
  auto result = registry.resolveApplication(22, 80, 53);
  EXPECT_EQ(result, "HTTP");
}

TEST_F(ServiceRegistryTest, resolveApplication_srcAndPacketPort) {
  // No filter dst port, src port wins over packet port
  auto result = registry.resolveApplication(443, 0, 22);
  EXPECT_EQ(result, "HTTPS");
}

TEST_F(ServiceRegistryTest, resolveApplication_onlyPacketPort) {
  auto result = registry.resolveApplication(0, 0, 3306);
  EXPECT_EQ(result, "MySQL");
}

// ── getUniqueServices completeness ───────────────────────────────────

TEST_F(ServiceRegistryTest, uniqueServices_containsExpectedCount) {
  auto services = registry.getUniqueServices();
  // Should have many distinct services (port table has ~130 entries with many
  // duplicates)
  EXPECT_GT(services.size(), 50u);
  // Check some specific ones
  EXPECT_TRUE(services.count("SSH/SCP/SFTP") > 0);
  EXPECT_TRUE(services.count("MySQL") > 0);
  EXPECT_TRUE(services.count("PostgreSQL") > 0);
  EXPECT_TRUE(services.count("RDP") > 0);
}
