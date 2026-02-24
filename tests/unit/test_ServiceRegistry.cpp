#include <gtest/gtest.h>
#include "core/services/ServiceRegistry.h"

using nids::core::ServiceRegistry;

class ServiceRegistryTest : public ::testing::Test {
protected:
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
    auto result = registry.resolveApplication("80", "443", "53");
    EXPECT_EQ(result, "HTTPS");
}

TEST_F(ServiceRegistryTest, resolveApplication_sourcePortFallback) {
    auto result = registry.resolveApplication("80", "", "53");
    EXPECT_EQ(result, "HTTP");
}

TEST_F(ServiceRegistryTest, resolveApplication_packetPortFallback) {
    auto result = registry.resolveApplication("", "", "53");
    EXPECT_EQ(result, "DNS");
}

TEST_F(ServiceRegistryTest, resolveApplication_allEmpty) {
    auto result = registry.resolveApplication("", "", "");
    EXPECT_EQ(result, "Unknown");
}

TEST_F(ServiceRegistryTest, resolveApplication_invalidPort) {
    auto result = registry.resolveApplication("not_a_port", "", "");
    EXPECT_EQ(result, "Unknown");
}
