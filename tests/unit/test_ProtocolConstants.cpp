#include <gtest/gtest.h>

#include "core/model/ProtocolConstants.h"

using nids::core::kIpProtoIcmp;
using nids::core::kIpProtoTcp;
using nids::core::kIpProtoUdp;
using nids::core::protocolToName;

TEST(ProtocolConstants, kIpProtoValues) {
    EXPECT_EQ(kIpProtoIcmp, 1);
    EXPECT_EQ(kIpProtoTcp, 6);
    EXPECT_EQ(kIpProtoUdp, 17);
}

TEST(ProtocolConstants, protocolToName_tcp) {
    EXPECT_EQ(protocolToName(6), "TCP");
}

TEST(ProtocolConstants, protocolToName_udp) {
    EXPECT_EQ(protocolToName(17), "UDP");
}

TEST(ProtocolConstants, protocolToName_icmp) {
    EXPECT_EQ(protocolToName(1), "ICMP");
}

TEST(ProtocolConstants, protocolToName_unknown_returnsOther) {
    EXPECT_EQ(protocolToName(0), "Other");
    EXPECT_EQ(protocolToName(47), "Other");   // GRE
    EXPECT_EQ(protocolToName(255), "Other");
}

TEST(ProtocolConstants, protocolToName_isConstexpr) {
    // Verify the function is usable in a constexpr context.
    constexpr auto name = protocolToName(6);
    static_assert(name == "TCP");
}

TEST(ProtocolConstants, constants_areConstexpr) {
    static_assert(kIpProtoTcp == 6);
    static_assert(kIpProtoUdp == 17);
    static_assert(kIpProtoIcmp == 1);
}
