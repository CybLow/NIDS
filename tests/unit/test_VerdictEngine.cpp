#include "app/VerdictEngine.h"

#include "helpers/MockThreatIntel.h"

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <cstdint>
#include <string>
#include <vector>

using namespace nids;
using ::testing::Return;

namespace {

core::FlowInfo makeFlow(const std::string& src, const std::string& dst,
                          std::uint16_t srcPort, std::uint16_t dstPort,
                          std::uint8_t proto = 6) {
    core::FlowInfo f;
    f.srcIp = src;
    f.dstIp = dst;
    f.srcPort = srcPort;
    f.dstPort = dstPort;
    f.protocol = proto;
    return f;
}

std::vector<std::uint8_t> toBytes(const std::string& s) {
    return {s.begin(), s.end()};
}

} // namespace

TEST(VerdictEngine, defaultPolicy_noDetectors_forwards) {
    app::VerdictEngine engine(nullptr, nullptr, nullptr);

    auto payload = toBytes("normal traffic");
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80);

    auto result = engine.evaluate(payload, flow);
    EXPECT_EQ(result.verdict, core::PacketVerdict::Forward);
    EXPECT_EQ(result.source, core::VerdictSource::Default);
}

TEST(VerdictEngine, tiMatch_drops) {
    nids::testing::MockThreatIntel mockTi;
    EXPECT_CALL(mockTi, lookup(std::string_view("10.0.0.1")))
        .WillOnce(Return(core::ThreatIntelLookup{true, "botnet"}));

    app::VerdictEngine engine(&mockTi, nullptr, nullptr);

    auto payload = toBytes("data");
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80);

    auto result = engine.evaluate(payload, flow);
    EXPECT_EQ(result.verdict, core::PacketVerdict::Drop);
    EXPECT_EQ(result.source, core::VerdictSource::ThreatIntel);
}

TEST(VerdictEngine, tiMatch_dstIp_drops) {
    nids::testing::MockThreatIntel mockTi;
    EXPECT_CALL(mockTi, lookup(std::string_view("10.0.0.1")))
        .WillOnce(Return(core::ThreatIntelLookup{false, ""}));
    EXPECT_CALL(mockTi, lookup(std::string_view("192.168.1.1")))
        .WillOnce(Return(core::ThreatIntelLookup{true, "c2"}));

    app::VerdictEngine engine(&mockTi, nullptr, nullptr);

    auto payload = toBytes("data");
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80);

    auto result = engine.evaluate(payload, flow);
    EXPECT_EQ(result.verdict, core::PacketVerdict::Drop);
}

TEST(VerdictEngine, tiDisabled_noBlock) {
    nids::testing::MockThreatIntel mockTi;

    app::VerdictPolicy policy;
    policy.blockOnTiMatch = false;

    app::VerdictEngine engine(&mockTi, nullptr, nullptr, policy);

    auto payload = toBytes("data");
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80);

    auto result = engine.evaluate(payload, flow);
    EXPECT_EQ(result.verdict, core::PacketVerdict::Forward);
}

TEST(VerdictEngine, dynamicBlock_drops) {
    app::VerdictEngine engine(nullptr, nullptr, nullptr);

    infra::FlowKey key{"10.0.0.1", "192.168.1.1", 12345, 80, 6};
    engine.blockFlow(key, "ML detected DDoS");

    auto payload = toBytes("data");
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80);

    auto result = engine.evaluate(payload, flow);
    EXPECT_EQ(result.verdict, core::PacketVerdict::Drop);
    EXPECT_EQ(result.source, core::VerdictSource::DynamicBlock);
}

TEST(VerdictEngine, dynamicBlock_unblock_forwards) {
    app::VerdictEngine engine(nullptr, nullptr, nullptr);

    infra::FlowKey key{"10.0.0.1", "192.168.1.1", 12345, 80, 6};
    engine.blockFlow(key, "test");
    EXPECT_EQ(engine.blockCount(), 1u);

    engine.unblockFlow(key);
    EXPECT_EQ(engine.blockCount(), 0u);

    auto payload = toBytes("data");
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80);

    auto result = engine.evaluate(payload, flow);
    EXPECT_EQ(result.verdict, core::PacketVerdict::Forward);
}

TEST(VerdictEngine, clearBlocks_removesAll) {
    app::VerdictEngine engine(nullptr, nullptr, nullptr);

    engine.blockFlow({"10.0.0.1", "1.1.1.1", 111, 80, 6}, "a");
    engine.blockFlow({"10.0.0.2", "2.2.2.2", 222, 443, 6}, "b");
    EXPECT_EQ(engine.blockCount(), 2u);

    engine.clearBlocks();
    EXPECT_EQ(engine.blockCount(), 0u);
}

TEST(VerdictEngine, emptyPayload_noDetectors_forwards) {
    app::VerdictEngine engine(nullptr, nullptr, nullptr);

    std::span<const std::uint8_t> empty;
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80);

    auto result = engine.evaluate(empty, flow);
    EXPECT_EQ(result.verdict, core::PacketVerdict::Forward);
}

TEST(VerdictEngine, setPolicy_updatesPolicy) {
    app::VerdictEngine engine(nullptr, nullptr, nullptr);

    app::VerdictPolicy policy;
    policy.blockOnYara = true;
    engine.setPolicy(policy);

    // Just verify no crash.
    SUCCEED();
}
