#include "infra/rules/SnortRuleEngine.h"

#include "core/model/FlowInfo.h"
#include "core/model/SignatureMatch.h"

#include "helpers/TestFixtures.h"
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

using namespace nids;

namespace {
using nids::testing::makeFlow;
using nids::testing::makeResult;

[[nodiscard]] std::filesystem::path findTestRules() {
    for (const auto& base : {".", "..", "../.."}) {
        auto p = std::filesystem::path(base) / "tests" / "data" / "test_snort.rules";
        if (std::filesystem::exists(p)) return std::filesystem::canonical(p);
    }
    auto p = std::filesystem::path(NIDS_SOURCE_DIR) / "tests" / "data" / "test_snort.rules";
    if (std::filesystem::exists(p)) return p;
    return {};
}

std::vector<std::uint8_t> toBytes(const std::string& s) {
    return {s.begin(), s.end()};
}

} // namespace

class SnortRuleEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        rulesPath_ = findTestRules();
        if (rulesPath_.empty()) GTEST_SKIP() << "Test rules not found";
    }
    std::filesystem::path rulesPath_;
};

TEST_F(SnortRuleEngineTest, loadRules_loadsTestFile) {
    infra::SnortRuleEngine engine;
    EXPECT_TRUE(engine.loadRules(rulesPath_));
    EXPECT_GT(engine.ruleCount(), 5u);
    EXPECT_EQ(engine.fileCount(), 1u);
}

TEST_F(SnortRuleEngineTest, inspect_httpGet_matchesRule) {
    infra::SnortRuleEngine engine;
    engine.setVariable("HOME_NET", "any");
    engine.setVariable("EXTERNAL_NET", "any");
    ASSERT_TRUE(engine.loadRules(rulesPath_));

    auto payload = toBytes("GET /index.html HTTP/1.1\r\nHost: example.com\r\n");
    auto flow = makeFlow("192.168.1.10", "10.0.0.1", 54321, 80, 6);

    auto matches = engine.inspect(payload, flow);

    bool foundHttpGet = false;
    for (const auto& m : matches) {
        if (m.sid == 1000001) {
            foundHttpGet = true;
            EXPECT_EQ(m.msg, "Test HTTP GET");
            EXPECT_EQ(m.classtype, "web-application-attack");
            EXPECT_EQ(m.priority, 2);
            EXPECT_FLOAT_EQ(m.severity, 0.75f);
        }
    }
    EXPECT_TRUE(foundHttpGet);
}

TEST_F(SnortRuleEngineTest, inspect_sshBanner_matchesRule) {
    infra::SnortRuleEngine engine;
    ASSERT_TRUE(engine.loadRules(rulesPath_));

    auto payload = toBytes("SSH-2.0-OpenSSH_8.9");
    auto flow = makeFlow("10.0.0.1", "192.168.1.10", 54321, 22, 6);

    auto matches = engine.inspect(payload, flow);

    bool foundSsh = false;
    for (const auto& m : matches) {
        if (m.sid == 1000002) foundSsh = true;
    }
    EXPECT_TRUE(foundSsh);
}

TEST_F(SnortRuleEngineTest, inspect_hexContent_matchesRule) {
    infra::SnortRuleEngine engine;
    ASSERT_TRUE(engine.loadRules(rulesPath_));

    std::vector<std::uint8_t> payload = {
        0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x01};
    auto flow = makeFlow("10.0.0.1", "192.168.1.10", 54321, 8080, 6);

    auto matches = engine.inspect(payload, flow);

    bool foundHex = false;
    for (const auto& m : matches) {
        if (m.sid == 1000007) {
            foundHex = true;
            ASSERT_GE(m.references.size(), 1u);
            EXPECT_EQ(m.references[0].type, "cve");
            EXPECT_EQ(m.references[0].value, "2024-1234");
        }
    }
    EXPECT_TRUE(foundHex);
}

TEST_F(SnortRuleEngineTest, inspect_noMatch_returnsEmpty) {
    infra::SnortRuleEngine engine;
    ASSERT_TRUE(engine.loadRules(rulesPath_));

    // Use data that doesn't contain any of the test rule patterns.
    std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03, 0x04};
    auto flow = makeFlow("10.0.0.1", "192.168.1.10", 54321, 12345, 17);

    auto matches = engine.inspect(payload, flow);
    // UDP port 12345 with binary data should not match any test rule.
    EXPECT_TRUE(matches.empty());
}

TEST_F(SnortRuleEngineTest, inspect_emptyPayload_returnsEmpty) {
    infra::SnortRuleEngine engine;
    ASSERT_TRUE(engine.loadRules(rulesPath_));

    std::span<const std::uint8_t> empty;
    auto flow = makeFlow("10.0.0.1", "192.168.1.10", 54321, 80, 6);

    auto matches = engine.inspect(empty, flow);
    EXPECT_TRUE(matches.empty());
}

TEST_F(SnortRuleEngineTest, setVariable_affectsRuleMatching) {
    infra::SnortRuleEngine engine;
    engine.setVariable("HOME_NET", "192.168.1.0");
    engine.setVariable("EXTERNAL_NET", "10.0.0.0");
    ASSERT_TRUE(engine.loadRules(rulesPath_));

    // Rule 1000001: src=$HOME_NET -> dst=$EXTERNAL_NET
    auto payload = toBytes("GET /test HTTP/1.1\r\n");
    auto flow = makeFlow("192.168.1.0", "10.0.0.0", 54321, 80, 6);

    auto matches = engine.inspect(payload, flow);
    bool foundHttpGet = false;
    for (const auto& m : matches) {
        if (m.sid == 1000001) foundHttpGet = true;
    }
    EXPECT_TRUE(foundHttpGet);
}

TEST_F(SnortRuleEngineTest, reloadRules_preservesRules) {
    infra::SnortRuleEngine engine;
    ASSERT_TRUE(engine.loadRules(rulesPath_));
    auto countBefore = engine.ruleCount();

    EXPECT_TRUE(engine.reloadRules());
    EXPECT_EQ(engine.ruleCount(), countBefore);
}

TEST_F(SnortRuleEngineTest, inspect_bidirectionalRule_matchesBothDirections) {
    infra::SnortRuleEngine engine;
    ASSERT_TRUE(engine.loadRules(rulesPath_));

    auto payload = toBytes("HELLO");

    // Forward direction
    auto flow1 = makeFlow("10.0.0.1", "192.168.1.10", 54321, 8080, 6);
    auto matches1 = engine.inspect(payload, flow1);
    bool foundBidir1 = false;
    for (const auto& m : matches1) {
        if (m.sid == 1000008) foundBidir1 = true;
    }

    // Reverse direction
    auto flow2 = makeFlow("192.168.1.10", "10.0.0.1", 8080, 54321, 6);
    auto matches2 = engine.inspect(payload, flow2);
    bool foundBidir2 = false;
    for (const auto& m : matches2) {
        if (m.sid == 1000008) foundBidir2 = true;
    }

    EXPECT_TRUE(foundBidir1 || foundBidir2);
}

TEST(SnortRuleEngine, noRulesLoaded_returnsEmpty) {
    infra::SnortRuleEngine engine;

    auto payload = toBytes("GET / HTTP/1.1");
    auto flow = makeFlow("10.0.0.1", "192.168.1.10", 54321, 80, 6);

    auto matches = engine.inspect(payload, flow);
    EXPECT_TRUE(matches.empty());
}
