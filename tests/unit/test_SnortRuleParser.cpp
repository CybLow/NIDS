#include "infra/rules/SnortRuleParser.h"

#include "core/model/SnortRule.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

using namespace nids;

namespace {

[[nodiscard]] std::filesystem::path findTestRules() {
    for (const auto& base : {".", "..", "../.."}) {
        auto p = std::filesystem::path(base) / "tests" / "data" / "test_snort.rules";
        if (std::filesystem::exists(p)) return std::filesystem::canonical(p);
    }
    auto p = std::filesystem::path(NIDS_SOURCE_DIR) / "tests" / "data" / "test_snort.rules";
    if (std::filesystem::exists(p)) return p;
    return {};
}

} // namespace

TEST(SnortRuleParser, parse_alertTcpRule_extractsHeader) {
    infra::SnortRuleParser parser;

    auto result = parser.parse(
        R"(alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Test"; sid:1; rev:1;))");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->action, core::SnortRule::Action::Alert);
    EXPECT_EQ(result->protocol, 6);
    EXPECT_EQ(result->srcIp, "$HOME_NET");
    EXPECT_EQ(result->srcPort, "any");
    EXPECT_EQ(result->dstIp, "$EXTERNAL_NET");
    EXPECT_EQ(result->dstPort, "80");
    EXPECT_FALSE(result->bidirectional);
}

TEST(SnortRuleParser, parse_bidirectionalRule_setsBidirectional) {
    infra::SnortRuleParser parser;

    auto result = parser.parse(
        R"(alert tcp any any <> any any (msg:"Bidir"; sid:2; rev:1;))");

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->bidirectional);
}

TEST(SnortRuleParser, parse_extractsMetadata) {
    infra::SnortRuleParser parser;

    auto result = parser.parse(
        R"(alert tcp any any -> any 80 (msg:"HTTP GET"; sid:100; rev:3; classtype:web-application-attack; priority:2;))");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->msg, "HTTP GET");
    EXPECT_EQ(result->sid, 100u);
    EXPECT_EQ(result->rev, 3u);
    EXPECT_EQ(result->classtype, "web-application-attack");
    EXPECT_EQ(result->priority, 2);
}

TEST(SnortRuleParser, parse_contentOption_decodesText) {
    infra::SnortRuleParser parser;

    auto result = parser.parse(
        R"(alert tcp any any -> any any (msg:"T"; content:"GET"; sid:1; rev:1;))");

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->contents.size(), 1u);
    EXPECT_EQ(result->contents[0].pattern,
              std::vector<std::uint8_t>({'G', 'E', 'T'}));
}

TEST(SnortRuleParser, parse_contentHex_decodesHexBytes) {
    infra::SnortRuleParser parser;

    auto result = parser.parse(
        R"(alert tcp any any -> any any (msg:"T"; content:"|DE AD BE EF|"; sid:1; rev:1;))");

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->contents.size(), 1u);
    std::vector<std::uint8_t> expected = {0xDE, 0xAD, 0xBE, 0xEF};
    EXPECT_EQ(result->contents[0].pattern, expected);
}

TEST(SnortRuleParser, parse_contentModifiers_appliedCorrectly) {
    infra::SnortRuleParser parser;

    auto result = parser.parse(
        R"(alert tcp any any -> any any (msg:"T"; content:"GET"; offset:0; depth:3; nocase; sid:1; rev:1;))");

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->contents.size(), 1u);
    EXPECT_TRUE(result->contents[0].nocase);
    EXPECT_EQ(result->contents[0].offset, 0);
    EXPECT_EQ(result->contents[0].depth, 3);
}

TEST(SnortRuleParser, parse_multipleContents_chainedCorrectly) {
    infra::SnortRuleParser parser;

    auto result = parser.parse(
        R"(alert tcp any any -> any any (msg:"T"; content:"|00 01|"; content:"tunnel"; distance:4; within:20; sid:1; rev:1;))");

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->contents.size(), 2u);
    EXPECT_EQ(result->contents[1].distance, 4);
    EXPECT_EQ(result->contents[1].within, 20);
}

TEST(SnortRuleParser, parse_negatedContent_setsNegated) {
    infra::SnortRuleParser parser;

    auto result = parser.parse(
        R"(alert tcp any any -> any any (msg:"T"; content:!"SAFE"; sid:1; rev:1;))");

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->contents.size(), 1u);
    EXPECT_TRUE(result->contents[0].negated);
}

TEST(SnortRuleParser, parse_pcreOption_extractsPattern) {
    infra::SnortRuleParser parser;

    auto result = parser.parse(
        R"(alert tcp any any -> any any (msg:"T"; pcre:"/password\s*=/i"; sid:1; rev:1;))");

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->pcres.size(), 1u);
    EXPECT_EQ(result->pcres[0].pattern, "password\\s*=");
    EXPECT_EQ(result->pcres[0].modifiers, "i");
}

TEST(SnortRuleParser, parse_flowOption_extractsKeywords) {
    infra::SnortRuleParser parser;

    auto result = parser.parse(
        R"(alert tcp any any -> any any (msg:"T"; flow:established,to_server; sid:1; rev:1;))");

    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->flow.has_value());
    EXPECT_TRUE(result->flow->established);
    EXPECT_EQ(result->flow->direction,
              core::SnortRule::FlowOption::Direction::ToServer);
}

TEST(SnortRuleParser, parse_flowbitsOption_parsesSetCommand) {
    infra::SnortRuleParser parser;

    auto result = parser.parse(
        R"(alert tcp any any -> any any (msg:"T"; flowbits:set,login_attempt; sid:1; rev:1;))");

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->flowbits.size(), 1u);
    EXPECT_EQ(result->flowbits[0].command,
              core::SnortRule::FlowbitsOption::Command::Set);
    EXPECT_EQ(result->flowbits[0].name, "login_attempt");
}

TEST(SnortRuleParser, parse_thresholdOption_extractsParams) {
    infra::SnortRuleParser parser;

    auto result = parser.parse(
        R"(alert tcp any any -> any any (msg:"T"; threshold:type limit, track by_src, count 5, seconds 60; sid:1; rev:1;))");

    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->threshold.has_value());
    EXPECT_EQ(result->threshold->type,
              core::SnortRule::ThresholdOption::Type::Limit);
    EXPECT_EQ(result->threshold->track,
              core::SnortRule::ThresholdOption::Track::BySrc);
    EXPECT_EQ(result->threshold->count, 5);
    EXPECT_EQ(result->threshold->seconds, 60);
}

TEST(SnortRuleParser, parse_references_extracted) {
    infra::SnortRuleParser parser;

    auto result = parser.parse(
        R"(alert tcp any any -> any any (msg:"T"; reference:cve,2024-1234; reference:url,example.com; sid:1; rev:1;))");

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->references.size(), 2u);
    EXPECT_EQ(result->references[0].first, "cve");
    EXPECT_EQ(result->references[0].second, "2024-1234");
}

TEST(SnortRuleParser, parse_commentLine_returnsError) {
    infra::SnortRuleParser parser;
    auto result = parser.parse("# This is a comment");
    EXPECT_FALSE(result.has_value());
}

TEST(SnortRuleParser, parse_emptyLine_returnsError) {
    infra::SnortRuleParser parser;
    auto result = parser.parse("");
    EXPECT_FALSE(result.has_value());
}

TEST(SnortRuleParser, parse_malformedRule_returnsError) {
    infra::SnortRuleParser parser;
    auto result = parser.parse("this is not a valid rule");
    EXPECT_FALSE(result.has_value());
}

TEST(SnortRuleParser, parse_udpProtocol_setsProtocol17) {
    infra::SnortRuleParser parser;

    auto result = parser.parse(
        R"(alert udp any any -> any 53 (msg:"DNS"; sid:1; rev:1;))");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->protocol, 17);
}

TEST(SnortRuleParser, parse_icmpProtocol_setsProtocol1) {
    infra::SnortRuleParser parser;

    auto result = parser.parse(
        R"(alert icmp any any -> any any (msg:"ICMP"; sid:1; rev:1;))");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->protocol, 1);
}

TEST(SnortRuleParser, parse_dropAction_setsAction) {
    infra::SnortRuleParser parser;

    auto result = parser.parse(
        R"(drop tcp any any -> any any (msg:"Drop"; sid:1; rev:1;))");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->action, core::SnortRule::Action::Drop);
}

TEST(SnortRuleParser, parseFile_loadsTestRules) {
    auto path = findTestRules();
    if (path.empty()) GTEST_SKIP() << "Test rules not found";

    infra::SnortRuleParser parser;
    auto rules = parser.parseFile(path);

    EXPECT_GT(rules.size(), 5u);
    EXPECT_GT(parser.lastStats().parsedRules, 5u);
}
