#include "infra/rules/RuleVariableStore.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>

using namespace nids::infra;

TEST(RuleVariableStore, set_and_resolve_variable) {
    RuleVariableStore store;
    store.set("HOME_NET", "192.168.0.0/16");

    EXPECT_EQ(store.resolve("$HOME_NET"), "192.168.0.0/16");
}

TEST(RuleVariableStore, resolve_nonVariable_returnsAsIs) {
    RuleVariableStore store;
    EXPECT_EQ(store.resolve("192.168.1.1"), "192.168.1.1");
    EXPECT_EQ(store.resolve("any"), "any");
}

TEST(RuleVariableStore, resolve_unknownVariable_returnsAsIs) {
    RuleVariableStore store;
    EXPECT_EQ(store.resolve("$UNKNOWN"), "$UNKNOWN");
}

TEST(RuleVariableStore, set_stripsLeadingDollar) {
    RuleVariableStore store;
    store.set("$HOME_NET", "10.0.0.0/8");
    EXPECT_EQ(store.resolve("$HOME_NET"), "10.0.0.0/8");
}

TEST(RuleVariableStore, ipMatches_any_matchesEverything) {
    RuleVariableStore store;
    EXPECT_TRUE(store.ipMatches("10.0.0.1", "any"));
    EXPECT_TRUE(store.ipMatches("192.168.1.1", "any"));
}

TEST(RuleVariableStore, ipMatches_exactMatch) {
    RuleVariableStore store;
    EXPECT_TRUE(store.ipMatches("10.0.0.1", "10.0.0.1"));
    EXPECT_FALSE(store.ipMatches("10.0.0.2", "10.0.0.1"));
}

TEST(RuleVariableStore, ipMatches_negation) {
    RuleVariableStore store;
    EXPECT_FALSE(store.ipMatches("10.0.0.1", "!10.0.0.1"));
    EXPECT_TRUE(store.ipMatches("10.0.0.2", "!10.0.0.1"));
}

TEST(RuleVariableStore, ipMatches_commaGroup) {
    RuleVariableStore store;
    EXPECT_TRUE(store.ipMatches("10.0.0.1", "10.0.0.1,192.168.1.1"));
    EXPECT_TRUE(store.ipMatches("192.168.1.1", "10.0.0.1,192.168.1.1"));
    EXPECT_FALSE(store.ipMatches("172.16.0.1", "10.0.0.1,192.168.1.1"));
}

TEST(RuleVariableStore, ipMatches_bracketGroup) {
    RuleVariableStore store;
    EXPECT_TRUE(store.ipMatches("10.0.0.1", "[10.0.0.1,192.168.1.1]"));
}

TEST(RuleVariableStore, ipMatches_variableResolution) {
    RuleVariableStore store;
    store.set("HOME_NET", "10.0.0.1");
    EXPECT_TRUE(store.ipMatches("10.0.0.1", "$HOME_NET"));
    EXPECT_FALSE(store.ipMatches("10.0.0.2", "$HOME_NET"));
}

TEST(RuleVariableStore, portMatches_any_matchesAll) {
    RuleVariableStore store;
    EXPECT_TRUE(store.portMatches(80, "any"));
    EXPECT_TRUE(store.portMatches(443, "any"));
}

TEST(RuleVariableStore, portMatches_exactPort) {
    RuleVariableStore store;
    EXPECT_TRUE(store.portMatches(80, "80"));
    EXPECT_FALSE(store.portMatches(443, "80"));
}

TEST(RuleVariableStore, portMatches_commaGroup) {
    RuleVariableStore store;
    EXPECT_TRUE(store.portMatches(80, "80,443,8080"));
    EXPECT_TRUE(store.portMatches(443, "80,443,8080"));
    EXPECT_FALSE(store.portMatches(22, "80,443,8080"));
}

TEST(RuleVariableStore, portMatches_bracketGroup) {
    RuleVariableStore store;
    EXPECT_TRUE(store.portMatches(80, "[80,443]"));
    EXPECT_FALSE(store.portMatches(22, "[80,443]"));
}

TEST(RuleVariableStore, portMatches_range) {
    RuleVariableStore store;
    EXPECT_TRUE(store.portMatches(1024, "1024:2048"));
    EXPECT_TRUE(store.portMatches(2048, "1024:2048"));
    EXPECT_FALSE(store.portMatches(80, "1024:2048"));
}

TEST(RuleVariableStore, portMatches_rangeOpenEnd) {
    RuleVariableStore store;
    EXPECT_TRUE(store.portMatches(50000, "1024:"));
    EXPECT_FALSE(store.portMatches(80, "1024:"));
}

TEST(RuleVariableStore, portMatches_rangeOpenStart) {
    RuleVariableStore store;
    EXPECT_TRUE(store.portMatches(80, ":1024"));
    EXPECT_FALSE(store.portMatches(2000, ":1024"));
}

TEST(RuleVariableStore, portMatches_negation) {
    RuleVariableStore store;
    EXPECT_FALSE(store.portMatches(80, "!80"));
    EXPECT_TRUE(store.portMatches(443, "!80"));
}

TEST(RuleVariableStore, portMatches_variableResolution) {
    RuleVariableStore store;
    store.set("HTTP_PORTS", "80,443,8080");
    EXPECT_TRUE(store.portMatches(80, "$HTTP_PORTS"));
    EXPECT_TRUE(store.portMatches(443, "$HTTP_PORTS"));
    EXPECT_FALSE(store.portMatches(22, "$HTTP_PORTS"));
}

TEST(RuleVariableStore, resolve_emptyInput_returnsEmpty) {
    RuleVariableStore store;
    EXPECT_EQ(store.resolve(""), "");
}
