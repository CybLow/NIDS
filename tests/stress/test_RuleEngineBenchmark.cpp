#include "StressTestHelpers.h"

#ifdef NIDS_HAS_SIGNATURES
#include "infra/rules/SnortRuleEngine.h"
#include "infra/rules/SnortRuleParser.h"
#endif

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace nids;
using namespace nids::test;

namespace fs = std::filesystem;

#ifdef NIDS_HAS_SIGNATURES

namespace {

/// Generate a synthetic Snort rules file with N rules.
/// Each rule has unique SID and a random content pattern.
fs::path generateRulesFile(std::size_t ruleCount, const std::string& name) {
    auto path = fs::temp_directory_path() / name;
    std::ofstream out(path);

    for (std::size_t i = 0; i < ruleCount; ++i) {
        // Generate a unique content string per rule.
        auto pattern = "BENCH_PATTERN_" + std::to_string(i);
        auto sid = 9000000 + i;

        out << "alert tcp any any -> any any ("
            << "msg:\"Benchmark rule " << i << "\"; "
            << "content:\"" << pattern << "\"; "
            << "sid:" << sid << "; rev:1; "
            << "classtype:misc-attack; priority:3;)\n";
    }

    return path;
}

core::FlowInfo makeFlow() {
    core::FlowInfo f;
    f.srcIp = "10.0.0.1";
    f.dstIp = "192.168.1.1";
    f.srcPort = 54321;
    f.dstPort = 80;
    f.protocol = 6;
    return f;
}

} // namespace

TEST(RuleEngineBenchmark, parse_1000Rules_under1Second) {
    auto path = generateRulesFile(1000, "bench_1k.rules");

    double elapsedMs = 0;
    {
        ScopedTimer timer(elapsedMs);
        infra::SnortRuleParser parser;
        auto rules = parser.parseFile(path);
        EXPECT_EQ(rules.size(), 1000u);
    }

    EXPECT_LT(elapsedMs, 1000.0)
        << "Parsing 1K rules took " << elapsedMs << " ms";
    fs::remove(path);
}

TEST(RuleEngineBenchmark, parse_10000Rules_under5Seconds) {
    auto path = generateRulesFile(10000, "bench_10k.rules");

    double elapsedMs = 0;
    {
        ScopedTimer timer(elapsedMs);
        infra::SnortRuleParser parser;
        auto rules = parser.parseFile(path);
        EXPECT_EQ(rules.size(), 10000u);
    }

    EXPECT_LT(elapsedMs, 5000.0)
        << "Parsing 10K rules took " << elapsedMs << " ms";
    fs::remove(path);
}

TEST(RuleEngineBenchmark, load_10000Rules_engineIndexing) {
    auto path = generateRulesFile(10000, "bench_engine_10k.rules");

    double elapsedMs = 0;
    {
        ScopedTimer timer(elapsedMs);
        infra::SnortRuleEngine engine;
        EXPECT_TRUE(engine.loadRules(path));
        EXPECT_EQ(engine.ruleCount(), 10000u);
    }

    EXPECT_LT(elapsedMs, 10000.0)
        << "Loading 10K rules took " << elapsedMs << " ms";
    fs::remove(path);
}

TEST(RuleEngineBenchmark, inspect_10000Rules_throughput) {
    auto path = generateRulesFile(10000, "bench_inspect_10k.rules");

    infra::SnortRuleEngine engine;
    ASSERT_TRUE(engine.loadRules(path));

    auto flow = makeFlow();
    std::vector<std::uint8_t> payload(256, 0x41); // 'AAAA...'
    const int iterations = 100;
    double elapsedMs = 0;
    {
        ScopedTimer timer(elapsedMs);
        for (int i = 0; i < iterations; ++i) {
            [[maybe_unused]] auto matches = engine.inspect(payload, flow);
        }
    }

    double inspectionsPerSec = static_cast<double>(iterations) /
                                (elapsedMs / 1000.0);
    // Should sustain at least 100 inspections/sec with 10K rules (debug).
    EXPECT_GT(inspectionsPerSec, 100.0)
        << "Throughput: " << inspectionsPerSec << " inspections/sec";

    fs::remove(path);
}

TEST(RuleEngineBenchmark, inspect_matchingPayload_findsRule) {
    auto path = generateRulesFile(5000, "bench_match_5k.rules");

    infra::SnortRuleEngine engine;
    ASSERT_TRUE(engine.loadRules(path));

    // Create a payload that matches rule #2500.
    std::string pattern = "BENCH_PATTERN_2500";
    std::vector<std::uint8_t> payload(pattern.begin(), pattern.end());
    auto flow = makeFlow();

    auto matches = engine.inspect(payload, flow);
    EXPECT_GE(matches.size(), 1u);

    bool found = false;
    for (const auto& m : matches) {
        if (m.sid == 9002500) found = true;
    }
    EXPECT_TRUE(found);

    fs::remove(path);
}

TEST(RuleEngineBenchmark, memory_10000Rules_bounded) {
    auto rssBefore = currentRssKb();
    auto path = generateRulesFile(10000, "bench_mem_10k.rules");

    infra::SnortRuleEngine engine;
    ASSERT_TRUE(engine.loadRules(path));

    auto rssAfter = currentRssKb();
    auto growthMb = static_cast<double>(rssAfter - rssBefore) / 1024.0;

    // 10K rules should use less than 50 MB.
    EXPECT_LT(growthMb, 50.0)
        << "Memory usage for 10K rules: " << growthMb << " MB";

    fs::remove(path);
}

#else

TEST(RuleEngineBenchmark, DISABLED_skipped_no_signatures) {
    GTEST_SKIP() << "NIDS_ENABLE_SIGNATURES not enabled";
}

#endif // NIDS_HAS_SIGNATURES
