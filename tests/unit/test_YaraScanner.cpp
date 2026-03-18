#include "infra/rules/YaraScanner.h"

#include "core/model/ContentMatch.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace nids;
namespace fs = std::filesystem;

namespace {

/// Path to the test YARA rules (relative to the build directory).
/// CI and local builds may differ, so we search upward.
[[nodiscard]] fs::path findTestRules() {
    // Try relative paths from common build directories.
    for (const auto& base : {".", "..", "../.."}) {
        auto p = fs::path(base) / "tests" / "data" / "test_rules.yar";
        if (fs::exists(p)) return fs::canonical(p);
    }
    // Fallback: absolute from source tree.
    auto p = fs::path(NIDS_SOURCE_DIR) / "tests" / "data" / "test_rules.yar";
    if (fs::exists(p)) return p;
    return {};
}

/// Helper to create a byte vector from a string.
[[nodiscard]] std::vector<std::uint8_t> toBytes(const std::string& s) {
    return {s.begin(), s.end()};
}

} // namespace

class YaraScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
        rulesPath_ = findTestRules();
        if (rulesPath_.empty()) {
            GTEST_SKIP() << "Test YARA rules not found";
        }
    }

    fs::path rulesPath_;
};

TEST_F(YaraScannerTest, loadRules_validFile_succeeds) {
    infra::YaraScanner scanner;
    EXPECT_TRUE(scanner.loadRules(rulesPath_));
    EXPECT_GT(scanner.ruleCount(), 0u);
    EXPECT_EQ(scanner.fileCount(), 1u);
}

TEST_F(YaraScannerTest, scan_matchingPattern_returnsMatch) {
    infra::YaraScanner scanner;
    ASSERT_TRUE(scanner.loadRules(rulesPath_));

    auto data = toBytes("some prefix NIDS_TEST_PAYLOAD some suffix");
    auto matches = scanner.scan(data);

    ASSERT_GE(matches.size(), 1u);

    bool found = false;
    for (const auto& m : matches) {
        if (m.ruleName == "NIDS_Test_Simple") {
            found = true;
            EXPECT_EQ(m.description, "Simple test pattern");
            EXPECT_FLOAT_EQ(m.severity, 0.5f);
            EXPECT_FALSE(m.strings.empty());
        }
    }
    EXPECT_TRUE(found) << "NIDS_Test_Simple rule did not match";
}

TEST_F(YaraScannerTest, scan_hexPattern_returnsMatch) {
    infra::YaraScanner scanner;
    ASSERT_TRUE(scanner.loadRules(rulesPath_));

    std::vector<std::uint8_t> data = {
        0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF, 0x02, 0x03};
    auto matches = scanner.scan(data);

    bool found = false;
    for (const auto& m : matches) {
        if (m.ruleName == "NIDS_Test_Hex") {
            found = true;
            EXPECT_FLOAT_EQ(m.severity, 0.8f);
        }
    }
    EXPECT_TRUE(found) << "NIDS_Test_Hex rule did not match";
}

TEST_F(YaraScannerTest, scan_multipleStrings_matchesBoth) {
    infra::YaraScanner scanner;
    ASSERT_TRUE(scanner.loadRules(rulesPath_));

    auto data = toBytes("ALPHA_MARKER some data BETA_MARKER");
    auto matches = scanner.scan(data);

    bool found = false;
    for (const auto& m : matches) {
        if (m.ruleName == "NIDS_Test_Multiple") {
            found = true;
            EXPECT_GE(m.strings.size(), 2u);
        }
    }
    EXPECT_TRUE(found) << "NIDS_Test_Multiple rule did not match";
}

TEST_F(YaraScannerTest, scan_nonMatchingData_returnsEmpty) {
    infra::YaraScanner scanner;
    ASSERT_TRUE(scanner.loadRules(rulesPath_));

    auto data = toBytes("completely normal traffic data with nothing suspicious");
    auto matches = scanner.scan(data);

    // None of the test rules should match.
    EXPECT_TRUE(matches.empty());
}

TEST_F(YaraScannerTest, scan_emptyData_returnsEmpty) {
    infra::YaraScanner scanner;
    ASSERT_TRUE(scanner.loadRules(rulesPath_));

    std::span<const std::uint8_t> empty;
    auto matches = scanner.scan(empty);

    EXPECT_TRUE(matches.empty());
}

TEST_F(YaraScannerTest, scan_noRulesLoaded_returnsEmpty) {
    infra::YaraScanner scanner;
    // Don't load any rules.

    auto data = toBytes("NIDS_TEST_PAYLOAD");
    auto matches = scanner.scan(data);

    EXPECT_TRUE(matches.empty());
}

TEST_F(YaraScannerTest, scan_stringMatchOffset_isCorrect) {
    infra::YaraScanner scanner;
    ASSERT_TRUE(scanner.loadRules(rulesPath_));

    std::string prefix = "AAAA"; // 4 bytes
    std::string payload = "NIDS_TEST_PAYLOAD";
    auto data = toBytes(prefix + payload);
    auto matches = scanner.scan(data);

    for (const auto& m : matches) {
        if (m.ruleName == "NIDS_Test_Simple" && !m.strings.empty()) {
            EXPECT_EQ(m.strings[0].offset, 4u);
            EXPECT_EQ(m.strings[0].length, payload.size());
        }
    }
}

TEST_F(YaraScannerTest, scan_withTimeout_completesNormally) {
    infra::YaraScanner scanner;
    ASSERT_TRUE(scanner.loadRules(rulesPath_));

    auto data = toBytes("NIDS_TEST_PAYLOAD");
    auto matches = scanner.scan(data, 1000); // 1 second timeout

    EXPECT_GE(matches.size(), 1u);
}

TEST_F(YaraScannerTest, reloadRules_recompilesSuccessfully) {
    infra::YaraScanner scanner;
    ASSERT_TRUE(scanner.loadRules(rulesPath_));
    auto countBefore = scanner.ruleCount();

    EXPECT_TRUE(scanner.reloadRules());
    EXPECT_EQ(scanner.ruleCount(), countBefore);
}

TEST_F(YaraScannerTest, loadRules_nonexistentPath_returnsFalse) {
    infra::YaraScanner scanner;
    EXPECT_FALSE(scanner.loadRules("/nonexistent/path/rules.yar"));
    EXPECT_EQ(scanner.ruleCount(), 0u);
}

TEST_F(YaraScannerTest, loadRules_directory_loadsAllYarFiles) {
    auto dir = rulesPath_.parent_path();
    infra::YaraScanner scanner;
    EXPECT_TRUE(scanner.loadRules(dir));
    EXPECT_GT(scanner.ruleCount(), 0u);
}

TEST_F(YaraScannerTest, scan_extractsMetadata) {
    infra::YaraScanner scanner;
    ASSERT_TRUE(scanner.loadRules(rulesPath_));

    auto data = toBytes("NIDS_TEST_PAYLOAD");
    auto matches = scanner.scan(data);

    for (const auto& m : matches) {
        if (m.ruleName == "NIDS_Test_Simple") {
            // Should have metadata entries.
            EXPECT_FALSE(m.metadata.empty());
            bool hasCategoryMeta = false;
            for (const auto& [key, value] : m.metadata) {
                if (key == "category" && value == "test") {
                    hasCategoryMeta = true;
                }
            }
            EXPECT_TRUE(hasCategoryMeta);
        }
    }
}

TEST_F(YaraScannerTest, moveConstruction_transfersState) {
    infra::YaraScanner scanner1;
    ASSERT_TRUE(scanner1.loadRules(rulesPath_));
    auto count = scanner1.ruleCount();

    infra::YaraScanner scanner2(std::move(scanner1));
    EXPECT_EQ(scanner2.ruleCount(), count);
}
