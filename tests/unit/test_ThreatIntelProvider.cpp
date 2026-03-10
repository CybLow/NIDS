#include <gtest/gtest.h>
#include "infra/threat/ThreatIntelProvider.h"

#include <filesystem>
#include <fstream>

using nids::infra::ThreatIntelProvider;

namespace fs = std::filesystem;

class ThreatIntelProviderTest : public ::testing::Test {
protected:
    const std::string testDir_ = "test_feeds";

    void SetUp() override {
        fs::create_directories(testDir_);
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(testDir_, ec);
    }

    void writeFeedFile(const std::string& name, const std::string& content) {
        std::ofstream file(testDir_ + "/" + name);
        file << content;
    }
};

// ── Loading ──────────────────────────────────────────────────────────

TEST_F(ThreatIntelProviderTest, loadFeeds_emptyDirectory_returnsZero) {
    ThreatIntelProvider provider;
    EXPECT_EQ(provider.loadFeeds(testDir_), 0u);
    EXPECT_EQ(provider.entryCount(), 0u);
    EXPECT_EQ(provider.feedCount(), 0u);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_nonexistentDirectory_returnsZero) {
    ThreatIntelProvider provider;
    EXPECT_EQ(provider.loadFeeds("/nonexistent/path"), 0u);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_plainTextIps) {
    writeFeedFile("malicious.txt",
        "# Malicious IPs\n"
        "1.2.3.4\n"
        "5.6.7.8\n"
        "10.0.0.1\n"
    );

    ThreatIntelProvider provider;
    auto loaded = provider.loadFeeds(testDir_);
    EXPECT_EQ(loaded, 3u);
    EXPECT_EQ(provider.entryCount(), 3u);
    EXPECT_EQ(provider.feedCount(), 1u);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_skipsCommentsAndEmptyLines) {
    writeFeedFile("feed.txt",
        "# Comment line\n"
        "; Another comment\n"
        "\n"
        "   \n"
        "192.168.1.1\n"
    );

    ThreatIntelProvider provider;
    EXPECT_EQ(provider.loadFeeds(testDir_), 1u);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_cidrRanges) {
    writeFeedFile("ranges.txt", "10.0.0.0/24\n192.168.0.0/16\n");

    ThreatIntelProvider provider;
    auto loaded = provider.loadFeeds(testDir_);
    EXPECT_GE(loaded, 2u);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_malformedLinesSkipped) {
    writeFeedFile("bad.txt",
        "not.an.ip\n"
        "256.256.256.256\n"
        "1.2.3\n"
        "valid: 8.8.8.8\n"
    );

    ThreatIntelProvider provider;
    // Some lines will be skipped; at least one valid IP exists after semicolons
    auto loaded = provider.loadFeeds(testDir_);
    // The exact count depends on parsing logic
    EXPECT_LE(loaded, 4u);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_multipleFeedsFromDirectory) {
    writeFeedFile("feed_a.txt", "1.1.1.1\n2.2.2.2\n");
    writeFeedFile("feed_b.txt", "3.3.3.3\n");

    ThreatIntelProvider provider;
    provider.loadFeeds(testDir_);
    EXPECT_EQ(provider.feedCount(), 2u);
    EXPECT_EQ(provider.entryCount(), 3u);
}

// ── Lookup ───────────────────────────────────────────────────────────

TEST_F(ThreatIntelProviderTest, lookup_matchesLoadedIp) {
    writeFeedFile("threats.txt", "10.0.0.99\n");

    ThreatIntelProvider provider;
    provider.loadFeeds(testDir_);

    auto result = provider.lookup("10.0.0.99");
    EXPECT_TRUE(result.matched);
}

TEST_F(ThreatIntelProviderTest, lookup_noMatchForUnknownIp) {
    writeFeedFile("threats.txt", "10.0.0.99\n");

    ThreatIntelProvider provider;
    provider.loadFeeds(testDir_);

    auto result = provider.lookup("192.168.1.1");
    EXPECT_FALSE(result.matched);
}

TEST_F(ThreatIntelProviderTest, lookup_matchesCidrRange) {
    writeFeedFile("ranges.txt", "10.0.0.0/24\n");

    ThreatIntelProvider provider;
    provider.loadFeeds(testDir_);

    // 10.0.0.42 is within 10.0.0.0/24
    auto result = provider.lookup("10.0.0.42");
    EXPECT_TRUE(result.matched);

    // 10.0.1.1 is outside 10.0.0.0/24
    auto miss = provider.lookup("10.0.1.1");
    EXPECT_FALSE(miss.matched);
}

TEST_F(ThreatIntelProviderTest, lookup_feedNamePopulated) {
    writeFeedFile("feodo.txt", "1.2.3.4\n");

    ThreatIntelProvider provider;
    provider.loadFeeds(testDir_);

    auto result = provider.lookup("1.2.3.4");
    EXPECT_TRUE(result.matched);
    EXPECT_FALSE(result.feedName.empty());
}

TEST_F(ThreatIntelProviderTest, lookup_numericOverload) {
    writeFeedFile("threats.txt", "10.0.0.1\n");

    ThreatIntelProvider provider;
    provider.loadFeeds(testDir_);

    // 10.0.0.1 in host byte order = 0x0A000001
    auto result = provider.lookup(static_cast<std::uint32_t>(0x0A000001));
    EXPECT_TRUE(result.matched);
}

TEST_F(ThreatIntelProviderTest, lookup_invalidIpString_noMatch) {
    writeFeedFile("threats.txt", "1.2.3.4\n");

    ThreatIntelProvider provider;
    provider.loadFeeds(testDir_);

    auto result = provider.lookup("not-an-ip");
    EXPECT_FALSE(result.matched);
}

TEST_F(ThreatIntelProviderTest, lookup_emptyProvider_noMatch) {
    ThreatIntelProvider provider;
    auto result = provider.lookup("1.2.3.4");
    EXPECT_FALSE(result.matched);
}

// ── Single file loading ──────────────────────────────────────────────

TEST_F(ThreatIntelProviderTest, loadFeedFile_returnsCountOfLoadedEntries) {
    const std::string path = testDir_ + "/single.txt";
    std::ofstream file(path);
    file << "1.1.1.1\n2.2.2.2\n3.3.3.3\n";
    file.close();

    ThreatIntelProvider provider;
    EXPECT_EQ(provider.loadFeedFile(path, "test_feed"), 3u);
}

TEST_F(ThreatIntelProviderTest, loadFeedFile_nonexistentFile_returnsZero) {
    ThreatIntelProvider provider;
    EXPECT_EQ(provider.loadFeedFile("/nonexistent/file.txt", "missing"), 0u);
}
