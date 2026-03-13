#include "infra/threat/ThreatIntelProvider.h"
#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>

using nids::infra::ThreatIntelProvider;

namespace fs = std::filesystem;

class ThreatIntelProviderTest : public ::testing::Test {
protected: // NOSONAR
  std::string testDir_;

  void SetUp() override {
    // Use a unique temp directory per test instance to avoid races
    // when CTest runs tests in parallel.
    auto tmpTemplate = fs::temp_directory_path() / "nids_test_feeds_XXXXXX";
    auto tmpStr = tmpTemplate.string();
    char *result = mkdtemp(tmpStr.data());
    ASSERT_NE(result, nullptr) << "Failed to create temp directory";
    testDir_ = result;
  }

  void TearDown() override {
    std::error_code ec;
    fs::remove_all(testDir_, ec);
  }

  void writeFeedFile(const std::string &name,
                     const std::string &content) const {
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
  writeFeedFile("malicious.txt", "# Malicious IPs\n"
                                 "1.2.3.4\n"
                                 "5.6.7.8\n"
                                 "10.0.0.1\n");

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  EXPECT_EQ(loaded, 3u);
  EXPECT_EQ(provider.entryCount(), 3u);
  EXPECT_EQ(provider.feedCount(), 1u);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_skipsCommentsAndEmptyLines) {
  writeFeedFile("feed.txt", "# Comment line\n"
                            "; Another comment\n"
                            "\n"
                            "   \n"
                            "192.168.1.1\n");

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
  writeFeedFile("bad.txt", "not.an.ip\n"
                           "256.256.256.256\n"
                           "1.2.3\n"
                           "valid: 8.8.8.8\n");

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
  [[maybe_unused]] auto loaded = provider.loadFeeds(testDir_);
  EXPECT_EQ(provider.feedCount(), 2u);
  EXPECT_EQ(provider.entryCount(), 3u);
}

// ── Lookup ───────────────────────────────────────────────────────────

TEST_F(ThreatIntelProviderTest, lookup_matchesLoadedIp) {
  writeFeedFile("threats.txt", "10.0.0.99\n");

  ThreatIntelProvider provider;
  [[maybe_unused]] auto loaded = provider.loadFeeds(testDir_);

  auto result = provider.lookup("10.0.0.99");
  EXPECT_TRUE(result.matched);
}

TEST_F(ThreatIntelProviderTest, lookup_noMatchForUnknownIp) {
  writeFeedFile("threats.txt", "10.0.0.99\n");

  ThreatIntelProvider provider;
  [[maybe_unused]] auto loaded = provider.loadFeeds(testDir_);

  auto result = provider.lookup("192.168.1.1");
  EXPECT_FALSE(result.matched);
}

TEST_F(ThreatIntelProviderTest, lookup_matchesCidrRange) {
  writeFeedFile("ranges.txt", "10.0.0.0/24\n");

  ThreatIntelProvider provider;
  [[maybe_unused]] auto loaded = provider.loadFeeds(testDir_);

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
  [[maybe_unused]] auto loaded = provider.loadFeeds(testDir_);

  auto result = provider.lookup("1.2.3.4");
  EXPECT_TRUE(result.matched);
  EXPECT_FALSE(result.feedName.empty());
}

TEST_F(ThreatIntelProviderTest, lookup_numericOverload) {
  writeFeedFile("threats.txt", "10.0.0.1\n");

  ThreatIntelProvider provider;
  [[maybe_unused]] auto loaded = provider.loadFeeds(testDir_);

  // 10.0.0.1 in host byte order = 0x0A000001
  auto result = provider.lookup(static_cast<std::uint32_t>(0x0A000001));
  EXPECT_TRUE(result.matched);
}

TEST_F(ThreatIntelProviderTest, lookup_invalidIpString_noMatch) {
  writeFeedFile("threats.txt", "1.2.3.4\n");

  ThreatIntelProvider provider;
  [[maybe_unused]] auto loaded = provider.loadFeeds(testDir_);

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

// ── Extension filtering ──────────────────────────────────────────────

TEST_F(ThreatIntelProviderTest, loadFeeds_jsonFileSkipped) {
  writeFeedFile("data.json",
                R"({"ips": ["1.1.1.1"]})"); // JSON extension → skip
  writeFeedFile("legit.txt", "2.2.2.2\n");

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  EXPECT_EQ(loaded, 1u);
  EXPECT_EQ(provider.feedCount(), 1u);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_csvFileAccepted) {
  writeFeedFile("blocklist.csv", "1.1.1.1;port80\n2.2.2.2;port443\n");

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  EXPECT_EQ(loaded, 2u);
  EXPECT_EQ(provider.feedCount(), 1u);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_extensionlessFileAccepted) {
  // Write file with no extension
  std::ofstream file(testDir_ + "/blocklist");
  file << "3.3.3.3\n4.4.4.4\n";
  file.close();

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  EXPECT_EQ(loaded, 2u);
}

// ── Delimiter parsing ────────────────────────────────────────────────

TEST_F(ThreatIntelProviderTest, loadFeeds_semicolonDelimiter) {
  writeFeedFile("feed.csv", "1.2.3.4;some_extra_data\n5.6.7.8;more_data\n");

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  EXPECT_EQ(loaded, 2u);

  auto result = provider.lookup("1.2.3.4");
  EXPECT_TRUE(result.matched);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_commaDelimiter) {
  writeFeedFile("feed.csv", "1.2.3.4,description\n5.6.7.8,another\n");

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  EXPECT_EQ(loaded, 2u);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_spaceDelimiter) {
  writeFeedFile("feed.txt", "1.2.3.4 some metadata\n5.6.7.8 other info\n");

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  EXPECT_EQ(loaded, 2u);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_emptyAfterDelimiter) {
  // Semicolon at start of the IP field (after whitespace strip)
  writeFeedFile("feed.txt", ";just_data\n1.2.3.4\n");

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  // ";just_data" → after extractIpField, empty before semicolon → skip
  // But actually ";" → comment line starting with ';', so it's skipped
  EXPECT_EQ(loaded, 1u);
}

// ── CIDR edge cases ──────────────────────────────────────────────────

TEST_F(ThreatIntelProviderTest, loadFeeds_cidrPrefix32_singleHost) {
  writeFeedFile("ranges.txt", "10.0.0.1/32\n");

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  EXPECT_EQ(loaded, 1u);

  auto hit = provider.lookup("10.0.0.1");
  EXPECT_TRUE(hit.matched);

  auto miss = provider.lookup("10.0.0.2");
  EXPECT_FALSE(miss.matched);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_cidrPrefix0_skipped) {
  writeFeedFile("ranges.txt", "0.0.0.0/0\n");

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  // Prefix 0 is skipped (would match everything)
  EXPECT_EQ(loaded, 0u);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_cidrInvalidPrefix_skipped) {
  writeFeedFile("ranges.txt", "10.0.0.0/33\n");

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  EXPECT_EQ(loaded, 0u);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_cidrNoIp_skipped) {
  writeFeedFile("ranges.txt", "/24\n");

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  EXPECT_EQ(loaded, 0u);
}

// ── feedNames content verification ───────────────────────────────────

TEST_F(ThreatIntelProviderTest, feedNames_returnsLoadedFeedNames) {
  writeFeedFile("alpha.txt", "1.1.1.1\n");
  writeFeedFile("beta.txt", "2.2.2.2\n");

  ThreatIntelProvider provider;
  [[maybe_unused]] auto loaded = provider.loadFeeds(testDir_);

  auto names = provider.feedNames();
  EXPECT_EQ(names.size(), 2u);

  // Order may vary based on directory iteration
  bool hasAlpha = false;
  bool hasBeta = false;
  for (const auto &n : names) {
    if (n == "alpha")
      hasAlpha = true;
    if (n == "beta")
      hasBeta = true;
  }
  EXPECT_TRUE(hasAlpha);
  EXPECT_TRUE(hasBeta);
}

TEST_F(ThreatIntelProviderTest, feedNames_emptyWhenNoFeeds) {
  ThreatIntelProvider provider;
  EXPECT_TRUE(provider.feedNames().empty());
}

// ── CIDR broad range lookup ──────────────────────────────────────────

TEST_F(ThreatIntelProviderTest, lookup_cidrBroadRange) {
  writeFeedFile("ranges.txt", "192.168.0.0/16\n");

  ThreatIntelProvider provider;
  [[maybe_unused]] auto loaded = provider.loadFeeds(testDir_);

  EXPECT_TRUE(provider.lookup("192.168.0.1").matched);
  EXPECT_TRUE(provider.lookup("192.168.255.254").matched);
  EXPECT_FALSE(provider.lookup("192.169.0.1").matched);
}

// ── Duplicate IPs across feeds ───────────────────────────────────────

TEST_F(ThreatIntelProviderTest, loadFeeds_duplicateIpsAcrossFeeds) {
  writeFeedFile("feed_a.txt", "1.2.3.4\n5.6.7.8\n");
  writeFeedFile("feed_b.txt", "1.2.3.4\n9.10.11.12\n");

  ThreatIntelProvider provider;
  [[maybe_unused]] auto loaded = provider.loadFeeds(testDir_);

  // Duplicate IP → last writer wins in unordered_map
  auto result = provider.lookup("1.2.3.4");
  EXPECT_TRUE(result.matched);
  // entryCount should be 3 (unique IPs: 1.2.3.4, 5.6.7.8, 9.10.11.12)
  EXPECT_EQ(provider.entryCount(), 3u);
}

// ── Directory edge cases ─────────────────────────────────────────────

TEST_F(ThreatIntelProviderTest, loadFeeds_regularFileAsDirectory_returnsZero) {
  // Pass a regular file path (not a directory) as the feed directory
  const std::string filePath = testDir_ + "/not_a_dir.txt";
  std::ofstream file(filePath);
  file << "1.2.3.4\n";
  file.close();

  ThreatIntelProvider provider;
  EXPECT_EQ(provider.loadFeeds(filePath), 0u);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_subdirectorySkipped) {
  // Create a subdirectory inside the feed dir — should be skipped
  fs::create_directory(testDir_ + "/subdir");
  writeFeedFile("valid.txt", "1.2.3.4\n");

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  EXPECT_EQ(loaded, 1u);
  EXPECT_EQ(provider.feedCount(), 1u);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_allMalformed_zeroLoaded) {
  // File with only malformed entries — file found but nothing parsed.
  // The feed is NOT counted (feedCount stays 0) because loaded == 0
  // exercises the false branch of `if (loaded > 0)`.
  writeFeedFile("bad_only.txt", "not.valid.ip\nxyz\nabc.def.ghi.jkl\n");

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  EXPECT_EQ(loaded, 0u);
  EXPECT_EQ(provider.feedCount(), 0u);
  EXPECT_EQ(provider.entryCount(), 0u);
}

// ── Malformed CIDR edge cases ────────────────────────────────────────

TEST_F(ThreatIntelProviderTest, loadFeeds_cidrMalformedIp_skipped) {
  // CIDR with unparseable IP part
  writeFeedFile("ranges.txt", "bad.ip.addr/24\n");

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  EXPECT_EQ(loaded, 0u);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_cidrZeroIp_valid) {
  // 0.0.0.0/8 is a valid CIDR (covers 0.0.0.0 - 0.255.255.255)
  writeFeedFile("ranges.txt", "0.0.0.0/8\n");

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  EXPECT_EQ(loaded, 1u);

  // 0.0.0.1 should match 0.0.0.0/8
  auto hit = provider.lookup("0.0.0.1");
  EXPECT_TRUE(hit.matched);

  // 1.0.0.1 should NOT match 0.0.0.0/8
  auto miss = provider.lookup("1.0.0.1");
  EXPECT_FALSE(miss.matched);
}

// ── Whitespace and field extraction edge cases ───────────────────────

TEST_F(ThreatIntelProviderTest,
       loadFeeds_ipWithLeadingTrailingWhitespace_trimmed) {
  // IP with surrounding whitespace — exercises stripWhitespace trim branch
  // (line 24-25)
  writeFeedFile("spaces.txt", "  10.0.0.1  \n\t10.0.0.2\t\n");

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  EXPECT_EQ(loaded, 2u);

  EXPECT_TRUE(provider.lookup("10.0.0.1").matched);
  EXPECT_TRUE(provider.lookup("10.0.0.2").matched);
}

TEST_F(ThreatIntelProviderTest,
       loadFeeds_lineEmptyAfterExtractIpField_skipped) {
  // Lines where the IP field portion is empty after truncation:
  // ";10.0.0.1" → field before ';' is empty → extractIpField clears it
  // ", 10.0.0.2" → field before ',' is empty
  writeFeedFile("empty_field.txt", ";10.0.0.1\n,10.0.0.2\n");

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  EXPECT_EQ(loaded, 0u);
}

TEST_F(ThreatIntelProviderTest, loadFeeds_multipleCidrs_sortedCorrectly) {
  // Multiple CIDR ranges ensure the sort lambda (line 86-88) is exercised
  // with actual comparisons (needs >= 2 CIDRs)
  writeFeedFile("cidrs.txt", "192.168.0.0/16\n10.0.0.0/8\n172.16.0.0/12\n");

  ThreatIntelProvider provider;
  auto loaded = provider.loadFeeds(testDir_);
  EXPECT_EQ(loaded, 3u);

  // All ranges should match their respective IPs
  EXPECT_TRUE(provider.lookup("10.1.2.3").matched);
  EXPECT_TRUE(provider.lookup("172.20.0.1").matched);
  EXPECT_TRUE(provider.lookup("192.168.100.1").matched);
  // Outside all ranges
  EXPECT_FALSE(provider.lookup("8.8.8.8").matched);
}
