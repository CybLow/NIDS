#include "infra/platform/NetfilterBlocker.h"

#include <gtest/gtest.h>

#include <chrono>
#include <thread>

using namespace nids::infra;

namespace {
FlowKey makeKey(const std::string& src = "10.0.0.1",
                 const std::string& dst = "192.168.1.1",
                 std::uint16_t sp = 12345,
                 std::uint16_t dp = 80) {
    return {src, dst, sp, dp, 6};
}
} // namespace

TEST(NetfilterBlocker, constructor_dryRun_noSideEffects) {
    NetfilterBlocker blocker(true);
    EXPECT_EQ(blocker.activeRuleCount(), 0u);
}

TEST(NetfilterBlocker, block_addsRule) {
    NetfilterBlocker blocker(true);
    auto key = makeKey();

    EXPECT_TRUE(blocker.block(key, "test block"));
    EXPECT_EQ(blocker.activeRuleCount(), 1u);
    EXPECT_TRUE(blocker.isBlocked(key));
}

TEST(NetfilterBlocker, block_duplicateKey_refreshesExpiry) {
    NetfilterBlocker blocker(true);
    auto key = makeKey();

    EXPECT_TRUE(blocker.block(key, "first", std::chrono::seconds{60}));
    EXPECT_TRUE(blocker.block(key, "refresh", std::chrono::seconds{120}));
    EXPECT_EQ(blocker.activeRuleCount(), 1u);
}

TEST(NetfilterBlocker, unblock_removesRule) {
    NetfilterBlocker blocker(true);
    auto key = makeKey();

    blocker.block(key, "test");
    EXPECT_TRUE(blocker.isBlocked(key));

    EXPECT_TRUE(blocker.unblock(key));
    EXPECT_FALSE(blocker.isBlocked(key));
    EXPECT_EQ(blocker.activeRuleCount(), 0u);
}

TEST(NetfilterBlocker, unblock_nonexistentKey_returnsFalse) {
    NetfilterBlocker blocker(true);
    EXPECT_FALSE(blocker.unblock(makeKey()));
}

TEST(NetfilterBlocker, clearAll_removesAllRules) {
    NetfilterBlocker blocker(true);

    blocker.block(makeKey("10.0.0.1", "1.1.1.1", 111, 80), "a");
    blocker.block(makeKey("10.0.0.2", "2.2.2.2", 222, 443), "b");
    blocker.block(makeKey("10.0.0.3", "3.3.3.3", 333, 22), "c");
    EXPECT_EQ(blocker.activeRuleCount(), 3u);

    blocker.clearAll();
    EXPECT_EQ(blocker.activeRuleCount(), 0u);
}

TEST(NetfilterBlocker, sweepExpired_removesOldRules) {
    NetfilterBlocker blocker(true);
    auto key = makeKey();

    // Block with 0 duration = immediately expired.
    blocker.block(key, "test", std::chrono::seconds{0});

    // Small delay to ensure clock has advanced past expiry.
    std::this_thread::sleep_for(std::chrono::milliseconds{10});

    blocker.sweepExpired();
    EXPECT_EQ(blocker.activeRuleCount(), 0u);
}

TEST(NetfilterBlocker, sweepExpired_keepsActiveRules) {
    NetfilterBlocker blocker(true);
    auto key = makeKey();

    blocker.block(key, "test", std::chrono::seconds{3600});
    blocker.sweepExpired();

    EXPECT_EQ(blocker.activeRuleCount(), 1u);
    EXPECT_TRUE(blocker.isBlocked(key));
}

TEST(NetfilterBlocker, isBlocked_unknownKey_returnsFalse) {
    NetfilterBlocker blocker(true);
    EXPECT_FALSE(blocker.isBlocked(makeKey()));
}

TEST(NetfilterBlocker, multipleBlocks_trackedIndependently) {
    NetfilterBlocker blocker(true);

    auto key1 = makeKey("10.0.0.1", "1.1.1.1", 111, 80);
    auto key2 = makeKey("10.0.0.2", "2.2.2.2", 222, 443);

    blocker.block(key1, "a");
    blocker.block(key2, "b");

    EXPECT_TRUE(blocker.isBlocked(key1));
    EXPECT_TRUE(blocker.isBlocked(key2));

    blocker.unblock(key1);
    EXPECT_FALSE(blocker.isBlocked(key1));
    EXPECT_TRUE(blocker.isBlocked(key2));
}

TEST(NetfilterBlocker, destructor_clearsRules) {
    EXPECT_NO_THROW({
        NetfilterBlocker blocker(true);
        blocker.block(makeKey(), "test");
    });
}
