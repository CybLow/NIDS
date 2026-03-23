#include "app/BypassManager.h"

#include <gtest/gtest.h>

using namespace nids;

namespace {
core::FlowKey makeKey(const std::string& src = "10.0.0.1",
                        const std::string& dst = "192.168.1.1",
                        std::uint16_t sp = 12345,
                        std::uint16_t dp = 80) {
    return {src, dst, sp, dp, 6};
}
} // namespace

TEST(BypassManager, newFlow_notBypassed) {
    app::BypassManager mgr;
    EXPECT_FALSE(mgr.shouldBypass(makeKey()));
    EXPECT_EQ(mgr.trackedFlowCount(), 0u);
}

TEST(BypassManager, trackForwarded_belowThreshold_notBypassed) {
    app::BypassPolicy policy;
    policy.cleanPacketThreshold = 10;
    app::BypassManager mgr(policy);

    auto key = makeKey();
    for (int i = 0; i < 5; ++i) {
        mgr.trackForwarded(key, static_cast<int64_t>(i) * 1000);
    }

    EXPECT_FALSE(mgr.shouldBypass(key));
    EXPECT_EQ(mgr.trackedFlowCount(), 1u);
    EXPECT_EQ(mgr.bypassedFlowCount(), 0u);
}

TEST(BypassManager, trackForwarded_aboveThreshold_bypassed) {
    app::BypassPolicy policy;
    policy.cleanPacketThreshold = 5;
    app::BypassManager mgr(policy);

    auto key = makeKey();
    for (int i = 0; i < 10; ++i) {
        mgr.trackForwarded(key, static_cast<int64_t>(i) * 1000);
    }

    EXPECT_TRUE(mgr.shouldBypass(key));
    EXPECT_EQ(mgr.bypassedFlowCount(), 1u);
}

TEST(BypassManager, markBypassed_explicitlyBypasses) {
    app::BypassManager mgr;
    auto key = makeKey();

    mgr.markBypassed(key);
    EXPECT_TRUE(mgr.shouldBypass(key));
}

TEST(BypassManager, revokeBypass_removesFlag) {
    app::BypassManager mgr;
    auto key = makeKey();

    mgr.markBypassed(key);
    EXPECT_TRUE(mgr.shouldBypass(key));

    mgr.revokeBypass(key);
    EXPECT_FALSE(mgr.shouldBypass(key));
}

TEST(BypassManager, sweep_removesExpiredFlows) {
    app::BypassManager mgr;
    auto key = makeKey();

    mgr.trackForwarded(key, 1000);
    EXPECT_EQ(mgr.trackedFlowCount(), 1u);

    // Sweep with a time far in the future, timeout of 1.
    mgr.sweep(999999, 1);
    EXPECT_EQ(mgr.trackedFlowCount(), 0u);
}

TEST(BypassManager, sweep_keepsRecentFlows) {
    app::BypassManager mgr;
    auto key = makeKey();

    mgr.trackForwarded(key, 1000);

    // Sweep with time close to lastSeen.
    mgr.sweep(1001, 1000000);
    EXPECT_EQ(mgr.trackedFlowCount(), 1u);
}

TEST(BypassManager, disabled_neverBypasses) {
    app::BypassPolicy policy;
    policy.enabled = false;
    app::BypassManager mgr(policy);

    auto key = makeKey();
    for (int i = 0; i < 200; ++i) {
        mgr.trackForwarded(key, static_cast<int64_t>(i) * 1000);
    }

    EXPECT_FALSE(mgr.shouldBypass(key));
}

TEST(BypassManager, multipleFlows_trackedIndependently) {
    app::BypassPolicy policy;
    policy.cleanPacketThreshold = 3;
    app::BypassManager mgr(policy);

    auto key1 = makeKey("10.0.0.1", "1.1.1.1", 111, 80);
    auto key2 = makeKey("10.0.0.2", "2.2.2.2", 222, 443);

    for (int i = 0; i < 5; ++i) {
        mgr.trackForwarded(key1, static_cast<int64_t>(i) * 1000);
    }
    mgr.trackForwarded(key2, 1000);

    EXPECT_TRUE(mgr.shouldBypass(key1));
    EXPECT_FALSE(mgr.shouldBypass(key2));
    EXPECT_EQ(mgr.trackedFlowCount(), 2u);
}

TEST(BypassManager, setPolicy_updatesThreshold) {
    app::BypassPolicy policy;
    policy.cleanPacketThreshold = 1000;
    app::BypassManager mgr(policy);

    app::BypassPolicy newPolicy;
    newPolicy.cleanPacketThreshold = 2;
    mgr.setPolicy(newPolicy);

    auto key = makeKey();
    mgr.trackForwarded(key, 1000);
    mgr.trackForwarded(key, 2000);

    EXPECT_TRUE(mgr.shouldBypass(key));
}
