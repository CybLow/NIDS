#include "infra/flow/TcpReassembler.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

using namespace nids;

// TcpReassembler tests require PcapPlusPlus runtime (npcap on Windows).
class TcpReassemblerTest : public ::testing::Test {
protected:
    void SetUp() override {
#ifdef _WIN32
        GTEST_SKIP() << "PcapPlusPlus requires npcap on Windows";
#endif
    }
};

TEST_F(TcpReassemblerTest, constructor_defaultConfig_createsInstance) {
    infra::TcpReassembler reassembler;
    EXPECT_EQ(reassembler.activeStreams(), 0u);
    EXPECT_EQ(reassembler.completedStreams(), 0u);
}

TEST_F(TcpReassemblerTest, constructor_customConfig_accepted) {
    infra::ReassemblyConfig cfg;
    cfg.maxStreamSize = 512 * 1024;
    cfg.maxConcurrentStreams = 5000;

    infra::TcpReassembler reassembler(cfg);
    EXPECT_EQ(reassembler.activeStreams(), 0u);
}

TEST_F(TcpReassemblerTest, setCallback_acceptsCallback) {
    infra::TcpReassembler reassembler;

    bool callbackSet = false;
    reassembler.setCallback(
        [&callbackSet](const core::FlowInfo&,
                       std::span<const std::uint8_t>,
                       std::span<const std::uint8_t>) {
            callbackSet = true;
        });

    // Just verify it doesn't crash.
    SUCCEED();
}

TEST_F(TcpReassemblerTest, reset_clearsState) {
    infra::TcpReassembler reassembler;
    reassembler.reset();

    EXPECT_EQ(reassembler.activeStreams(), 0u);
    EXPECT_EQ(reassembler.completedStreams(), 0u);
}

TEST_F(TcpReassemblerTest, flushAll_onEmpty_doesNotCrash) {
    infra::TcpReassembler reassembler;
    EXPECT_NO_THROW(reassembler.flushAll());
}

TEST_F(TcpReassemblerTest, destructor_cleansUpCleanly) {
    EXPECT_NO_THROW({
        infra::TcpReassembler reassembler;
        reassembler.setCallback(
            [](const core::FlowInfo&,
               std::span<const std::uint8_t>,
               std::span<const std::uint8_t>) {});
    });
}

TEST_F(TcpReassemblerTest, completedStreams_initiallyZero) {
    infra::TcpReassembler reassembler;
    EXPECT_EQ(reassembler.completedStreams(), 0u);
}

TEST_F(TcpReassemblerTest, reset_afterSetCallback_clearsStreams) {
    infra::TcpReassembler reassembler;
    reassembler.setCallback(
        [](const core::FlowInfo&,
           std::span<const std::uint8_t>,
           std::span<const std::uint8_t>) {});
    reassembler.reset();

    EXPECT_EQ(reassembler.activeStreams(), 0u);
    EXPECT_EQ(reassembler.completedStreams(), 0u);
}
