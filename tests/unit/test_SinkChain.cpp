#include "app/SinkChain.h"

#include "core/model/DetectionResult.h"
#include "core/model/FlowInfo.h"
#include "core/services/IOutputSink.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace nids;

namespace {

/// Mock sink that records calls for verification.
class MockSink : public core::IOutputSink {
public:
    explicit MockSink(std::string sinkName) : name_(std::move(sinkName)) {}

    [[nodiscard]] std::string_view name() const noexcept override {
        return name_;
    }

    [[nodiscard]] bool start() override {
        started_ = true;
        return startResult_;
    }

    void onFlowResult(std::size_t flowIndex,
                      const core::DetectionResult& /*result*/,
                      const core::FlowInfo& /*flow*/) override {
        receivedFlows_.push_back(flowIndex);
    }

    void stop() override {
        stopped_ = true;
    }

    bool started_ = false;
    bool stopped_ = false;
    bool startResult_ = true;
    std::vector<std::size_t> receivedFlows_;

private:
    std::string name_;
};

/// Sink that throws on every operation.
class ThrowingSink : public core::IOutputSink {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "ThrowingSink";
    }

    [[nodiscard]] bool start() override {
        throw std::runtime_error("start failed");
    }

    void onFlowResult(std::size_t /*flowIndex*/,
                      const core::DetectionResult& /*result*/,
                      const core::FlowInfo& /*flow*/) override {
        throw std::runtime_error("onFlowResult failed");
    }

    void stop() override {
        throw std::runtime_error("stop failed");
    }
};

core::DetectionResult makeBenignResult() {
    core::DetectionResult r;
    r.mlResult.classification = core::AttackType::Benign;
    r.mlResult.confidence = 0.99f;
    r.finalVerdict = core::AttackType::Benign;
    r.combinedScore = 0.0f;
    r.detectionSource = core::DetectionSource::None;
    return r;
}

core::FlowInfo makeSimpleFlow() {
    core::FlowInfo f;
    f.srcIp = "10.0.0.1";
    f.dstIp = "192.168.1.1";
    f.srcPort = 12345;
    f.dstPort = 80;
    f.protocol = 6;
    return f;
}

} // namespace

TEST(SinkChain, emptyChain_sinkCountIsZero) {
    app::SinkChain chain;
    EXPECT_EQ(chain.sinkCount(), 0u);
}

TEST(SinkChain, addOwnedSink_incrementsSinkCount) {
    app::SinkChain chain;
    chain.addSink(std::make_unique<MockSink>("test1"));
    chain.addSink(std::make_unique<MockSink>("test2"));
    EXPECT_EQ(chain.sinkCount(), 2u);
}

TEST(SinkChain, addNonOwnedSink_incrementsSinkCount) {
    app::SinkChain chain;
    MockSink s1("test1");
    MockSink s2("test2");
    chain.addSink(&s1);
    chain.addSink(&s2);
    EXPECT_EQ(chain.sinkCount(), 2u);
}

TEST(SinkChain, addNullSink_doesNotIncrement) {
    app::SinkChain chain;
    chain.addSink(std::unique_ptr<core::IOutputSink>(nullptr));
    chain.addSink(static_cast<core::IOutputSink*>(nullptr));
    EXPECT_EQ(chain.sinkCount(), 0u);
}

TEST(SinkChain, start_startsAllSinks) {
    app::SinkChain chain;
    auto s1 = std::make_unique<MockSink>("test1");
    auto s2 = std::make_unique<MockSink>("test2");
    auto* p1 = s1.get();
    auto* p2 = s2.get();
    chain.addSink(std::move(s1));
    chain.addSink(std::move(s2));

    EXPECT_TRUE(chain.start());
    EXPECT_TRUE(p1->started_);
    EXPECT_TRUE(p2->started_);
}

TEST(SinkChain, start_oneFailsReturnsFalse) {
    app::SinkChain chain;
    auto s1 = std::make_unique<MockSink>("ok");
    auto s2 = std::make_unique<MockSink>("fail");
    s2->startResult_ = false;
    auto* p1 = s1.get();
    chain.addSink(std::move(s1));
    chain.addSink(std::move(s2));

    EXPECT_FALSE(chain.start());
    // First sink still started
    EXPECT_TRUE(p1->started_);
}

TEST(SinkChain, onFlowResult_dispatchesToAllSinks) {
    app::SinkChain chain;
    auto s1 = std::make_unique<MockSink>("test1");
    auto s2 = std::make_unique<MockSink>("test2");
    auto* p1 = s1.get();
    auto* p2 = s2.get();
    chain.addSink(std::move(s1));
    chain.addSink(std::move(s2));

    auto result = makeBenignResult();
    auto flow = makeSimpleFlow();

    chain.onFlowResult(0, result, flow);
    chain.onFlowResult(1, result, flow);

    EXPECT_EQ(p1->receivedFlows_.size(), 2u);
    EXPECT_EQ(p2->receivedFlows_.size(), 2u);
    EXPECT_EQ(p1->receivedFlows_[0], 0u);
    EXPECT_EQ(p1->receivedFlows_[1], 1u);
}

TEST(SinkChain, onFlowResult_mixedOwnedAndNonOwned) {
    app::SinkChain chain;
    auto s1 = std::make_unique<MockSink>("owned");
    auto* p1 = s1.get();
    MockSink s2("nonOwned");

    chain.addSink(std::move(s1));
    chain.addSink(&s2);

    auto result = makeBenignResult();
    auto flow = makeSimpleFlow();

    chain.onFlowResult(42, result, flow);

    EXPECT_EQ(p1->receivedFlows_.size(), 1u);
    EXPECT_EQ(s2.receivedFlows_.size(), 1u);
    EXPECT_EQ(p1->receivedFlows_[0], 42u);
    EXPECT_EQ(s2.receivedFlows_[0], 42u);
}

TEST(SinkChain, stop_stopsAllSinks) {
    app::SinkChain chain;
    auto s1 = std::make_unique<MockSink>("test1");
    auto s2 = std::make_unique<MockSink>("test2");
    auto* p1 = s1.get();
    auto* p2 = s2.get();
    chain.addSink(std::move(s1));
    chain.addSink(std::move(s2));

    chain.stop();

    EXPECT_TRUE(p1->stopped_);
    EXPECT_TRUE(p2->stopped_);
}

TEST(SinkChain, errorIsolation_throwingSinkDoesNotBlockOthers) {
    app::SinkChain chain;
    auto throwing = std::make_unique<ThrowingSink>();
    auto mock = std::make_unique<MockSink>("safe");
    auto* mockPtr = mock.get();

    chain.addSink(std::move(throwing));
    chain.addSink(std::move(mock));

    // start: throwing sink throws, but mock still gets started
    [[maybe_unused]] auto ok = chain.start();
    EXPECT_TRUE(mockPtr->started_);

    // onFlowResult: throwing sink throws, but mock still receives
    auto result = makeBenignResult();
    auto flow = makeSimpleFlow();
    chain.onFlowResult(0, result, flow);
    EXPECT_EQ(mockPtr->receivedFlows_.size(), 1u);

    // stop: throwing sink throws, but mock still gets stopped
    chain.stop();
    EXPECT_TRUE(mockPtr->stopped_);
}

TEST(SinkChain, name_returnsSinkChain) {
    app::SinkChain chain;
    EXPECT_EQ(chain.name(), "SinkChain");
}

TEST(SinkChain, emptyChain_operationsAreNoOps) {
    app::SinkChain chain;
    EXPECT_TRUE(chain.start());

    auto result = makeBenignResult();
    auto flow = makeSimpleFlow();
    EXPECT_NO_THROW(chain.onFlowResult(0, result, flow));
    EXPECT_NO_THROW(chain.stop());
}
