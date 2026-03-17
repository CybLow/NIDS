#include "app/HuntEngine.h"

#include "app/HybridDetectionService.h"
#include "core/model/AttackType.h"
#include "core/model/DetectionResult.h"
#include "core/model/DetectionSource.h"
#include "core/model/FlowInfo.h"
#include "core/model/FlowQuery.h"
#include "core/model/IndexedFlow.h"

#include "helpers/MockAnalyzer.h"
#include "helpers/MockFlowExtractor.h"
#include "helpers/MockNormalizer.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

using namespace nids;
using namespace nids::testing;

namespace {

/// Concrete mock of IFlowIndex for testing HuntEngine.
class MockFlowIndex : public core::IFlowIndex {
public:
    std::vector<core::IndexedFlow> storedFlows;

    void index(const core::FlowInfo&, const core::DetectionResult&,
               std::string_view, std::size_t) override {}

    [[nodiscard]] std::vector<core::IndexedFlow> query(
        const core::FlowQuery& q) override {
        std::vector<core::IndexedFlow> result;
        for (const auto& f : storedFlows) {
            if (q.anyIp && f.srcIp != *q.anyIp && f.dstIp != *q.anyIp)
                continue;
            if (q.anyPort && f.srcPort != *q.anyPort && f.dstPort != *q.anyPort)
                continue;
            result.push_back(f);
        }
        return result;
    }

    [[nodiscard]] std::size_t count(const core::FlowQuery&) const override {
        return storedFlows.size();
    }

    [[nodiscard]] std::vector<std::string> distinctValues(
        std::string_view, std::size_t) const override { return {}; }

    [[nodiscard]] core::FlowStatsSummary aggregate(
        const core::FlowQuery&) const override {
        core::FlowStatsSummary s;
        s.totalFlows = storedFlows.size();
        for (const auto& f : storedFlows) {
            if (f.isFlagged) ++s.flaggedFlows;
            s.avgCombinedScore += f.combinedScore;
        }
        if (s.totalFlows > 0) {
            s.avgCombinedScore /= static_cast<float>(s.totalFlows);
        }
        return s;
    }

    void optimize() override {}
    [[nodiscard]] std::size_t sizeBytes() const noexcept override { return 0; }
};

core::IndexedFlow makeIndexedFlow(
    const std::string& src, const std::string& dst,
    std::uint16_t srcPort, std::uint16_t dstPort,
    core::AttackType verdict, float score, bool flagged) {
    core::IndexedFlow f;
    f.id = 1;
    f.timestampUs = 1000000;
    f.srcIp = src;
    f.dstIp = dst;
    f.srcPort = srcPort;
    f.dstPort = dstPort;
    f.protocol = 6;
    f.verdict = verdict;
    f.combinedScore = score;
    f.isFlagged = flagged;
    return f;
}

} // namespace

TEST(HuntEngine, iocSearch_byIp_findsMatchingFlows) {
    MockFlowIndex flowIndex;
    flowIndex.storedFlows.push_back(
        makeIndexedFlow("10.0.0.1", "1.1.1.1", 111, 80,
                        core::AttackType::SshBruteForce, 0.8f, true));
    flowIndex.storedFlows.push_back(
        makeIndexedFlow("10.0.0.2", "2.2.2.2", 222, 443,
                        core::AttackType::Benign, 0.0f, false));

    MockFlowExtractor extractor;
    MockAnalyzer analyzer;
    MockNormalizer normalizer;
    app::HybridDetectionService detector(nullptr, nullptr);

    app::HuntEngine engine(flowIndex, extractor, analyzer,
                           normalizer, detector);

    core::IocSearchQuery query;
    query.ips.push_back("10.0.0.1");

    auto result = engine.iocSearch(query);
    EXPECT_TRUE(result.completed);
    EXPECT_EQ(result.matchedFlows.size(), 1u);
    EXPECT_EQ(result.matchedFlows[0].srcIp, "10.0.0.1");
}

TEST(HuntEngine, iocSearch_byPort_findsMatchingFlows) {
    MockFlowIndex flowIndex;
    flowIndex.storedFlows.push_back(
        makeIndexedFlow("10.0.0.1", "1.1.1.1", 111, 443,
                        core::AttackType::Benign, 0.0f, false));
    flowIndex.storedFlows.push_back(
        makeIndexedFlow("10.0.0.2", "2.2.2.2", 222, 80,
                        core::AttackType::Benign, 0.0f, false));

    MockFlowExtractor extractor;
    MockAnalyzer analyzer;
    MockNormalizer normalizer;
    app::HybridDetectionService detector(nullptr, nullptr);

    app::HuntEngine engine(flowIndex, extractor, analyzer,
                           normalizer, detector);

    core::IocSearchQuery query;
    query.ports.push_back(443);

    auto result = engine.iocSearch(query);
    EXPECT_TRUE(result.completed);
    EXPECT_EQ(result.matchedFlows.size(), 1u);
}

TEST(HuntEngine, iocSearch_emptyQuery_returnsEmpty) {
    MockFlowIndex flowIndex;
    MockFlowExtractor extractor;
    MockAnalyzer analyzer;
    MockNormalizer normalizer;
    app::HybridDetectionService detector(nullptr, nullptr);

    app::HuntEngine engine(flowIndex, extractor, analyzer,
                           normalizer, detector);

    core::IocSearchQuery query; // Empty query
    auto result = engine.iocSearch(query);
    EXPECT_TRUE(result.completed);
    EXPECT_TRUE(result.matchedFlows.empty());
}

TEST(HuntEngine, correlateByIp_findsAllFlowsForIp) {
    MockFlowIndex flowIndex;
    flowIndex.storedFlows.push_back(
        makeIndexedFlow("10.0.0.1", "1.1.1.1", 111, 80,
                        core::AttackType::SshBruteForce, 0.8f, true));
    flowIndex.storedFlows.push_back(
        makeIndexedFlow("2.2.2.2", "10.0.0.1", 222, 443,
                        core::AttackType::DdosUdp, 0.9f, true));
    flowIndex.storedFlows.push_back(
        makeIndexedFlow("3.3.3.3", "4.4.4.4", 333, 80,
                        core::AttackType::Benign, 0.0f, false));

    MockFlowExtractor extractor;
    MockAnalyzer analyzer;
    MockNormalizer normalizer;
    app::HybridDetectionService detector(nullptr, nullptr);

    app::HuntEngine engine(flowIndex, extractor, analyzer,
                           normalizer, detector);

    auto result = engine.correlateByIp("10.0.0.1", 0, 999999999);
    EXPECT_EQ(result.matchedFlows.size(), 2u);
}

TEST(HuntEngine, buildTimeline_sortsByTimestamp) {
    MockFlowIndex flowIndex;
    MockFlowExtractor extractor;
    MockAnalyzer analyzer;
    MockNormalizer normalizer;
    app::HybridDetectionService detector(nullptr, nullptr);

    app::HuntEngine engine(flowIndex, extractor, analyzer,
                           normalizer, detector);

    std::vector<core::IndexedFlow> flows;
    auto f1 = makeIndexedFlow("10.0.0.1", "1.1.1.1", 111, 80,
                              core::AttackType::PortScanning, 0.5f, true);
    f1.timestampUs = 3000000;
    auto f2 = makeIndexedFlow("10.0.0.1", "2.2.2.2", 222, 443,
                              core::AttackType::SshBruteForce, 0.8f, true);
    f2.timestampUs = 1000000;
    flows.push_back(f1);
    flows.push_back(f2);

    auto timeline = engine.buildTimeline(flows);

    EXPECT_EQ(timeline.events.size(), 2u);
    EXPECT_EQ(timeline.startTimeUs, 1000000);
    EXPECT_EQ(timeline.endTimeUs, 3000000);
    EXPECT_LE(timeline.events[0].timestampUs,
              timeline.events[1].timestampUs);
}

TEST(HuntEngine, buildTimeline_emptyFlows_returnsEmptyTimeline) {
    MockFlowIndex flowIndex;
    MockFlowExtractor extractor;
    MockAnalyzer analyzer;
    MockNormalizer normalizer;
    app::HybridDetectionService detector(nullptr, nullptr);

    app::HuntEngine engine(flowIndex, extractor, analyzer,
                           normalizer, detector);

    auto timeline = engine.buildTimeline({});
    EXPECT_TRUE(timeline.events.empty());
}

TEST(HuntEngine, buildTimeline_collectsInvolvedIps) {
    MockFlowIndex flowIndex;
    MockFlowExtractor extractor;
    MockAnalyzer analyzer;
    MockNormalizer normalizer;
    app::HybridDetectionService detector(nullptr, nullptr);

    app::HuntEngine engine(flowIndex, extractor, analyzer,
                           normalizer, detector);

    std::vector<core::IndexedFlow> flows;
    flows.push_back(makeIndexedFlow("10.0.0.1", "1.1.1.1", 111, 80,
                                    core::AttackType::Benign, 0.0f, false));
    flows.push_back(makeIndexedFlow("10.0.0.2", "1.1.1.1", 222, 80,
                                    core::AttackType::Benign, 0.0f, false));

    auto timeline = engine.buildTimeline(flows);

    EXPECT_EQ(timeline.involvedIps.size(), 3u); // 10.0.0.1, 10.0.0.2, 1.1.1.1
}

TEST(HuntEngine, detectAnomalies_noFlows_returnsEmpty) {
    MockFlowIndex flowIndex;
    MockFlowExtractor extractor;
    MockAnalyzer analyzer;
    MockNormalizer normalizer;
    app::HybridDetectionService detector(nullptr, nullptr);

    app::HuntEngine engine(flowIndex, extractor, analyzer,
                           normalizer, detector);

    auto anomalies = engine.detectAnomalies(0, 999999999);
    EXPECT_TRUE(anomalies.empty());
}

TEST(HuntEngine, detectAnomalies_highScoreFlows_flagsAnomaly) {
    MockFlowIndex flowIndex;
    // Add many high-score flagged flows.
    for (int i = 0; i < 20; ++i) {
        flowIndex.storedFlows.push_back(
            makeIndexedFlow("10.0.0.1", "1.1.1.1", 111, 80,
                            core::AttackType::DdosUdp, 0.9f, true));
    }

    MockFlowExtractor extractor;
    MockAnalyzer analyzer;
    MockNormalizer normalizer;
    app::HybridDetectionService detector(nullptr, nullptr);

    app::HuntEngine engine(flowIndex, extractor, analyzer,
                           normalizer, detector);

    auto anomalies = engine.detectAnomalies(0, 999999999);
    EXPECT_FALSE(anomalies.empty());
}

TEST(HuntEngine, retroactiveAnalysis_nonexistentFile_returnsError) {
    MockFlowIndex flowIndex;
    MockFlowExtractor extractor;
    MockAnalyzer analyzer;
    MockNormalizer normalizer;
    app::HybridDetectionService detector(nullptr, nullptr);

    app::HuntEngine engine(flowIndex, extractor, analyzer,
                           normalizer, detector);

    auto result = engine.retroactiveAnalysis("/nonexistent/file.pcap");
    EXPECT_FALSE(result.completed);
    EXPECT_FALSE(result.errorMessage.empty());
}

TEST(HuntEngine, setProgressCallback_isAccepted) {
    MockFlowIndex flowIndex;
    MockFlowExtractor extractor;
    MockAnalyzer analyzer;
    MockNormalizer normalizer;
    app::HybridDetectionService detector(nullptr, nullptr);

    app::HuntEngine engine(flowIndex, extractor, analyzer,
                           normalizer, detector);

    bool callbackCalled = false;
    engine.setProgressCallback(
        [&callbackCalled](float, std::string_view) {
            callbackCalled = true;
        });

    // Just verify it doesn't crash.
    EXPECT_NO_THROW({
        [[maybe_unused]] auto r = engine.retroactiveAnalysis("/nonexistent.pcap");
    });
}
