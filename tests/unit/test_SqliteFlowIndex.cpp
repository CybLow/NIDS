#include "infra/storage/SqliteFlowIndex.h"

#include "core/model/AttackType.h"
#include "core/model/DetectionResult.h"
#include "core/model/DetectionSource.h"
#include "core/model/FlowInfo.h"
#include "core/model/FlowQuery.h"
#include "core/model/IndexedFlow.h"

#include "helpers/TestFixtures.h"
#include <gtest/gtest.h>

#include <cstddef>
#include <filesystem>
#include <string>

using namespace nids;
namespace fs = std::filesystem;

namespace {

/// RAII helper to remove test database on scope exit.
struct DbGuard {
    fs::path path;
    ~DbGuard() {
        std::error_code ec;
        fs::remove(path, ec);
        // Also remove WAL/SHM files.
        fs::remove(fs::path(path.string() + "-wal"), ec);
        fs::remove(fs::path(path.string() + "-shm"), ec);
    }
};

core::FlowInfo makeFlow(const std::string& src, const std::string& dst,
                          std::uint16_t srcPort, std::uint16_t dstPort,
                          std::uint8_t proto) {
    core::FlowInfo f;
    f.srcIp = src;
    f.dstIp = dst;
    f.srcPort = srcPort;
    f.dstPort = dstPort;
    f.protocol = proto;
    f.totalFwdPackets = 10;
    f.totalBwdPackets = 5;
    f.flowDurationUs = 1000000.0;
    f.avgPacketSize = 256.0;
    return f;
}

core::DetectionResult makeResult(core::AttackType type, float confidence,
                                   float combinedScore,
                                   core::DetectionSource source) {
    core::DetectionResult r;
    r.mlResult.classification = type;
    r.mlResult.confidence = confidence;
    r.finalVerdict = type;
    r.combinedScore = combinedScore;
    r.detectionSource = source;
    return r;
}

} // namespace

TEST(SqliteFlowIndex, constructor_createsDatabase) {
    auto dbPath = fs::temp_directory_path() / "nids_test_flowindex.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    EXPECT_TRUE(fs::exists(dbPath));
    EXPECT_GT(index.sizeBytes(), 0u);
}

TEST(SqliteFlowIndex, index_insertsFlow) {
    auto dbPath = fs::temp_directory_path() / "nids_test_index_insert.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);
    auto result = makeResult(core::AttackType::SshBruteForce, 0.85f, 0.78f,
                             core::DetectionSource::MlOnly);

    index.index(flow, result, "test.pcap", 0);

    core::FlowQuery q;
    auto count = index.count(q);
    EXPECT_EQ(count, 1u);
}

TEST(SqliteFlowIndex, query_returnsIndexedFlow) {
    auto dbPath = fs::temp_directory_path() / "nids_test_query.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);
    auto result = makeResult(core::AttackType::DdosUdp, 0.95f, 0.87f,
                             core::DetectionSource::Ensemble);

    index.index(flow, result, "capture.pcap", 1024);

    core::FlowQuery q;
    auto flows = index.query(q);

    ASSERT_EQ(flows.size(), 1u);
    EXPECT_EQ(flows[0].srcIp, "10.0.0.1");
    EXPECT_EQ(flows[0].dstIp, "192.168.1.1");
    EXPECT_EQ(flows[0].srcPort, 12345);
    EXPECT_EQ(flows[0].dstPort, 80);
    EXPECT_EQ(flows[0].protocol, 6);
    EXPECT_EQ(flows[0].verdict, core::AttackType::DdosUdp);
    EXPECT_FLOAT_EQ(flows[0].mlConfidence, 0.95f);
    EXPECT_EQ(flows[0].pcapFile, "capture.pcap");
    EXPECT_EQ(flows[0].pcapOffset, 1024u);
}

TEST(SqliteFlowIndex, query_filterBySrcIp) {
    auto dbPath = fs::temp_directory_path() / "nids_test_filter_src.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto r = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                        core::DetectionSource::None);

    index.index(makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6), r, "", 0);
    index.index(makeFlow("10.0.0.2", "1.1.1.1", 222, 80, 6), r, "", 0);
    index.index(makeFlow("10.0.0.1", "2.2.2.2", 333, 443, 6), r, "", 0);

    core::FlowQuery q;
    q.srcIp = "10.0.0.1";
    auto flows = index.query(q);

    EXPECT_EQ(flows.size(), 2u);
}

TEST(SqliteFlowIndex, query_filterByAnyIp) {
    auto dbPath = fs::temp_directory_path() / "nids_test_filter_anyip.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto r = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                        core::DetectionSource::None);

    index.index(makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6), r, "", 0);
    index.index(makeFlow("10.0.0.2", "10.0.0.1", 222, 80, 6), r, "", 0);
    index.index(makeFlow("10.0.0.3", "2.2.2.2", 333, 80, 6), r, "", 0);

    core::FlowQuery q;
    q.anyIp = "10.0.0.1";
    auto flows = index.query(q);

    EXPECT_EQ(flows.size(), 2u);
}

TEST(SqliteFlowIndex, query_filterByVerdict) {
    auto dbPath = fs::temp_directory_path() / "nids_test_filter_verdict.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto flow = makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6);

    index.index(flow,
        makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                   core::DetectionSource::None), "", 0);
    index.index(flow,
        makeResult(core::AttackType::SynFlood, 0.9f, 0.8f,
                   core::DetectionSource::MlOnly), "", 0);
    index.index(flow,
        makeResult(core::AttackType::SynFlood, 0.85f, 0.7f,
                   core::DetectionSource::MlOnly), "", 0);

    core::FlowQuery q;
    q.verdict = core::AttackType::SynFlood;
    EXPECT_EQ(index.count(q), 2u);
}

TEST(SqliteFlowIndex, query_filterByFlagged) {
    auto dbPath = fs::temp_directory_path() / "nids_test_filter_flagged.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto flow = makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6);

    index.index(flow,
        makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                   core::DetectionSource::None), "", 0);
    index.index(flow,
        makeResult(core::AttackType::DdosUdp, 0.95f, 0.87f,
                   core::DetectionSource::Ensemble), "", 0);

    core::FlowQuery q;
    q.flaggedOnly = true;
    EXPECT_EQ(index.count(q), 1u);
}

TEST(SqliteFlowIndex, query_filterByPort) {
    auto dbPath = fs::temp_directory_path() / "nids_test_filter_port.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto r = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                        core::DetectionSource::None);

    index.index(makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6), r, "", 0);
    index.index(makeFlow("10.0.0.1", "1.1.1.1", 222, 443, 6), r, "", 0);
    index.index(makeFlow("10.0.0.1", "1.1.1.1", 443, 8080, 6), r, "", 0);

    core::FlowQuery q;
    q.anyPort = static_cast<std::uint16_t>(443);
    auto flows = index.query(q);

    EXPECT_EQ(flows.size(), 2u);
}

TEST(SqliteFlowIndex, query_pagination) {
    auto dbPath = fs::temp_directory_path() / "nids_test_pagination.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto r = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                        core::DetectionSource::None);

    for (int i = 0; i < 10; ++i) {
        auto flow = makeFlow("10.0.0." + std::to_string(i),
                             "1.1.1.1", 111, 80, 6);
        index.index(flow, r, "", 0);
    }

    core::FlowQuery q;
    q.limit = 3;
    q.offset = 0;
    EXPECT_EQ(index.query(q).size(), 3u);

    q.offset = 8;
    EXPECT_EQ(index.query(q).size(), 2u);
}

TEST(SqliteFlowIndex, aggregate_computesStats) {
    auto dbPath = fs::temp_directory_path() / "nids_test_aggregate.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto flow = makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6);

    index.index(flow,
        makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                   core::DetectionSource::None), "", 0);
    index.index(flow,
        makeResult(core::AttackType::DdosUdp, 0.95f, 0.87f,
                   core::DetectionSource::Ensemble), "", 0);
    index.index(flow,
        makeResult(core::AttackType::SshBruteForce, 0.85f, 0.78f,
                   core::DetectionSource::MlOnly), "", 0);

    core::FlowQuery q;
    auto stats = index.aggregate(q);

    EXPECT_EQ(stats.totalFlows, 3u);
    EXPECT_GE(stats.flaggedFlows, 2u);
    EXPECT_GT(stats.avgCombinedScore, 0.0f);
    EXPECT_FLOAT_EQ(stats.maxCombinedScore, 0.87f);
}

TEST(SqliteFlowIndex, distinctValues_returnsUniqueIps) {
    auto dbPath = fs::temp_directory_path() / "nids_test_distinct.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto r = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                        core::DetectionSource::None);

    index.index(makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6), r, "", 0);
    index.index(makeFlow("10.0.0.1", "2.2.2.2", 222, 80, 6), r, "", 0);
    index.index(makeFlow("10.0.0.2", "1.1.1.1", 333, 80, 6), r, "", 0);

    auto srcIps = index.distinctValues("src_ip");
    EXPECT_EQ(srcIps.size(), 2u);

    auto dstIps = index.distinctValues("dst_ip");
    EXPECT_EQ(dstIps.size(), 2u);
}

TEST(SqliteFlowIndex, distinctValues_rejectsInvalidField) {
    auto dbPath = fs::temp_directory_path() / "nids_test_distinct_invalid.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);

    // SQL injection attempt should be blocked.
    auto values = index.distinctValues("1; DROP TABLE flows; --");
    EXPECT_TRUE(values.empty());
}

TEST(SqliteFlowIndex, optimize_doesNotThrow) {
    auto dbPath = fs::temp_directory_path() / "nids_test_optimize.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    EXPECT_NO_THROW(index.optimize());
}

TEST(SqliteFlowIndex, query_emptyDatabase_returnsEmpty) {
    auto dbPath = fs::temp_directory_path() / "nids_test_empty.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);

    core::FlowQuery q;
    EXPECT_EQ(index.count(q), 0u);
    EXPECT_TRUE(index.query(q).empty());
}

TEST(SqliteFlowIndex, query_filterByProtocol) {
    auto dbPath = fs::temp_directory_path() / "nids_test_filter_proto.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto r = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                        core::DetectionSource::None);

    index.index(makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6), r, "", 0);
    index.index(makeFlow("10.0.0.1", "1.1.1.1", 222, 53, 17), r, "", 0);

    core::FlowQuery q;
    q.protocol = static_cast<std::uint8_t>(17);
    EXPECT_EQ(index.count(q), 1u);
}

TEST(SqliteFlowIndex, index_withThreatIntelMatches) {
    auto dbPath = fs::temp_directory_path() / "nids_test_ti_matches.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto flow = makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6);
    auto result = makeResult(core::AttackType::SshBruteForce, 0.8f, 0.75f,
                             core::DetectionSource::MlPlusThreatIntel);
    result.threatIntelMatches.push_back({"10.0.0.1", "feodo", true});

    index.index(flow, result, "test.pcap", 100);

    core::FlowQuery q;
    auto flows = index.query(q);

    ASSERT_EQ(flows.size(), 1u);
    EXPECT_FALSE(flows[0].tiMatchesJson.empty());
    EXPECT_NE(flows[0].tiMatchesJson.find("feodo"), std::string::npos);
}

TEST(SqliteFlowIndex, query_filterByDstIp) {
    auto dbPath = fs::temp_directory_path() / "nids_test_filter_dst.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto r = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                        core::DetectionSource::None);

    index.index(makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6), r, "", 0);
    index.index(makeFlow("10.0.0.2", "2.2.2.2", 222, 80, 6), r, "", 0);

    core::FlowQuery q;
    q.dstIp = "1.1.1.1";
    EXPECT_EQ(index.count(q), 1u);
}

TEST(SqliteFlowIndex, query_filterBySrcPort) {
    auto dbPath = fs::temp_directory_path() / "nids_test_filter_srcport.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto r = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                        core::DetectionSource::None);

    index.index(makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6), r, "", 0);
    index.index(makeFlow("10.0.0.1", "1.1.1.1", 222, 80, 6), r, "", 0);

    core::FlowQuery q;
    q.srcPort = static_cast<std::uint16_t>(111);
    EXPECT_EQ(index.count(q), 1u);
}

TEST(SqliteFlowIndex, query_filterByDstPort) {
    auto dbPath = fs::temp_directory_path() / "nids_test_filter_dstport.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto r = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                        core::DetectionSource::None);

    index.index(makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6), r, "", 0);
    index.index(makeFlow("10.0.0.1", "1.1.1.1", 222, 443, 6), r, "", 0);

    core::FlowQuery q;
    q.dstPort = static_cast<std::uint16_t>(443);
    EXPECT_EQ(index.count(q), 1u);
}

TEST(SqliteFlowIndex, query_filterByDetectionSource) {
    auto dbPath = fs::temp_directory_path() / "nids_test_filter_source.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto flow = makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6);

    index.index(flow,
        makeResult(core::AttackType::DdosUdp, 0.95f, 0.87f,
                   core::DetectionSource::Ensemble), "", 0);
    index.index(flow,
        makeResult(core::AttackType::SynFlood, 0.9f, 0.8f,
                   core::DetectionSource::MlOnly), "", 0);

    core::FlowQuery q;
    q.detectionSource = core::DetectionSource::Ensemble;
    EXPECT_EQ(index.count(q), 1u);
}

TEST(SqliteFlowIndex, query_multipleFilters_combined) {
    auto dbPath = fs::temp_directory_path() / "nids_test_multi_filter.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);

    index.index(makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6),
        makeResult(core::AttackType::SynFlood, 0.9f, 0.85f,
                   core::DetectionSource::MlOnly), "", 0);
    index.index(makeFlow("10.0.0.1", "2.2.2.2", 222, 443, 6),
        makeResult(core::AttackType::DdosUdp, 0.95f, 0.87f,
                   core::DetectionSource::Ensemble), "", 0);
    index.index(makeFlow("10.0.0.2", "1.1.1.1", 333, 80, 17),
        makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                   core::DetectionSource::None), "", 0);

    core::FlowQuery q;
    q.srcIp = "10.0.0.1";
    q.protocol = static_cast<std::uint8_t>(6);
    EXPECT_EQ(index.count(q), 2u);

    q.dstPort = static_cast<std::uint16_t>(443);
    EXPECT_EQ(index.count(q), 1u);
}

TEST(SqliteFlowIndex, query_withTimeRange) {
    auto dbPath = fs::temp_directory_path() / "nids_test_timerange.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto r = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                        core::DetectionSource::None);

    // Insert multiple flows — all get current timestamp.
    for (int i = 0; i < 5; ++i) {
        index.index(makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6), r, "", 0);
    }

    // Query with a wide time range should return all.
    core::FlowQuery q;
    q.startTimeUs = 0;
    q.endTimeUs = 9'999'999'999'999'999; // ~year 2286
    EXPECT_EQ(index.count(q), 5u);

    // Query with a very old time range should return none.
    core::FlowQuery q2;
    q2.startTimeUs = 1;
    q2.endTimeUs = 2;
    EXPECT_EQ(index.count(q2), 0u);
}

TEST(SqliteFlowIndex, query_noFlaggedFlows_flaggedOnlyReturnsEmpty) {
    auto dbPath = fs::temp_directory_path() / "nids_test_no_flagged.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    index.index(makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6),
        makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                   core::DetectionSource::None), "", 0);

    core::FlowQuery q;
    q.flaggedOnly = true;
    EXPECT_EQ(index.count(q), 0u);
}

TEST(SqliteFlowIndex, aggregate_emptyDb_returnsZeros) {
    auto dbPath = fs::temp_directory_path() / "nids_test_agg_empty.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);

    core::FlowQuery q;
    auto stats = index.aggregate(q);

    EXPECT_EQ(stats.totalFlows, 0u);
    EXPECT_EQ(stats.flaggedFlows, 0u);
    EXPECT_EQ(stats.totalPackets, 0u);
    EXPECT_EQ(stats.totalBytes, 0u);
    EXPECT_FLOAT_EQ(stats.avgCombinedScore, 0.0f);
    EXPECT_FLOAT_EQ(stats.maxCombinedScore, 0.0f);
}

TEST(SqliteFlowIndex, index_multipleFlows_countCorrect) {
    auto dbPath = fs::temp_directory_path() / "nids_test_multi_index.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto r = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                        core::DetectionSource::None);

    for (int i = 0; i < 50; ++i) {
        index.index(
            makeFlow("10.0.0." + std::to_string(i % 10),
                     "1.1.1." + std::to_string(i % 5),
                     static_cast<std::uint16_t>(1000 + i), 80, 6),
            r, "batch.pcap", static_cast<std::size_t>(i));
    }

    core::FlowQuery q;
    EXPECT_EQ(index.count(q), 50u);
}

TEST(SqliteFlowIndex, sizeBytes_growsWithInserts) {
    auto dbPath = fs::temp_directory_path() / "nids_test_sizetrack.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto sizeBefore = index.sizeBytes();

    auto r = makeResult(core::AttackType::DdosUdp, 0.95f, 0.87f,
                        core::DetectionSource::Ensemble);
    for (int i = 0; i < 100; ++i) {
        index.index(makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6),
                    r, "test.pcap", 0);
    }

    EXPECT_GT(index.sizeBytes(), sizeBefore);
}

TEST(SqliteFlowIndex, index_withRuleMatches) {
    auto dbPath = fs::temp_directory_path() / "nids_test_rule_matches.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto flow = makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6);
    auto result = makeResult(core::AttackType::PortScanning, 0.6f, 0.55f,
                             core::DetectionSource::MlPlusHeuristic);
    result.ruleMatches.push_back({"rule_a", "Rule A", 0.3f});

    index.index(flow, result, "rules.pcap", 200);

    core::FlowQuery q;
    auto flows = index.query(q);

    ASSERT_EQ(flows.size(), 1u);
    EXPECT_FALSE(flows[0].ruleMatchesJson.empty());
    EXPECT_NE(flows[0].ruleMatchesJson.find("rule_a"), std::string::npos);
}

TEST(SqliteFlowIndex, query_filterByMinCombinedScore) {
    auto dbPath = fs::temp_directory_path() / "nids_test_min_score.db";
    DbGuard guard{dbPath};

    infra::SqliteFlowIndex index(dbPath);
    auto flow = makeFlow("10.0.0.1", "1.1.1.1", 111, 80, 6);

    index.index(flow,
        makeResult(core::AttackType::Benign, 0.99f, 0.1f,
                   core::DetectionSource::None), "", 0);
    index.index(flow,
        makeResult(core::AttackType::DdosUdp, 0.95f, 0.87f,
                   core::DetectionSource::Ensemble), "", 0);
    index.index(flow,
        makeResult(core::AttackType::SynFlood, 0.9f, 0.6f,
                   core::DetectionSource::MlOnly), "", 0);

    core::FlowQuery q;
    q.minCombinedScore = 0.5f;
    EXPECT_EQ(index.count(q), 2u);
}
