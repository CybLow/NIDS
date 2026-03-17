#include "infra/output/JsonFileSink.h"

#include "core/model/AttackType.h"
#include "core/model/DetectionResult.h"
#include "core/model/DetectionSource.h"
#include "core/model/FlowInfo.h"

#include <nlohmann/json.hpp>
#include <gtest/gtest.h>

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>

using namespace nids;
namespace fs = std::filesystem;

namespace {

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

core::FlowInfo makeFlow(const std::string& srcIp, const std::string& dstIp,
                         std::uint16_t srcPort, std::uint16_t dstPort,
                         std::uint8_t proto) {
    core::FlowInfo f;
    f.srcIp = srcIp;
    f.dstIp = dstIp;
    f.srcPort = srcPort;
    f.dstPort = dstPort;
    f.protocol = proto;
    f.totalFwdPackets = 100;
    f.totalBwdPackets = 50;
    f.flowDurationUs = 5000000.0;
    f.avgPacketSize = 512.0;
    return f;
}

/// Count lines in a file.
std::size_t countLines(const fs::path& path) {
    std::ifstream f(path);
    std::size_t count = 0;
    std::string line;
    while (std::getline(f, line)) {
        ++count;
    }
    return count;
}

/// RAII helper to remove test files on scope exit.
struct TestFileGuard {
    fs::path path;
    ~TestFileGuard() {
        std::error_code ec;
        fs::remove(path, ec);
        // Also remove rotated files
        for (int i = 1; i <= 10; ++i) {
            auto rotated = path;
            rotated += "." + std::to_string(i);
            fs::remove(rotated, ec);
        }
    }
};

} // namespace

TEST(JsonFileSink, toJson_producesValidJson) {
    auto result = makeResult(core::AttackType::DdosUdp, 0.95f, 0.87f,
                             core::DetectionSource::Ensemble);
    auto flow = makeFlow("10.0.0.1", "192.168.1.100", 54321, 80, 17);

    auto jsonStr = infra::JsonFileSink::toJson(42, result, flow);
    auto j = nlohmann::json::parse(jsonStr);

    EXPECT_EQ(j["flowIndex"], 42);
    EXPECT_EQ(j["flow"]["srcIp"], "10.0.0.1");
    EXPECT_EQ(j["flow"]["dstIp"], "192.168.1.100");
    EXPECT_EQ(j["flow"]["srcPort"], 54321);
    EXPECT_EQ(j["flow"]["dstPort"], 80);
    EXPECT_EQ(j["flow"]["protocol"], 17);
    EXPECT_EQ(j["flow"]["protocolName"], "UDP");
}

TEST(JsonFileSink, toJson_containsDetectionFields) {
    auto result = makeResult(core::AttackType::SshBruteForce, 0.85f, 0.78f,
                             core::DetectionSource::MlOnly);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 22222, 22, 6);

    auto jsonStr = infra::JsonFileSink::toJson(1, result, flow);
    auto j = nlohmann::json::parse(jsonStr);

    EXPECT_EQ(j["detection"]["finalVerdict"], "SSH Brute Force");
    EXPECT_FLOAT_EQ(j["detection"]["combinedScore"].get<float>(), 0.78f);
    EXPECT_EQ(j["detection"]["detectionSource"], "ML Classifier");
    EXPECT_TRUE(j["detection"]["isFlagged"].get<bool>());
}

TEST(JsonFileSink, toJson_containsMlPrediction) {
    auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                             core::DetectionSource::None);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    auto jsonStr = infra::JsonFileSink::toJson(0, result, flow);
    auto j = nlohmann::json::parse(jsonStr);

    EXPECT_EQ(j["detection"]["ml"]["classification"], "Benign");
    EXPECT_FLOAT_EQ(j["detection"]["ml"]["confidence"].get<float>(), 0.99f);
    EXPECT_EQ(j["detection"]["ml"]["probabilities"].size(), 16u);
    EXPECT_FALSE(j["detection"]["isFlagged"].get<bool>());
}

TEST(JsonFileSink, toJson_containsThreatIntelMatches) {
    auto result = makeResult(core::AttackType::SshBruteForce, 0.8f, 0.75f,
                             core::DetectionSource::MlPlusThreatIntel);
    result.threatIntelMatches.push_back({"10.0.0.1", "feodo", true});
    result.threatIntelMatches.push_back({"192.168.1.1", "spamhaus", false});

    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 22222, 22, 6);

    auto jsonStr = infra::JsonFileSink::toJson(0, result, flow);
    auto j = nlohmann::json::parse(jsonStr);

    EXPECT_EQ(j["detection"]["threatIntel"].size(), 2u);
    EXPECT_EQ(j["detection"]["threatIntel"][0]["ip"], "10.0.0.1");
    EXPECT_EQ(j["detection"]["threatIntel"][0]["feed"], "feodo");
    EXPECT_EQ(j["detection"]["threatIntel"][0]["direction"], "source");
    EXPECT_EQ(j["detection"]["threatIntel"][1]["direction"], "destination");
}

TEST(JsonFileSink, toJson_containsRuleMatches) {
    auto result = makeResult(core::AttackType::PortScanning, 0.6f, 0.55f,
                             core::DetectionSource::MlPlusHeuristic);
    result.ruleMatches.push_back({"suspicious_port", "Port is suspicious", 0.5f});

    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 44444, 4444, 6);

    auto jsonStr = infra::JsonFileSink::toJson(0, result, flow);
    auto j = nlohmann::json::parse(jsonStr);

    EXPECT_EQ(j["detection"]["heuristicRules"].size(), 1u);
    EXPECT_EQ(j["detection"]["heuristicRules"][0]["name"], "suspicious_port");
    EXPECT_FLOAT_EQ(j["detection"]["heuristicRules"][0]["severity"].get<float>(), 0.5f);
}

TEST(JsonFileSink, toJson_containsTimestamp) {
    auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                             core::DetectionSource::None);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    auto jsonStr = infra::JsonFileSink::toJson(0, result, flow);
    auto j = nlohmann::json::parse(jsonStr);

    EXPECT_TRUE(j.contains("timestamp_ms"));
    EXPECT_GT(j["timestamp_ms"].get<int64_t>(), 0);
}

TEST(JsonFileSink, toJson_containsFlowMetrics) {
    auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                             core::DetectionSource::None);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    auto jsonStr = infra::JsonFileSink::toJson(0, result, flow);
    auto j = nlohmann::json::parse(jsonStr);

    EXPECT_EQ(j["flow"]["totalFwdPackets"], 100u);
    EXPECT_EQ(j["flow"]["totalBwdPackets"], 50u);
    EXPECT_DOUBLE_EQ(j["flow"]["flowDurationUs"].get<double>(), 5000000.0);
    EXPECT_DOUBLE_EQ(j["flow"]["avgPacketSize"].get<double>(), 512.0);
}

TEST(JsonFileSink, startStop_writesToFile) {
    auto tmpPath = fs::temp_directory_path() / "nids_test_jsonfile.jsonl";
    TestFileGuard guard{tmpPath};

    infra::JsonFileConfig cfg;
    cfg.outputPath = tmpPath;
    cfg.appendMode = false;

    infra::JsonFileSink sink(std::move(cfg));
    ASSERT_TRUE(sink.start());

    auto result = makeResult(core::AttackType::DdosUdp, 0.95f, 0.87f,
                             core::DetectionSource::Ensemble);
    auto flow = makeFlow("10.0.0.1", "192.168.1.100", 54321, 80, 17);

    sink.onFlowResult(0, result, flow);
    sink.onFlowResult(1, result, flow);
    sink.stop();

    EXPECT_EQ(countLines(tmpPath), 2u);
}

TEST(JsonFileSink, appendMode_appendsToExistingFile) {
    auto tmpPath = fs::temp_directory_path() / "nids_test_jsonfile_append.jsonl";
    TestFileGuard guard{tmpPath};

    // Write initial content
    {
        std::ofstream ofs(tmpPath, std::ios::out | std::ios::trunc);
        ofs << "{\"existing\":true}\n";
    }

    infra::JsonFileConfig cfg;
    cfg.outputPath = tmpPath;
    cfg.appendMode = true;

    infra::JsonFileSink sink(std::move(cfg));
    ASSERT_TRUE(sink.start());

    auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                             core::DetectionSource::None);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    sink.onFlowResult(0, result, flow);
    sink.stop();

    EXPECT_EQ(countLines(tmpPath), 2u);
}

TEST(JsonFileSink, name_returnsJsonFileSink) {
    infra::JsonFileConfig cfg;
    infra::JsonFileSink sink(std::move(cfg));

    EXPECT_EQ(sink.name(), "JsonFileSink");
}

TEST(JsonFileSink, rotation_rotatesWhenSizeExceeded) {
    auto tmpPath = fs::temp_directory_path() / "nids_test_rotate.jsonl";
    TestFileGuard guard{tmpPath};

    infra::JsonFileConfig cfg;
    cfg.outputPath = tmpPath;
    cfg.appendMode = false;
    cfg.maxFileSizeBytes = 100;  // Very small for testing
    cfg.maxFiles = 3;

    infra::JsonFileSink sink(std::move(cfg));
    ASSERT_TRUE(sink.start());

    auto result = makeResult(core::AttackType::DdosUdp, 0.95f, 0.87f,
                             core::DetectionSource::Ensemble);
    auto flow = makeFlow("10.0.0.1", "192.168.1.100", 54321, 80, 17);

    // Write enough entries to trigger rotation
    for (int i = 0; i < 10; ++i) {
        sink.onFlowResult(static_cast<std::size_t>(i), result, flow);
    }
    sink.stop();

    // The rotated file .1 should exist
    auto rotated1 = tmpPath;
    rotated1 += ".1";
    EXPECT_TRUE(fs::exists(rotated1));
}

TEST(JsonFileSink, eachLine_isValidJson) {
    auto tmpPath = fs::temp_directory_path() / "nids_test_validjson.jsonl";
    TestFileGuard guard{tmpPath};

    infra::JsonFileConfig cfg;
    cfg.outputPath = tmpPath;
    cfg.appendMode = false;

    infra::JsonFileSink sink(std::move(cfg));
    ASSERT_TRUE(sink.start());

    auto result = makeResult(core::AttackType::SynFlood, 0.9f, 0.85f,
                             core::DetectionSource::MlOnly);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    sink.onFlowResult(0, result, flow);
    sink.onFlowResult(1, result, flow);
    sink.onFlowResult(2, result, flow);
    sink.stop();

    std::ifstream f(tmpPath);
    std::string line;
    int lineNum = 0;
    while (std::getline(f, line)) {
        EXPECT_NO_THROW({
            auto parsed = nlohmann::json::parse(line);
            (void)parsed;
        }) << "Line " << lineNum << " is not valid JSON: " << line;
        ++lineNum;
    }
    EXPECT_EQ(lineNum, 3);
}

TEST(JsonFileSink, stop_beforeStart_isNoOp) {
    infra::JsonFileConfig cfg;
    infra::JsonFileSink sink(std::move(cfg));

    // stop() on a non-started sink should not crash.
    EXPECT_NO_THROW(sink.stop());
}

TEST(JsonFileSink, destructor_beforeStart_isNoOp) {
    EXPECT_NO_THROW({
        infra::JsonFileConfig cfg;
        infra::JsonFileSink sink(std::move(cfg));
    });
}

TEST(JsonFileSink, start_createsParentDirectory) {
    auto tmpDir = fs::temp_directory_path() / "nids_test_mkdir_parent";
    auto tmpPath = tmpDir / "sub" / "alerts.jsonl";
    // Ensure directory does not exist
    std::error_code ec;
    fs::remove_all(tmpDir, ec);

    infra::JsonFileConfig cfg;
    cfg.outputPath = tmpPath;
    cfg.appendMode = false;

    infra::JsonFileSink sink(std::move(cfg));
    ASSERT_TRUE(sink.start());
    sink.stop();

    EXPECT_TRUE(fs::exists(tmpPath));

    // Cleanup
    fs::remove_all(tmpDir, ec);
}

TEST(JsonFileSink, start_truncateMode_overwritesExistingFile) {
    auto tmpPath = fs::temp_directory_path() / "nids_test_truncate.jsonl";
    TestFileGuard guard{tmpPath};

    // Write initial data
    {
        std::ofstream ofs(tmpPath, std::ios::out | std::ios::trunc);
        ofs << "{\"old\":1}\n{\"old\":2}\n";
    }
    ASSERT_EQ(countLines(tmpPath), 2u);

    infra::JsonFileConfig cfg;
    cfg.outputPath = tmpPath;
    cfg.appendMode = false;

    infra::JsonFileSink sink(std::move(cfg));
    ASSERT_TRUE(sink.start());

    auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                             core::DetectionSource::None);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    sink.onFlowResult(0, result, flow);
    sink.stop();

    // Should have exactly 1 line (old content truncated)
    EXPECT_EQ(countLines(tmpPath), 1u);
}

TEST(JsonFileSink, rotation_createsMultipleBackups) {
    auto tmpPath = fs::temp_directory_path() / "nids_test_multi_rotate.jsonl";
    TestFileGuard guard{tmpPath};

    infra::JsonFileConfig cfg;
    cfg.outputPath = tmpPath;
    cfg.appendMode = false;
    cfg.maxFileSizeBytes = 50;   // Tiny threshold
    cfg.maxFiles = 3;

    infra::JsonFileSink sink(std::move(cfg));
    ASSERT_TRUE(sink.start());

    auto result = makeResult(core::AttackType::DdosUdp, 0.95f, 0.87f,
                             core::DetectionSource::Ensemble);
    auto flow = makeFlow("10.0.0.1", "192.168.1.100", 54321, 80, 17);

    // Write enough to trigger multiple rotations
    for (int i = 0; i < 20; ++i) {
        sink.onFlowResult(static_cast<std::size_t>(i), result, flow);
    }
    sink.stop();

    // Both .1 and .2 should exist
    auto rotated1 = tmpPath;
    rotated1 += ".1";
    auto rotated2 = tmpPath;
    rotated2 += ".2";
    EXPECT_TRUE(fs::exists(rotated1));
    EXPECT_TRUE(fs::exists(rotated2));
}

TEST(JsonFileSink, onFlowResult_afterStop_doesNotCrash) {
    auto tmpPath = fs::temp_directory_path() / "nids_test_afterstop.jsonl";
    TestFileGuard guard{tmpPath};

    infra::JsonFileConfig cfg;
    cfg.outputPath = tmpPath;
    cfg.appendMode = false;

    infra::JsonFileSink sink(std::move(cfg));
    ASSERT_TRUE(sink.start());
    sink.stop();

    auto result = makeResult(core::AttackType::Benign, 0.99f, 0.0f,
                             core::DetectionSource::None);
    auto flow = makeFlow("10.0.0.1", "192.168.1.1", 12345, 80, 6);

    // Writing after stop should increment write errors, not crash
    EXPECT_NO_THROW(sink.onFlowResult(0, result, flow));
}
