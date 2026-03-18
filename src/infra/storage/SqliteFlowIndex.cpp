#include "infra/storage/SqliteFlowIndex.h"

#include "core/model/AttackType.h"
#include "core/model/DetectionSource.h"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iterator>
#include <ranges>
#include <stdexcept>
#include <utility>

namespace nids::infra {

namespace fs = std::filesystem;

namespace {

/// RAII wrapper for sqlite3_stmt (auto-finalize).
struct StmtDeleter {
    void operator()(sqlite3_stmt* s) const noexcept {
        if (s) sqlite3_finalize(s);
    }
};
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

/// Prepare a statement, throwing on failure.
[[nodiscard]] StmtPtr prepare(sqlite3* db, std::string_view sql) {
    sqlite3_stmt* raw = nullptr;
    const int rc = sqlite3_prepare_v2(
        db, sql.data(), static_cast<int>(sql.size()), &raw, nullptr);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(
            std::string("SQLite prepare failed: ") + sqlite3_errmsg(db));
    }
    return StmtPtr(raw);
}

/// Serialize ThreatIntelMatch vector to JSON string.
[[nodiscard]] std::string serializeTiMatches(
    const std::vector<core::ThreatIntelMatch>& matches) {
    if (matches.empty()) return "[]";
    nlohmann::json arr = nlohmann::json::array();
    std::ranges::transform(matches, std::back_inserter(arr),
        [](const auto& m) -> nlohmann::json {
            return {{"ip", m.ip}, {"feed", m.feedName},
                    {"src", m.isSource}};
        });
    return arr.dump();
}

/// Serialize RuleMatch vector to JSON string.
[[nodiscard]] std::string serializeRuleMatches(
    const std::vector<core::RuleMatch>& matches) {
    if (matches.empty()) return "[]";
    nlohmann::json arr = nlohmann::json::array();
    std::ranges::transform(matches, std::back_inserter(arr),
        [](const auto& r) -> nlohmann::json {
            return {{"name", r.ruleName}, {"desc", r.description},
                    {"sev", r.severity}};
        });
    return arr.dump();
}

/// Allowed columns for distinctValues (prevent SQL injection).
[[nodiscard]] bool isAllowedField(std::string_view field) {
    static constexpr std::array kAllowed = {
        std::string_view{"src_ip"},    std::string_view{"dst_ip"},
        std::string_view{"verdict"},   std::string_view{"detection_source"},
        std::string_view{"protocol"},  std::string_view{"dst_port"},
    };
    return std::ranges::find(kAllowed, field) != kAllowed.end();
}

} // anonymous namespace

// ── Construction / Destruction ──────────────────────────────────────

SqliteFlowIndex::SqliteFlowIndex(const fs::path& dbPath)
    : dbPath_(dbPath) {
    openDatabase(dbPath);
    createSchema();
}

SqliteFlowIndex::~SqliteFlowIndex() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

void SqliteFlowIndex::openDatabase(const fs::path& dbPath) {
    // Ensure parent directory exists.
    if (dbPath.has_parent_path()) {
        std::error_code ec;
        fs::create_directories(dbPath.parent_path(), ec);
    }

    const int rc = sqlite3_open(dbPath.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::string msg = "SqliteFlowIndex: cannot open database: ";
        msg += sqlite3_errmsg(db_);
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error(msg);
    }

    // Enable WAL mode for concurrent read/write.
    exec("PRAGMA journal_mode=WAL");
    exec("PRAGMA synchronous=NORMAL");
    exec("PRAGMA foreign_keys=ON");

    spdlog::info("SqliteFlowIndex: opened database '{}'", dbPath.string());
}

void SqliteFlowIndex::createSchema() {
    static constexpr std::string_view kSchema = R"SQL(
CREATE TABLE IF NOT EXISTS flows (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_us    INTEGER NOT NULL,
    src_ip          TEXT NOT NULL,
    dst_ip          TEXT NOT NULL,
    src_port        INTEGER NOT NULL,
    dst_port        INTEGER NOT NULL,
    protocol        INTEGER NOT NULL,
    packet_count    INTEGER,
    byte_count      INTEGER,
    duration_us     INTEGER,
    verdict         TEXT NOT NULL,
    ml_confidence   REAL,
    combined_score  REAL,
    detection_source TEXT,
    is_flagged      INTEGER NOT NULL DEFAULT 0,
    ti_matches      TEXT,
    rule_matches    TEXT,
    pcap_file       TEXT,
    pcap_offset     INTEGER,
    created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE INDEX IF NOT EXISTS idx_flows_timestamp
    ON flows(timestamp_us);
CREATE INDEX IF NOT EXISTS idx_flows_src_ip
    ON flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst_ip
    ON flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_verdict
    ON flows(verdict);
CREATE INDEX IF NOT EXISTS idx_flows_flagged
    ON flows(is_flagged) WHERE is_flagged = 1;
CREATE INDEX IF NOT EXISTS idx_flows_combined_score
    ON flows(combined_score);
CREATE INDEX IF NOT EXISTS idx_flows_src_dst
    ON flows(src_ip, dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_ports
    ON flows(dst_port, protocol);
)SQL";

    exec(kSchema);
}

void SqliteFlowIndex::exec(std::string_view sql) {
    char* errMsg = nullptr;
    const int rc = sqlite3_exec(
        db_, std::string(sql).c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::string msg = "SQLite exec failed: ";
        if (errMsg) {
            msg += errMsg;
            sqlite3_free(errMsg);
        }
        throw std::runtime_error(msg);
    }
}

// ── index() ─────────────────────────────────────────────────────────

void SqliteFlowIndex::index(const core::FlowInfo& flow,
                            const core::DetectionResult& result,
                            std::string_view pcapFile,
                            std::size_t pcapOffset) {
    static constexpr std::string_view kInsert = R"SQL(
INSERT INTO flows (
    timestamp_us, src_ip, dst_ip, src_port, dst_port, protocol,
    packet_count, byte_count, duration_us,
    verdict, ml_confidence, combined_score, detection_source,
    is_flagged, ti_matches, rule_matches, pcap_file, pcap_offset
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
)SQL";

    using namespace std::chrono;
    const auto nowUs = duration_cast<microseconds>(
        system_clock::now().time_since_epoch()).count();

    const auto verdictStr = std::string{
        core::attackTypeToString(result.finalVerdict)};
    const auto sourceStr = std::string{
        core::detectionSourceToString(result.detectionSource)};
    const auto tiJson = serializeTiMatches(result.threatIntelMatches);
    const auto ruleJson = serializeRuleMatches(result.ruleMatches);
    const auto packetCount = static_cast<int64_t>(
        flow.totalFwdPackets + flow.totalBwdPackets);

    std::scoped_lock lock{mutex_};
    auto stmt = prepare(db_, kInsert);

    sqlite3_bind_int64(stmt.get(), 1, nowUs);
    sqlite3_bind_text(stmt.get(), 2, flow.srcIp.c_str(),
                      static_cast<int>(flow.srcIp.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, flow.dstIp.c_str(),
                      static_cast<int>(flow.dstIp.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt.get(), 4, flow.srcPort);
    sqlite3_bind_int(stmt.get(), 5, flow.dstPort);
    sqlite3_bind_int(stmt.get(), 6, flow.protocol);
    sqlite3_bind_int64(stmt.get(), 7, packetCount);
    sqlite3_bind_int64(stmt.get(), 8,
        static_cast<int64_t>(flow.avgPacketSize * static_cast<double>(packetCount)));
    sqlite3_bind_int64(stmt.get(), 9,
        static_cast<int64_t>(flow.flowDurationUs));
    sqlite3_bind_text(stmt.get(), 10, verdictStr.c_str(),
                      static_cast<int>(verdictStr.size()), SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt.get(), 11,
                        static_cast<double>(result.mlResult.confidence));
    sqlite3_bind_double(stmt.get(), 12,
                        static_cast<double>(result.combinedScore));
    sqlite3_bind_text(stmt.get(), 13, sourceStr.c_str(),
                      static_cast<int>(sourceStr.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt.get(), 14, result.isFlagged() ? 1 : 0);
    sqlite3_bind_text(stmt.get(), 15, tiJson.c_str(),
                      static_cast<int>(tiJson.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 16, ruleJson.c_str(),
                      static_cast<int>(ruleJson.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 17, pcapFile.data(),
                      static_cast<int>(pcapFile.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 18, static_cast<int64_t>(pcapOffset));

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        spdlog::warn("SqliteFlowIndex: INSERT failed: {}",
                     sqlite3_errmsg(db_));
    }
}

// ── WHERE clause builder ────────────────────────────────────────────

SqliteFlowIndex::WhereClause SqliteFlowIndex::buildWhereClause(
    const core::FlowQuery& query) const {

    WhereClause wc;
    std::vector<std::string> conditions;

    if (query.startTimeUs) {
        conditions.emplace_back(
            "timestamp_us >= " + std::to_string(*query.startTimeUs));
    }
    if (query.endTimeUs) {
        conditions.emplace_back(
            "timestamp_us <= " + std::to_string(*query.endTimeUs));
    }
    if (query.srcIp) {
        conditions.emplace_back("src_ip = '" + *query.srcIp + "'");
    }
    if (query.dstIp) {
        conditions.emplace_back("dst_ip = '" + *query.dstIp + "'");
    }
    if (query.anyIp) {
        conditions.emplace_back(
            "(src_ip = '" + *query.anyIp + "' OR dst_ip = '" +
            *query.anyIp + "')");
    }
    if (query.srcPort) {
        conditions.emplace_back(
            "src_port = " + std::to_string(*query.srcPort));
    }
    if (query.dstPort) {
        conditions.emplace_back(
            "dst_port = " + std::to_string(*query.dstPort));
    }
    if (query.anyPort) {
        conditions.emplace_back(
            "(src_port = " + std::to_string(*query.anyPort) +
            " OR dst_port = " + std::to_string(*query.anyPort) + ")");
    }
    if (query.protocol) {
        conditions.emplace_back(
            "protocol = " + std::to_string(*query.protocol));
    }
    if (query.verdict) {
        const auto vs = std::string{core::attackTypeToString(*query.verdict)};
        conditions.emplace_back("verdict = '" + vs + "'");
    }
    if (query.flaggedOnly && *query.flaggedOnly) {
        conditions.emplace_back("is_flagged = 1");
    }
    if (query.minCombinedScore) {
        conditions.emplace_back(
            "combined_score >= " + std::to_string(*query.minCombinedScore));
    }
    if (query.detectionSource) {
        const auto ds = std::string{
            core::detectionSourceToString(*query.detectionSource)};
        conditions.emplace_back("detection_source = '" + ds + "'");
    }

    if (conditions.empty()) {
        wc.sql = "1=1";
    } else {
        wc.sql = conditions[0];
        for (std::size_t i = 1; i < conditions.size(); ++i) {
            wc.sql += " AND " + conditions[i];
        }
    }
    return wc;
}

// ── query() ─────────────────────────────────────────────────────────

std::vector<core::IndexedFlow> SqliteFlowIndex::query(
    const core::FlowQuery& q) {

    auto wc = buildWhereClause(q);
    std::string sql = "SELECT id, timestamp_us, src_ip, dst_ip, src_port, "
                      "dst_port, protocol, packet_count, byte_count, "
                      "duration_us, verdict, ml_confidence, combined_score, "
                      "detection_source, is_flagged, ti_matches, "
                      "rule_matches, pcap_file, pcap_offset, created_at "
                      "FROM flows WHERE " + wc.sql +
                      " ORDER BY " + q.orderBy +
                      " LIMIT " + std::to_string(q.limit) +
                      " OFFSET " + std::to_string(q.offset);

    std::scoped_lock lock{mutex_};
    auto stmt = prepare(db_, sql);

    std::vector<core::IndexedFlow> results;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        core::IndexedFlow f;
        f.id = sqlite3_column_int64(stmt.get(), 0);
        f.timestampUs = sqlite3_column_int64(stmt.get(), 1);

        auto text = [&](int col) -> std::string {
            const auto* p = reinterpret_cast<const char*>( // NOLINT
                sqlite3_column_text(stmt.get(), col));
            return p ? std::string(p) : std::string{};
        };

        f.srcIp = text(2);
        f.dstIp = text(3);
        f.srcPort = static_cast<std::uint16_t>(
            sqlite3_column_int(stmt.get(), 4));
        f.dstPort = static_cast<std::uint16_t>(
            sqlite3_column_int(stmt.get(), 5));
        f.protocol = static_cast<std::uint8_t>(
            sqlite3_column_int(stmt.get(), 6));
        f.packetCount = static_cast<std::size_t>(
            sqlite3_column_int64(stmt.get(), 7));
        f.byteCount = static_cast<std::size_t>(
            sqlite3_column_int64(stmt.get(), 8));
        f.durationUs = sqlite3_column_int64(stmt.get(), 9);
        f.verdict = core::attackTypeFromString(text(10));
        f.mlConfidence = static_cast<float>(
            sqlite3_column_double(stmt.get(), 11));
        f.combinedScore = static_cast<float>(
            sqlite3_column_double(stmt.get(), 12));
        f.detectionSource = core::detectionSourceFromString(text(13));
        f.isFlagged = sqlite3_column_int(stmt.get(), 14) != 0;
        f.tiMatchesJson = text(15);
        f.ruleMatchesJson = text(16);
        f.pcapFile = text(17);
        f.pcapOffset = static_cast<std::size_t>(
            sqlite3_column_int64(stmt.get(), 18));
        f.createdAt = sqlite3_column_int64(stmt.get(), 19);

        results.push_back(std::move(f));
    }
    return results;
}

// ── count() ─────────────────────────────────────────────────────────

std::size_t SqliteFlowIndex::count(const core::FlowQuery& q) const {
    auto wc = buildWhereClause(q);
    std::string sql = "SELECT COUNT(*) FROM flows WHERE " + wc.sql;

    std::scoped_lock lock{mutex_};
    auto stmt = prepare(db_, sql);

    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return static_cast<std::size_t>(sqlite3_column_int64(stmt.get(), 0));
    }
    return 0;
}

// ── distinctValues() ────────────────────────────────────────────────

std::vector<std::string> SqliteFlowIndex::distinctValues(
    std::string_view field, std::size_t limit) const {

    if (!isAllowedField(field)) {
        spdlog::warn("SqliteFlowIndex: distinctValues called with "
                     "disallowed field '{}'", field);
        return {};
    }

    std::string sql = "SELECT DISTINCT " + std::string(field) +
                      " FROM flows ORDER BY " + std::string(field) +
                      " LIMIT " + std::to_string(limit);

    std::scoped_lock lock{mutex_};
    auto stmt = prepare(db_, sql);

    std::vector<std::string> values;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        const auto* p = reinterpret_cast<const char*>( // NOLINT
            sqlite3_column_text(stmt.get(), 0));
        if (p) values.emplace_back(p);
    }
    return values;
}

// ── aggregate() ─────────────────────────────────────────────────────

core::FlowStatsSummary SqliteFlowIndex::aggregate(
    const core::FlowQuery& q) const {

    auto wc = buildWhereClause(q);
    std::string sql =
        "SELECT COUNT(*), "
        "SUM(CASE WHEN is_flagged = 1 THEN 1 ELSE 0 END), "
        "COALESCE(SUM(packet_count), 0), "
        "COALESCE(SUM(byte_count), 0), "
        "COALESCE(AVG(combined_score), 0.0), "
        "COALESCE(MAX(combined_score), 0.0) "
        "FROM flows WHERE " + wc.sql;

    std::scoped_lock lock{mutex_};
    auto stmt = prepare(db_, sql);

    core::FlowStatsSummary stats;
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        stats.totalFlows = static_cast<std::size_t>(
            sqlite3_column_int64(stmt.get(), 0));
        stats.flaggedFlows = static_cast<std::size_t>(
            sqlite3_column_int64(stmt.get(), 1));
        stats.totalPackets = static_cast<std::size_t>(
            sqlite3_column_int64(stmt.get(), 2));
        stats.totalBytes = static_cast<std::size_t>(
            sqlite3_column_int64(stmt.get(), 3));
        stats.avgCombinedScore = static_cast<float>(
            sqlite3_column_double(stmt.get(), 4));
        stats.maxCombinedScore = static_cast<float>(
            sqlite3_column_double(stmt.get(), 5));
    }
    return stats;
}

// ── optimize() / sizeBytes() ────────────────────────────────────────

void SqliteFlowIndex::optimize() {
    std::scoped_lock lock{mutex_};
    exec("ANALYZE");
}

std::size_t SqliteFlowIndex::sizeBytes() const noexcept {
    std::error_code ec;
    const auto size = fs::file_size(dbPath_, ec);
    return ec ? 0 : static_cast<std::size_t>(size);
}

} // namespace nids::infra
