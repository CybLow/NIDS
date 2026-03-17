#pragma once

/// SQLite-backed flow metadata index for retroactive threat hunting.
///
/// Stores flow 5-tuple, detection results, and PCAP file references.
/// Provides indexed queries by IP, port, time range, verdict, and score.

#include "core/services/IFlowIndex.h"

#include <cstddef>
#include <filesystem>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

struct sqlite3;

namespace nids::infra {

class SqliteFlowIndex final : public core::IFlowIndex {
public:
    explicit SqliteFlowIndex(const std::filesystem::path& dbPath);
    ~SqliteFlowIndex() override;

    SqliteFlowIndex(const SqliteFlowIndex&) = delete;
    SqliteFlowIndex& operator=(const SqliteFlowIndex&) = delete;
    SqliteFlowIndex(SqliteFlowIndex&&) = delete;
    SqliteFlowIndex& operator=(SqliteFlowIndex&&) = delete;

    void index(const core::FlowInfo& flow,
               const core::DetectionResult& result,
               std::string_view pcapFile,
               std::size_t pcapOffset) override;

    [[nodiscard]] std::vector<core::IndexedFlow> query(
        const core::FlowQuery& query) override;

    [[nodiscard]] std::size_t count(
        const core::FlowQuery& query) const override;

    [[nodiscard]] std::vector<std::string> distinctValues(
        std::string_view field,
        std::size_t limit = 100) const override;

    [[nodiscard]] core::FlowStatsSummary aggregate(
        const core::FlowQuery& query) const override;

    void optimize() override;

    [[nodiscard]] std::size_t sizeBytes() const noexcept override;

private:
    void openDatabase(const std::filesystem::path& dbPath);
    void createSchema();
    void exec(std::string_view sql);

    /// Build a WHERE clause fragment and bind values from a FlowQuery.
    struct WhereClause {
        std::string sql;
        std::vector<std::string> stringBindings;
        std::vector<double> doubleBindings;
        std::vector<int64_t> intBindings;
    };
    [[nodiscard]] WhereClause buildWhereClause(
        const core::FlowQuery& query) const;

    sqlite3* db_ = nullptr;
    mutable std::mutex mutex_;
    std::filesystem::path dbPath_;
};

} // namespace nids::infra
