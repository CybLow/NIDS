#pragma once

/// IFlowIndex — interface for queryable flow metadata storage.
///
/// Abstracts the database backend (SQLite, DuckDB, etc.) behind a clean
/// interface. Stores flow metadata + detection results for retroactive
/// threat-hunting queries.

#include "core/model/DetectionResult.h"
#include "core/model/FlowInfo.h"
#include "core/model/FlowQuery.h"
#include "core/model/IndexedFlow.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace nids::core {

class IFlowIndex {
public:
    virtual ~IFlowIndex() = default;

    /// Index a completed flow with its detection result.
    virtual void index(const FlowInfo& flow,
                       const DetectionResult& result,
                       std::string_view pcapFile,
                       std::size_t pcapOffset) = 0;

    /// Query flows matching the given criteria.
    [[nodiscard]] virtual std::vector<IndexedFlow> query(
        const FlowQuery& query) = 0;

    /// Count flows matching criteria (faster than full query).
    [[nodiscard]] virtual std::size_t count(
        const FlowQuery& query) const = 0;

    /// Get distinct values for a field (for autocomplete/filters).
    [[nodiscard]] virtual std::vector<std::string> distinctValues(
        std::string_view field,
        std::size_t limit = 100) const = 0;

    /// Aggregate statistics over matching flows.
    [[nodiscard]] virtual FlowStatsSummary aggregate(
        const FlowQuery& query) const = 0;

    /// Vacuum/optimize the database.
    virtual void optimize() = 0;

    /// Database size in bytes.
    [[nodiscard]] virtual std::size_t sizeBytes() const noexcept = 0;
};

} // namespace nids::core
