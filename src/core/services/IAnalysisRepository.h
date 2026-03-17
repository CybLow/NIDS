#pragma once

/// Abstract repository for storing and retrieving per-flow detection results.
///
/// Follows the Repository pattern (AGENTS.md 5.6) to decouple result storage
/// from CaptureSession's packet storage.  The default implementation is
/// InMemoryAnalysisRepository (infra/analysis/).

#include "core/model/DetectionResult.h"

#include <cstddef>

namespace nids::core {

class IAnalysisRepository {
public:
    virtual ~IAnalysisRepository() = default;

    /// Store a detection result at the given flow index.
    /// If the index exceeds the current size, the repository grows to fit
    /// (intermediate entries get a default result with Unknown verdict).
    virtual void store(std::size_t flowIndex, const DetectionResult& result) = 0;

    /// Retrieve the detection result at the given flow index.
    /// Returns a default result (Unknown verdict) if the index is out of range.
    [[nodiscard]] virtual DetectionResult get(std::size_t flowIndex) const = 0;

    /// Return the number of stored detection results (including default-filled gaps).
    [[nodiscard]] virtual std::size_t size() const noexcept = 0;

    /// Remove all stored detection results.
    virtual void clear() = 0;
};

} // namespace nids::core
