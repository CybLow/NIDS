#pragma once

/// Interface for feature normalization before ML inference.
///
/// Abstracts the StandardScaler normalization step so that app/ layer code
/// can depend on this interface without pulling in infrastructure details
/// (nlohmann::json, spdlog, etc.). Concrete implementations live in infra/.
///
/// Defined in core/ to satisfy the Dependency Inversion Principle
/// (AGENTS.md 1.1, 1.3).

#include <string>
#include <vector>

namespace nids::core {

/** Abstract interface for feature normalization before ML inference. */
class IFeatureNormalizer {
public:
    virtual ~IFeatureNormalizer() = default;

    /// Load normalization parameters (means, stds, clip_value) from a
    /// model metadata file. Returns false on failure.
    [[nodiscard]] virtual bool loadMetadata(const std::string& metadataPath) = 0;

    /// Apply normalization to a raw feature vector.
    /// If metadata was not loaded or feature count mismatches, returns the
    /// input unchanged with a warning (graceful degradation).
    [[nodiscard]] virtual std::vector<float> normalize(
        const std::vector<float>& features) const = 0;

    /// Check whether normalization parameters have been loaded.
    [[nodiscard]] virtual bool isLoaded() const noexcept = 0;

    /// Number of features expected by the normalizer.
    [[nodiscard]] virtual std::size_t featureCount() const noexcept = 0;
};

} // namespace nids::core
