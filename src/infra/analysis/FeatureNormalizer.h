#pragma once

/// Feature normalizer for ML inference.
///
/// Reads normalization parameters (means, stds, clip_value) from the
/// model_metadata.json file and applies StandardScaler normalization
/// followed by value clipping. This ensures the C++ inference pipeline
/// receives data in the same format the model was trained on.
///
/// Implements core::IFeatureNormalizer (Dependency Inversion Principle).
///
/// Usage:
///   FeatureNormalizer normalizer;
///   if (!normalizer.loadMetadata("model_metadata.json")) { handle error }
///   auto normalized = normalizer.normalize(rawFeatures);
///   auto attackType = analyzer->predict(normalized);

#include "core/services/IFeatureNormalizer.h"

#include <span>
#include <string>
#include <vector>

namespace nids::infra {

/** StandardScaler feature normalizer backed by model metadata JSON. */
class FeatureNormalizer : public core::IFeatureNormalizer {
public:
    FeatureNormalizer() = default;

    /// Load normalization parameters from a model metadata JSON file.
    /// Reads: normalization.means, normalization.stds, normalization.clip_value
    /// Returns void on success, or an error message string on failure.
    [[nodiscard]] std::expected<void, std::string> loadMetadata(
        const std::string& metadataPath) override;

    /// Apply StandardScaler normalization: (x - mean) / std, then clip to
    /// [-clip_value, clip_value]. Returns a new vector of normalized features.
    /// If metadata was not loaded or feature count mismatches, returns the
    /// input unchanged with a warning.
    [[nodiscard]] std::vector<float> normalize(std::span<const float> features) const override;

    /// Check whether normalization parameters have been loaded.
    [[nodiscard]] bool isLoaded() const noexcept override { return loaded_; }

    /// Number of features expected by the normalizer.
    [[nodiscard]] std::size_t featureCount() const noexcept override { return means_.size(); }

private:
    std::vector<float> means_;
    std::vector<float> stds_;
    float clipValue_ = 10.0f;
    bool loaded_ = false;
};

} // namespace nids::infra
