#pragma once

/// Feature normalizer for ML inference.
///
/// Reads normalization parameters (means, stds, clip_value) from the
/// model_metadata.json file and applies StandardScaler normalization
/// followed by value clipping. This ensures the C++ inference pipeline
/// receives data in the same format the model was trained on.
///
/// Usage:
///   FeatureNormalizer normalizer;
///   if (!normalizer.loadMetadata("model_metadata.json")) { /* error */ }
///   auto normalized = normalizer.normalize(rawFeatures);
///   auto attackType = analyzer->predict(normalized);

#include <string>
#include <vector>

namespace nids::infra {

class FeatureNormalizer {
public:
    FeatureNormalizer() = default;

    /// Load normalization parameters from a model metadata JSON file.
    /// Reads: normalization.means, normalization.stds, normalization.clip_value
    /// Returns false if the file cannot be opened or parsed.
    [[nodiscard]] bool loadMetadata(const std::string& metadataPath);

    /// Apply StandardScaler normalization: (x - mean) / std, then clip to
    /// [-clip_value, clip_value]. Returns a new vector of normalized features.
    /// If metadata was not loaded or feature count mismatches, returns the
    /// input unchanged with a warning.
    [[nodiscard]] std::vector<float> normalize(const std::vector<float>& features) const;

    /// Check whether normalization parameters have been loaded.
    [[nodiscard]] bool isLoaded() const noexcept { return loaded_; }

    /// Number of features expected by the normalizer.
    [[nodiscard]] std::size_t featureCount() const noexcept { return means_.size(); }

private:
    std::vector<float> means_;
    std::vector<float> stds_;
    float clipValue_ = 10.0f;
    bool loaded_ = false;
};

} // namespace nids::infra
