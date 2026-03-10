#include "infra/analysis/FeatureNormalizer.h"

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cmath>
#include <fstream>

namespace nids::infra {

bool FeatureNormalizer::loadMetadata(const std::string& metadataPath) {
    try {
        std::ifstream file(metadataPath);
        if (!file.is_open()) {
            spdlog::error("FeatureNormalizer: cannot open metadata file '{}'", metadataPath);
            loaded_ = false;
            return false;
        }

        auto json = nlohmann::json::parse(file);

        if (!json.contains("normalization")) {
            spdlog::error("FeatureNormalizer: metadata file missing 'normalization' key");
            loaded_ = false;
            return false;
        }

        const auto& norm = json["normalization"];

        if (!norm.contains("means") || !norm.contains("stds")) {
            spdlog::error("FeatureNormalizer: normalization section missing 'means' or 'stds'");
            loaded_ = false;
            return false;
        }

        auto meansJson = norm["means"].get<std::vector<double>>();
        auto stdsJson = norm["stds"].get<std::vector<double>>();

        if (meansJson.size() != stdsJson.size()) {
            spdlog::error(
                "FeatureNormalizer: means ({}) and stds ({}) have different sizes",
                meansJson.size(), stdsJson.size());
            loaded_ = false;
            return false;
        }

        means_.resize(meansJson.size());
        stds_.resize(stdsJson.size());

        for (std::size_t i = 0; i < meansJson.size(); ++i) {
            means_[i] = static_cast<float>(meansJson[i]);

            // Guard against near-zero stds to prevent division by zero.
            // The Python preprocessing already replaces these with 1.0,
            // but we add an extra safety net here.
            auto stdVal = static_cast<float>(stdsJson[i]);
            stds_[i] = (std::abs(stdVal) < 1e-8f) ? 1.0f : stdVal;
        }

        if (!norm.contains("clip_value")) {
            spdlog::error("FeatureNormalizer: normalization section missing 'clip_value'");
            loaded_ = false;
            return false;
        }
        clipValue_ = norm["clip_value"].get<float>();

        loaded_ = true;
        spdlog::info(
            "FeatureNormalizer: loaded {} feature normalization params (clip={:.1f})",
            means_.size(), clipValue_);
        return true;

    } catch (const nlohmann::json::exception& e) {
        spdlog::error("FeatureNormalizer: JSON parse error in '{}': {}", metadataPath, e.what());
        loaded_ = false;
        return false;
    } catch (const std::exception& e) {
        spdlog::error("FeatureNormalizer: error loading '{}': {}", metadataPath, e.what());
        loaded_ = false;
        return false;
    }
}

std::vector<float> FeatureNormalizer::normalize(const std::vector<float>& features) const {
    if (!loaded_) [[unlikely]] {
        spdlog::warn("FeatureNormalizer: metadata not loaded, returning raw features");
        return features;
    }

    if (features.size() != means_.size()) [[unlikely]] {
        spdlog::warn(
            "FeatureNormalizer: feature count mismatch (got {}, expected {}), "
            "returning raw features",
            features.size(), means_.size());
        return features;
    }

    std::vector<float> normalized(features.size());

    for (std::size_t i = 0; i < features.size(); ++i) {
        // StandardScaler: (x - mean) / std
        float val = (features[i] - means_[i]) / stds_[i];

        // Clip to [-clip_value, clip_value]
        val = std::clamp(val, -clipValue_, clipValue_);

        normalized[i] = val;
    }

    return normalized;
}

} // namespace nids::infra
