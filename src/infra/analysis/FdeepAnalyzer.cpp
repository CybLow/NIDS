#include "infra/analysis/FdeepAnalyzer.h"

#include <fdeep/fdeep.hpp>
#include <iostream>
#include <algorithm>

namespace nids::infra {

FdeepAnalyzer::FdeepAnalyzer() = default;
FdeepAnalyzer::~FdeepAnalyzer() = default;

bool FdeepAnalyzer::loadModel(const std::string& modelPath) {
    try {
        model_ = std::make_unique<fdeep::model>(fdeep::load_model(modelPath));
        loaded_ = true;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to load model: " << e.what() << std::endl;
        loaded_ = false;
        return false;
    }
}

nids::core::AttackType FdeepAnalyzer::predict(const std::vector<float>& features) {
    if (!loaded_ || !model_) {
        return nids::core::AttackType::Unknown;
    }

    try {
        const auto result = model_->predict(
            {fdeep::tensor(fdeep::tensor_shape(static_cast<std::size_t>(features.size())), features)});

        if (result.empty()) {
            return nids::core::AttackType::Unknown;
        }

        const auto& output = *result[0].as_vector();
        auto maxIt = std::max_element(output.begin(), output.end());
        int maxIndex = static_cast<int>(std::distance(output.begin(), maxIt));

        return nids::core::attackTypeFromIndex(maxIndex);
    } catch (const std::exception&) {
        return nids::core::AttackType::Unknown;
    }
}

} // namespace nids::infra
