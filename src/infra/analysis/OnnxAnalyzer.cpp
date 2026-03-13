#include "infra/analysis/OnnxAnalyzer.h"
#include "core/services/Configuration.h"

#include <onnxruntime_cxx_api.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <span>

namespace nids::infra {

struct OnnxAnalyzer::Impl {
    Ort::Env env{ORT_LOGGING_LEVEL_WARNING, "NIDS"};
    std::unique_ptr<Ort::Session> session{};
    Ort::MemoryInfo memoryInfo = Ort::MemoryInfo::CreateCpu(
        OrtArenaAllocator, OrtMemTypeDefault);
    std::vector<std::string> inputNamesOwned{};
    std::vector<std::string> outputNamesOwned{};
    std::vector<const char*> inputNames{};
    std::vector<const char*> outputNames{};
    bool loaded = false;
};

OnnxAnalyzer::OnnxAnalyzer()
    : impl_(std::make_unique<Impl>()) {}

OnnxAnalyzer::~OnnxAnalyzer() = default;

bool OnnxAnalyzer::loadModel(const std::string& modelPath) {
    try {
        Ort::SessionOptions sessionOptions;
        const auto threads = nids::core::Configuration::instance().onnxIntraOpThreads();
        sessionOptions.SetIntraOpNumThreads(threads);
        sessionOptions.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);

        impl_->session = std::make_unique<Ort::Session>(
            impl_->env, modelPath.c_str(), sessionOptions);

        Ort::AllocatorWithDefaultOptions allocator;

        // Dynamically query input names from the model
        std::size_t numInputs = impl_->session->GetInputCount();
        impl_->inputNamesOwned.clear();
        impl_->inputNames.clear();
        for (std::size_t i = 0; i < numInputs; ++i) {
            auto name = impl_->session->GetInputNameAllocated(i, allocator);
            impl_->inputNamesOwned.emplace_back(name.get());
        }
        for (const auto& name : impl_->inputNamesOwned) {
            impl_->inputNames.push_back(name.c_str());
        }

        // Dynamically query output names from the model
        std::size_t numOutputs = impl_->session->GetOutputCount();
        impl_->outputNamesOwned.clear();
        impl_->outputNames.clear();
        for (std::size_t i = 0; i < numOutputs; ++i) {
            auto name = impl_->session->GetOutputNameAllocated(i, allocator);
            impl_->outputNamesOwned.emplace_back(name.get());
        }
        for (const auto& name : impl_->outputNamesOwned) {
            impl_->outputNames.push_back(name.c_str());
        }

        impl_->loaded = true;

        spdlog::info("ONNX model loaded: {}", modelPath);
        return true;
    } catch (const Ort::Exception& e) {
        spdlog::error("Failed to load ONNX model: {}", e.what());
        impl_->loaded = false;
        return false;
    }
}

nids::core::AttackType OnnxAnalyzer::predict(const std::vector<float>& features) {
    auto result = predictWithConfidence(features);
    return result.classification;
}

nids::core::PredictionResult OnnxAnalyzer::predictWithConfidence(
    const std::vector<float>& features) {
    nids::core::PredictionResult result;

    if (!impl_->loaded || !impl_->session) {
        return result;  // Unknown, 0 confidence
    }

    try {
        std::array<int64_t, 2> inputShape = {1, static_cast<int64_t>(features.size())};
        // ONNX Runtime C API requires non-const pointer for input data even though
        // it does not modify it. The const_cast is safe here.
        auto inputTensor = Ort::Value::CreateTensor<float>(
            impl_->memoryInfo,
            const_cast<float*>(features.data()),
            features.size(),
            inputShape.data(),
            inputShape.size());

        auto outputTensors = impl_->session->Run(
            Ort::RunOptions{nullptr},
            impl_->inputNames.data(),
            &inputTensor,
            1,
            impl_->outputNames.data(),
            impl_->outputNames.size());

        const auto* output = outputTensors.front().GetTensorData<float>();
        auto outputInfo = outputTensors.front().GetTensorTypeAndShapeInfo();
        auto outputSize = outputInfo.GetElementCount();

        std::span<const float> outputs(output, outputSize);

        // Copy probabilities (model output already has softmax applied)
        auto copyCount = std::min(outputSize,
            static_cast<std::size_t>(nids::core::kAttackTypeCount));
        for (std::size_t i = 0; i < copyCount; ++i) {
            result.probabilities[i] = outputs[i];
        }

        auto maxIt = std::ranges::max_element(outputs);
        auto maxIndex = static_cast<int>(std::distance(outputs.begin(), maxIt));

        result.classification = nids::core::attackTypeFromIndex(maxIndex);
        result.confidence = *maxIt;

        return result;
    } catch (const Ort::Exception& e) {
        spdlog::error("ONNX prediction failed: {}", e.what());
        return result;  // Unknown, 0 confidence
    }
}

} // namespace nids::infra
