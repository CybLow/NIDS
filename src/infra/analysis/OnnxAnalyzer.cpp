#include "infra/analysis/OnnxAnalyzer.h"

#include <iostream>

// Conditional compilation: only compile ONNX logic when the SDK is available
#ifdef NIDS_HAS_ONNX
#include <onnxruntime_cxx_api.h>
#endif

namespace nids::infra {

struct OnnxAnalyzer::Impl {
#ifdef NIDS_HAS_ONNX
    Ort::Env env{ORT_LOGGING_LEVEL_WARNING, "NIDS"};
    std::unique_ptr<Ort::Session> session;
    Ort::MemoryInfo memoryInfo = Ort::MemoryInfo::CreateCpu(
        OrtArenaAllocator, OrtMemTypeDefault);
    std::vector<const char*> inputNames;
    std::vector<const char*> outputNames;
    bool loaded = false;
#endif
};

OnnxAnalyzer::OnnxAnalyzer()
    : impl_(std::make_unique<Impl>()) {}

OnnxAnalyzer::~OnnxAnalyzer() = default;

bool OnnxAnalyzer::loadModel(const std::string& modelPath) {
#ifdef NIDS_HAS_ONNX
    try {
        Ort::SessionOptions sessionOptions;
        sessionOptions.SetIntraOpNumThreads(1);
        sessionOptions.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);

        impl_->session = std::make_unique<Ort::Session>(
            impl_->env, modelPath.c_str(), sessionOptions);

        Ort::AllocatorWithDefaultOptions allocator;
        auto inputName = impl_->session->GetInputNameAllocated(0, allocator);
        auto outputName = impl_->session->GetOutputNameAllocated(0, allocator);

        impl_->inputNames = {"input"};
        impl_->outputNames = {"output"};
        impl_->loaded = true;

        std::cout << "ONNX model loaded: " << modelPath << std::endl;
        return true;
    } catch (const Ort::Exception& e) {
        std::cerr << "Failed to load ONNX model: " << e.what() << std::endl;
        impl_->loaded = false;
        return false;
    }
#else
    (void)modelPath;
    std::cerr << "ONNX Runtime not available. Build with NIDS_HAS_ONNX defined "
              << "and link onnxruntime." << std::endl;
    return false;
#endif
}

nids::core::AttackType OnnxAnalyzer::predict(const std::vector<float>& features) {
#ifdef NIDS_HAS_ONNX
    if (!impl_->loaded || !impl_->session) {
        return nids::core::AttackType::Unknown;
    }

    try {
        std::array<int64_t, 2> inputShape = {1, static_cast<int64_t>(features.size())};
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

        const float* output = outputTensors.front().GetTensorData<float>();
        auto outputInfo = outputTensors.front().GetTensorTypeAndShapeInfo();
        auto outputSize = outputInfo.GetElementCount();

        int maxIndex = 0;
        float maxVal = output[0];
        for (size_t i = 1; i < outputSize; ++i) {
            if (output[i] > maxVal) {
                maxVal = output[i];
                maxIndex = static_cast<int>(i);
            }
        }

        return nids::core::attackTypeFromIndex(maxIndex);
    } catch (const Ort::Exception&) {
        return nids::core::AttackType::Unknown;
    }
#else
    (void)features;
    return nids::core::AttackType::Unknown;
#endif
}

} // namespace nids::infra
