#include "infra/analysis/OnnxAnalyzer.h"
#include "core/services/Configuration.h"

#include <onnxruntime_cxx_api.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <expected>
#include <span>

namespace nids::infra {

namespace {

/// Map raw model output probabilities to a PredictionResult.
/// Shared by single-flow and batched inference paths (DRY).
core::PredictionResult interpretOutput(std::span<const float> outputs) {
    core::PredictionResult result;
    auto copyCount = std::min(
        outputs.size(), static_cast<std::size_t>(core::kAttackTypeCount));
    for (std::size_t i = 0; i < copyCount; ++i) {
        result.probabilities[i] = outputs[i];
    }
    auto maxIt = std::ranges::max_element(outputs);
    result.classification = core::attackTypeFromIndex(
        static_cast<int>(std::distance(outputs.begin(), maxIt)));
    result.confidence = *maxIt;
    return result;
}

} // anonymous namespace

struct OnnxAnalyzer::Impl {
  Ort::Env env{ORT_LOGGING_LEVEL_WARNING, "NIDS"};
  std::unique_ptr<Ort::Session> session{};
  Ort::MemoryInfo memoryInfo =
      Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
  std::vector<std::string> inputNamesOwned{};
  std::vector<std::string> outputNamesOwned{};
  std::vector<const char *> inputNames{};
  std::vector<const char *> outputNames{};
  bool loaded = false;
};

OnnxAnalyzer::OnnxAnalyzer() : impl_(std::make_unique<Impl>()) {}

OnnxAnalyzer::~OnnxAnalyzer() = default;

std::expected<void, std::string> OnnxAnalyzer::loadModel(
    const std::string &modelPath) {
  try {
    Ort::SessionOptions sessionOptions;
    const auto threads =
        core::Configuration::instance().onnxIntraOpThreads();
    sessionOptions.SetIntraOpNumThreads(threads);
    sessionOptions.SetGraphOptimizationLevel(
        GraphOptimizationLevel::ORT_ENABLE_ALL);

#ifdef _WIN32
    std::wstring wideModelPath(modelPath.begin(), modelPath.end());
    impl_->session = std::make_unique<Ort::Session>(
        impl_->env, wideModelPath.c_str(), sessionOptions);
#else
    impl_->session = std::make_unique<Ort::Session>(
        impl_->env, modelPath.c_str(), sessionOptions);
#endif

    Ort::AllocatorWithDefaultOptions allocator;

    // Dynamically query input names from the model
    std::size_t numInputs = impl_->session->GetInputCount();
    impl_->inputNamesOwned.clear();
    impl_->inputNames.clear();
    for (std::size_t i = 0; i < numInputs; ++i) {
      auto name = impl_->session->GetInputNameAllocated(i, allocator);
      impl_->inputNamesOwned.emplace_back(name.get());
    }
    for (const auto &name : impl_->inputNamesOwned) {
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
    for (const auto &name : impl_->outputNamesOwned) {
      impl_->outputNames.push_back(name.c_str());
    }

    impl_->loaded = true;

    spdlog::info("ONNX model loaded: {}", modelPath);
    return {};
  } catch (const Ort::Exception &e) {
    std::string msg = fmt::format("Failed to load ONNX model: {}", e.what());
    spdlog::error(msg);
    impl_->loaded = false;
    return std::unexpected<std::string>(std::move(msg));
  }
}

core::AttackType
OnnxAnalyzer::predict(std::span<const float> features) {
  auto result = predictWithConfidence(features);
  return result.classification;
}

core::PredictionResult
OnnxAnalyzer::predictWithConfidence(std::span<const float> features) {
  core::PredictionResult result;

  if (!impl_->loaded || !impl_->session) [[unlikely]] {
    return result; // Unknown, 0 confidence
  }

  try {
    std::array<int64_t, 2> inputShape = {1,
                                         static_cast<int64_t>(features.size())};
    // ONNX Runtime C API requires non-const pointer for input data even though
    // it does not modify it. The const_cast is safe here.
    auto inputTensor = Ort::Value::CreateTensor<float>(
        impl_->memoryInfo, const_cast<float *>(features.data()),
        features.size(), inputShape.data(), inputShape.size());

    auto outputTensors = impl_->session->Run(
        Ort::RunOptions{nullptr}, impl_->inputNames.data(), &inputTensor, 1,
        impl_->outputNames.data(), impl_->outputNames.size());

    const auto *output = outputTensors.front().GetTensorData<float>();
    auto outputInfo = outputTensors.front().GetTensorTypeAndShapeInfo();
    auto outputSize = outputInfo.GetElementCount();

    std::span<const float> outputs(output, outputSize);
    return interpretOutput(outputs);
  } catch (const Ort::Exception &e) {
    spdlog::error("ONNX prediction failed: {}", e.what());
    return result; // Unknown, 0 confidence
  }
}

std::vector<core::PredictionResult>
OnnxAnalyzer::predictBatch(std::span<const float> batch,
                           std::size_t featureCount) {
  std::vector<core::PredictionResult> results;

  if (!impl_->loaded || !impl_->session || featureCount == 0 ||
      batch.empty()) [[unlikely]] {
    return results;
  }

  auto flowCount = static_cast<int64_t>(batch.size() / featureCount);
  if (flowCount == 0) {
    return results;
  }

  // Fall back to single-flow inference for batch size 1 (no overhead benefit).
  if (flowCount == 1) {
    results.push_back(predictWithConfidence(batch));
    return results;
  }

  try {
    std::array<int64_t, 2> inputShape = {flowCount,
                                         static_cast<int64_t>(featureCount)};

    auto inputTensor = Ort::Value::CreateTensor<float>(
        impl_->memoryInfo, const_cast<float*>(batch.data()), batch.size(),
        inputShape.data(), inputShape.size());

    auto outputTensors = impl_->session->Run(
        Ort::RunOptions{nullptr}, impl_->inputNames.data(), &inputTensor, 1,
        impl_->outputNames.data(), impl_->outputNames.size());

    const auto* output = outputTensors.front().GetTensorData<float>();
    auto outputInfo = outputTensors.front().GetTensorTypeAndShapeInfo();
    auto shape = outputInfo.GetShape();

    // Output shape is [N, numClasses].
    auto numClasses = (shape.size() >= 2)
                          ? static_cast<std::size_t>(shape[1])
                          : outputInfo.GetElementCount() /
                                static_cast<std::size_t>(flowCount);

    results.reserve(static_cast<std::size_t>(flowCount));

    for (std::size_t i = 0; i < static_cast<std::size_t>(flowCount); ++i) {
      std::span<const float> flowOut(output + i * numClasses, numClasses);
      results.push_back(interpretOutput(flowOut));
    }

    return results;
  } catch (const Ort::Exception& e) {
    spdlog::error("ONNX batch prediction failed: {}", e.what());
    // Fall back to per-flow inference.
    results.clear();
    for (std::size_t i = 0; i < static_cast<std::size_t>(flowCount); ++i) {
      auto flowData = batch.subspan(i * featureCount, featureCount);
      results.push_back(predictWithConfidence(flowData));
    }
    return results;
  }
}

} // namespace nids::infra
