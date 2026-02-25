#pragma once

/// Factory for creating IPacketAnalyzer implementations.
///
/// Follows the Factory Method pattern (AGENTS.md 5.3) to decouple
/// the creation of analyzer backends from consuming code.

#include "core/services/IPacketAnalyzer.h"

#include <memory>

namespace nids::infra {

enum class AnalyzerBackend {
    Onnx
};

/// Create an analyzer for the given backend.
/// Currently only ONNX is supported; additional backends (e.g., TensorRT,
/// OpenVINO) can be added without modifying calling code.
[[nodiscard]] std::unique_ptr<nids::core::IPacketAnalyzer>
createAnalyzer(AnalyzerBackend backend = AnalyzerBackend::Onnx);

} // namespace nids::infra
