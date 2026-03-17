#include "infra/analysis/AnalyzerFactory.h"
#include "infra/analysis/OnnxAnalyzer.h"

#include <spdlog/spdlog.h>

#include <stdexcept>

namespace nids::infra {

std::unique_ptr<core::IPacketAnalyzer>
createAnalyzer(AnalyzerBackend backend) {
    if (backend == AnalyzerBackend::Onnx) {
        spdlog::debug("Creating ONNX Runtime analyzer");
        return std::make_unique<OnnxAnalyzer>();
    }
    spdlog::error("Unknown analyzer backend requested");
    throw std::invalid_argument("Unsupported analyzer backend");
}

} // namespace nids::infra
