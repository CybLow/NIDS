#pragma once

/// Console output sink that logs detection results via spdlog.
///
/// Supports three filter modes:
///   - All:     log every flow (benign + flagged)
///   - Flagged: log only flagged flows (ML attack, TI match, or rule match)
///   - Clean:   log only benign/clean flows

#include "core/services/IOutputSink.h"

#include <atomic>
#include <cstddef>
#include <string_view>

namespace nids::infra {

/// Filter mode for console output.
enum class ConsoleFilter : std::uint8_t {
    All,      ///< Log every flow
    Flagged,  ///< Log only flagged flows
    Clean     ///< Log only clean (benign) flows
};

class ConsoleAlertSink final : public nids::core::IOutputSink {
public:
    explicit ConsoleAlertSink(ConsoleFilter filter = ConsoleFilter::Flagged)
        : filter_(filter) {}

    [[nodiscard]] std::string_view name() const noexcept override {
        return "ConsoleAlertSink";
    }

    [[nodiscard]] bool start() override;
    void onFlowResult(std::size_t flowIndex,
                      const nids::core::DetectionResult& result,
                      const nids::core::FlowInfo& flow) override;
    void stop() override;

private:
    ConsoleFilter filter_;
    std::atomic<std::size_t> totalFlows_{0};
    std::atomic<std::size_t> flaggedFlows_{0};
    std::atomic<std::size_t> cleanFlows_{0};
};

} // namespace nids::infra
