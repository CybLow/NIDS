#pragma once

/// Fan-out output sink that distributes detection results to multiple sinks.
///
/// Lives in the app/ layer because it orchestrates multiple IOutputSink
/// implementations without depending on any platform-specific API.
///
/// Supports both owned sinks (unique_ptr — SinkChain takes ownership) and
/// non-owned sinks (raw pointer — caller manages lifetime).
/// Error isolation: if one sink throws, the others still receive the result.

#include "core/services/IOutputSink.h"

#include <cstddef>
#include <memory>
#include <string_view>
#include <vector>

namespace nids::app {

class SinkChain final : public core::IOutputSink {
public:
    SinkChain() = default;

    [[nodiscard]] std::string_view name() const noexcept override {
        return "SinkChain";
    }

    /// Add an owned sink (SinkChain takes ownership).
    void addSink(std::unique_ptr<core::IOutputSink> sink);

    /// Add a non-owned sink (caller must keep alive until stop()).
    void addSink(core::IOutputSink* sink);

    [[nodiscard]] bool start() override;
    void onFlowResult(std::size_t flowIndex,
                      const core::DetectionResult& result,
                      const core::FlowInfo& flow) override;
    void stop() override;

    /// Number of registered sinks (owned + non-owned).
    [[nodiscard]] std::size_t sinkCount() const noexcept;

private:
    std::vector<std::unique_ptr<core::IOutputSink>> ownedSinks_;
    std::vector<core::IOutputSink*> nonOwnedSinks_;
};

} // namespace nids::app
