#include "app/SinkChain.h"

#include <spdlog/spdlog.h>

#include <exception>

namespace nids::app {

void SinkChain::addSink(std::unique_ptr<core::IOutputSink> sink) {
    if (sink) {
        ownedSinks_.push_back(std::move(sink));
    }
}

void SinkChain::addSink(core::IOutputSink* sink) {
    if (sink) {
        nonOwnedSinks_.push_back(sink);
    }
}

bool SinkChain::start() {
    bool allOk = true;
    for (auto& sink : ownedSinks_) {
        try {
            if (!sink->start()) {
                spdlog::warn("SinkChain: sink '{}' failed to start",
                             sink->name());
                allOk = false;
            }
        } catch (const std::exception& e) {
            spdlog::error("SinkChain: sink '{}' threw on start(): {}",
                          sink->name(), e.what());
            allOk = false;
        }
    }
    for (auto* sink : nonOwnedSinks_) {
        try {
            if (!sink->start()) {
                spdlog::warn("SinkChain: sink '{}' failed to start",
                             sink->name());
                allOk = false;
            }
        } catch (const std::exception& e) {
            spdlog::error("SinkChain: sink '{}' threw on start(): {}",
                          sink->name(), e.what());
            allOk = false;
        }
    }
    spdlog::info("SinkChain started with {} sinks", sinkCount());
    return allOk;
}

void SinkChain::onFlowResult(std::size_t flowIndex,
                              const core::DetectionResult& result,
                              const core::FlowInfo& flow) {
    // Error isolation: each sink gets the result even if a prior sink throws.
    for (auto& sink : ownedSinks_) {
        try {
            sink->onFlowResult(flowIndex, result, flow);
        } catch (const std::exception& e) {
            spdlog::error("SinkChain: sink '{}' threw on onFlowResult(): {}",
                          sink->name(), e.what());
        }
    }
    for (auto* sink : nonOwnedSinks_) {
        try {
            sink->onFlowResult(flowIndex, result, flow);
        } catch (const std::exception& e) {
            spdlog::error("SinkChain: sink '{}' threw on onFlowResult(): {}",
                          sink->name(), e.what());
        }
    }
}

void SinkChain::stop() {
    for (auto& sink : ownedSinks_) {
        try {
            sink->stop();
        } catch (const std::exception& e) {
            spdlog::error("SinkChain: sink '{}' threw on stop(): {}",
                          sink->name(), e.what());
        }
    }
    for (auto* sink : nonOwnedSinks_) {
        try {
            sink->stop();
        } catch (const std::exception& e) {
            spdlog::error("SinkChain: sink '{}' threw on stop(): {}",
                          sink->name(), e.what());
        }
    }
    spdlog::info("SinkChain stopped");
}

std::size_t SinkChain::sinkCount() const noexcept {
    return ownedSinks_.size() + nonOwnedSinks_.size();
}

} // namespace nids::app
