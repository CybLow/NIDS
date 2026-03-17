#include "infra/output/ConsoleAlertSink.h"

#include <spdlog/spdlog.h>

namespace nids::infra {

bool ConsoleAlertSink::start() {
    totalFlows_.store(0, std::memory_order_relaxed);
    flaggedFlows_.store(0, std::memory_order_relaxed);
    cleanFlows_.store(0, std::memory_order_relaxed);
    spdlog::info("ConsoleAlertSink started (filter={})",
                 filter_ == ConsoleFilter::All     ? "all"
                 : filter_ == ConsoleFilter::Flagged ? "flagged"
                                                     : "clean");
    return true;
}

void ConsoleAlertSink::onFlowResult(
    std::size_t flowIndex,
    const core::DetectionResult& result,
    const core::FlowInfo& flow) {

    totalFlows_.fetch_add(1, std::memory_order_relaxed);

    const bool flagged = result.isFlagged();
    if (flagged) {
        flaggedFlows_.fetch_add(1, std::memory_order_relaxed);
    } else {
        cleanFlows_.fetch_add(1, std::memory_order_relaxed);
    }

    // Apply filter.
    if (filter_ == ConsoleFilter::Flagged && !flagged) [[likely]] {
        return;
    }
    if (filter_ == ConsoleFilter::Clean && flagged) {
        return;
    }

    if (flagged) {
        spdlog::warn(
            "ALERT flow #{}: {}:{} -> {}:{} verdict={} "
            "confidence={:.3f} source={}",
            flowIndex, flow.srcIp, flow.srcPort,
            flow.dstIp, flow.dstPort,
            attackTypeToString(result.finalVerdict),
            result.mlResult.confidence,
            detectionSourceToString(result.detectionSource));
    } else {
        spdlog::debug(
            "CLEAN flow #{}: {}:{} -> {}:{} [{}] confidence={:.3f}",
            flowIndex, flow.srcIp, flow.srcPort,
            flow.dstIp, flow.dstPort,
            attackTypeToString(result.finalVerdict),
            result.mlResult.confidence);
    }
}

void ConsoleAlertSink::stop() {
    spdlog::info("ConsoleAlertSink summary: total={} flagged={} clean={}",
                 totalFlows_.load(std::memory_order_relaxed),
                 flaggedFlows_.load(std::memory_order_relaxed),
                 cleanFlows_.load(std::memory_order_relaxed));
}

} // namespace nids::infra
