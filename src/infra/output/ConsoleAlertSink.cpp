#include "infra/output/ConsoleAlertSink.h"

#include <spdlog/spdlog.h>

namespace nids::infra {

bool ConsoleAlertSink::start() {
  totalFlows_.store(0);
  flaggedFlows_.store(0);
  cleanFlows_.store(0);
  auto filterName = [this]() -> std::string_view {
    using enum nids::infra::ConsoleFilter;
    switch (filter_) {
    case All:
      return "all";
    case Flagged:
      return "flagged";
    case Clean:
      return "clean";
    }
    return "unknown";
  }();
  spdlog::info("ConsoleAlertSink started (filter={})", filterName);
  return true;
}

void ConsoleAlertSink::onFlowResult(std::size_t flowIndex,
                                    const core::DetectionResult &result,
                                    const core::FlowInfo &flow) {

  totalFlows_.fetch_add(1);

  const bool flagged = result.isFlagged();
  if (flagged) {
    flaggedFlows_.fetch_add(1);
  } else {
    cleanFlows_.fetch_add(1);
  }

  // Apply filter.
  if (filter_ == ConsoleFilter::Flagged && !flagged) [[likely]] {
    return;
  }
  if (filter_ == ConsoleFilter::Clean && flagged) {
    return;
  }

  if (flagged) {
    spdlog::warn("ALERT flow #{}: {}:{} -> {}:{} verdict={} "
                 "confidence={:.3f} source={}",
                 flowIndex, flow.srcIp, flow.srcPort, flow.dstIp, flow.dstPort,
                 attackTypeToString(result.finalVerdict),
                 result.mlResult.confidence,
                 detectionSourceToString(result.detectionSource));
  } else {
    spdlog::debug("CLEAN flow #{}: {}:{} -> {}:{} [{}] confidence={:.3f}",
                  flowIndex, flow.srcIp, flow.srcPort, flow.dstIp, flow.dstPort,
                  attackTypeToString(result.finalVerdict),
                  result.mlResult.confidence);
  }
}

void ConsoleAlertSink::stop() {
  spdlog::info("ConsoleAlertSink summary: total={} flagged={} clean={}",
               totalFlows_.load(), flaggedFlows_.load(), cleanFlows_.load());
}

} // namespace nids::infra
