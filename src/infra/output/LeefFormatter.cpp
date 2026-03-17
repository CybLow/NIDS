#include "infra/output/LeefFormatter.h"

#include "core/model/AttackType.h"
#include "core/model/DetectionSource.h"
#include "core/model/ProtocolConstants.h"

#include <fmt/format.h>
#include <sstream>
#include <utility>

namespace nids::infra {

std::string LeefFormatter::format(
    [[maybe_unused]] std::size_t flowIndex,
    const core::DetectionResult& result,
    const core::FlowInfo& flow) const {

    const auto verdictStr =
        std::string{core::attackTypeToString(result.finalVerdict)};
    const int severity = leefSeverity(result.combinedScore);

    const auto eventId = fmt::format(
        "NIDS-{}", std::to_underlying(result.finalVerdict));

    // LEEF:2.0|Vendor|Product|Version|EventID|<delimiter>key=value...
    // Tab is the default LEEF 2.0 delimiter.
    std::ostringstream oss;
    oss << "LEEF:2.0|NIDS|NIDS|0.2.0|" << eventId << "|\t";

    // Append the LEEF attributes, each tab-separated.
    oss << "src=" << flow.srcIp
        << "\tdst=" << flow.dstIp
        << "\tsrcPort=" << flow.srcPort
        << "\tdstPort=" << flow.dstPort
        << "\tproto=" << core::protocolToName(flow.protocol)
        << "\tsev=" << severity
        << "\tcat=" << verdictStr
        << "\tdevTimeFormat=MMM dd yyyy HH:mm:ss"
        << "\tidentSrc=" << flow.srcIp
        << "\tidentHostName=nids";

    oss << "\treason=" << fmt::format(
               "{} detected (ML confidence {:.1f}%, combined score {:.0f}%)",
               verdictStr,
               result.mlResult.confidence * 100.0f,
               result.combinedScore * 100.0f);

    return oss.str();
}

int LeefFormatter::leefSeverity(float combinedScore) noexcept {
    // Map [0.0, 1.0] → [1, 10] (LEEF minimum is 1)
    if (combinedScore <= 0.0f) return 1;
    if (combinedScore >= 1.0f) return 10;
    return 1 + static_cast<int>(combinedScore * 9.0f);
}

} // namespace nids::infra
