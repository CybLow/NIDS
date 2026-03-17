#include "infra/output/CefFormatter.h"

#include "core/model/AttackType.h"
#include "core/model/DetectionSource.h"
#include "core/model/ProtocolConstants.h"

#include <fmt/format.h>
#include <sstream>
#include <utility>

namespace nids::infra {

std::string CefFormatter::format(
    std::size_t flowIndex,
    const core::DetectionResult& result,
    const core::FlowInfo& flow) const {

    const auto verdictStr =
        std::string{core::attackTypeToString(result.finalVerdict)};
    const int severity = cefSeverity(result.combinedScore);

    // Build signature ID: NIDS-<sourceIndex>-<attackTypeIndex>
    const auto sigId = fmt::format(
        "NIDS-{}-{}",
        std::to_underlying(result.detectionSource),
        std::to_underlying(result.finalVerdict));

    // Build TI feed list
    std::string tiFeeds;
    for (const auto& m : result.threatIntelMatches) {
        if (!tiFeeds.empty()) tiFeeds += ',';
        tiFeeds += m.feedName;
    }

    // Build rule list
    std::string rules;
    for (const auto& r : result.ruleMatches) {
        if (!rules.empty()) rules += ',';
        rules += r.ruleName;
    }

    // CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
    std::ostringstream oss;
    oss << "CEF:0|NIDS|NIDS|0.2.0|"
        << escapeHeader(sigId) << '|'
        << escapeHeader(verdictStr) << '|'
        << severity << '|';

    // Extension key=value pairs (space-separated)
    oss << "src=" << escapeExtension(flow.srcIp)
        << " dst=" << escapeExtension(flow.dstIp)
        << " spt=" << flow.srcPort
        << " dpt=" << flow.dstPort
        << " proto=" << static_cast<int>(flow.protocol)
        << " cn1=" << static_cast<int>(result.combinedScore * 100.0f)
        << " cn1Label=combinedScore"
        << " cs1=" << fmt::format("{:.4f}", result.mlResult.confidence)
        << " cs1Label=mlConfidence"
        << " cs2=" << escapeExtension(
               core::detectionSourceToString(result.detectionSource))
        << " cs2Label=detectionSource";

    if (!tiFeeds.empty()) {
        oss << " cs3=" << escapeExtension(tiFeeds)
            << " cs3Label=threatIntelFeeds";
    }
    if (!rules.empty()) {
        oss << " cs4=" << escapeExtension(rules)
            << " cs4Label=heuristicRules";
    }

    oss << " cnt=" << flowIndex
        << " msg=" << escapeExtension(fmt::format(
               "{} detected with {:.1f}% ML confidence",
               verdictStr, result.mlResult.confidence * 100.0f));

    return oss.str();
}

int CefFormatter::cefSeverity(float combinedScore) noexcept {
    // Map [0.0, 1.0] → [0, 10]
    if (combinedScore <= 0.0f) return 0;
    if (combinedScore >= 1.0f) return 10;
    return static_cast<int>(combinedScore * 10.0f);
}

std::string CefFormatter::escapeHeader(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (char c : value) {
        if (c == '|' || c == '\\') out += '\\';
        out += c;
    }
    return out;
}

std::string CefFormatter::escapeExtension(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (char c : value) {
        if (c == '=' || c == '\\' || c == '\n') out += '\\';
        out += c;
    }
    return out;
}

} // namespace nids::infra
