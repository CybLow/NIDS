#include "server/GrpcStreamSink.h"

#include "core/model/AttackType.h"
#include "core/model/DetectionSource.h"
#include "core/model/ProtocolConstants.h"

namespace nids::server {

namespace {

/// Convert a core DetectionSource to the protobuf DetectionSourceType.
/// Uses an explicit switch instead of static_cast to prevent silent
/// mismatches if either enum is reordered.
[[nodiscard]] DetectionSourceType toProtoSource(
    core::DetectionSource source) {
    using enum core::DetectionSource;
    switch (source) {
    case MlOnly:           return SOURCE_ML_ONLY;
    case ThreatIntel:      return SOURCE_THREAT_INTEL;
    case HeuristicRule:    return SOURCE_HEURISTIC_RULE;
    case MlPlusThreatIntel: return SOURCE_ML_PLUS_TI;
    case MlPlusHeuristic:  return SOURCE_ML_PLUS_RULE;
    case ContentScan:      return SOURCE_ENSEMBLE;  // Map to ensemble for now
    case SignatureMatch:   return SOURCE_ENSEMBLE;
    case Ensemble:         return SOURCE_ENSEMBLE;
    case None:             return SOURCE_UNKNOWN;
    }
    return SOURCE_UNKNOWN;
}

} // anonymous namespace

GrpcStreamSink::GrpcStreamSink(std::shared_ptr<EventQueue> queue,
                               DetectionFilter filter)
    : queue_(std::move(queue)), filter_(filter) {}

void GrpcStreamSink::onFlowResult(
    std::size_t flowIndex,
    const core::DetectionResult& result,
    const core::FlowInfo& flow) {

    // Apply client-requested filter
    const bool isAttack = result.isFlagged();
    if (filter_ == FILTER_FLAGGED && !isAttack) {
        return;
    }
    if (filter_ == FILTER_CLEAN && isAttack) {
        return;
    }

    DetectionEvent event;
    populateDetectionEvent(event, flowIndex, result, flow);
    std::ignore = queue_->tryPush(std::move(event));
}

void GrpcStreamSink::populateDetectionEvent(
    DetectionEvent& event,
    std::size_t flowIndex,
    const core::DetectionResult& result,
    const core::FlowInfo& flow) {

    event.set_flow_index(flowIndex);
    populateFlowMetadata(event, flow);
    populateMlClassification(event, result);
    populateMatchesAndVerdict(event, result);
}

void GrpcStreamSink::populateFlowMetadata(
    DetectionEvent& event,
    const core::FlowInfo& flow) {

    auto* meta = event.mutable_flow();
    meta->set_src_ip(flow.srcIp);
    meta->set_dst_ip(flow.dstIp);
    meta->set_src_port(flow.srcPort);
    meta->set_dst_port(flow.dstPort);
    meta->set_protocol(std::string(core::protocolToName(flow.protocol)));
    meta->set_total_fwd_packets(flow.totalFwdPackets);
    meta->set_total_bwd_packets(flow.totalBwdPackets);
    meta->set_flow_duration_us(static_cast<std::uint64_t>(flow.flowDurationUs));
}

void GrpcStreamSink::populateMlClassification(
    DetectionEvent& event,
    const core::DetectionResult& result) {

    event.set_ml_classification(
        std::string(core::attackTypeToString(result.mlResult.classification)));
    event.set_ml_confidence(result.mlResult.confidence);

    for (const auto prob : result.mlResult.probabilities) {
        event.add_ml_probabilities(prob);
    }
}

void GrpcStreamSink::populateMatchesAndVerdict(
    DetectionEvent& event,
    const core::DetectionResult& result) {

    // Threat intelligence matches
    for (const auto& ti : result.threatIntelMatches) {
        auto* match = event.add_ti_matches();
        match->set_matched_ip(ti.ip);
        match->set_feed_name(ti.feedName);
        match->set_direction(ti.isSource ? "source" : "destination");
    }

    // Heuristic rule matches
    for (const auto& rule : result.ruleMatches) {
        auto* match = event.add_rule_matches();
        match->set_rule_name(rule.ruleName);
        match->set_description(rule.description);
        match->set_severity(rule.severity);
    }

    // Combined verdict
    event.set_verdict(result.finalVerdict == core::AttackType::Benign
                          ? VERDICT_BENIGN
                          : VERDICT_ATTACK);
    event.set_combined_score(result.combinedScore);
    event.set_source(toProtoSource(result.detectionSource));
}

} // namespace nids::server
