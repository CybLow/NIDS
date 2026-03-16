#include "server/GrpcStreamSink.h"

#include "core/model/AttackType.h"
#include "core/model/ProtocolConstants.h"

namespace nids::server {

GrpcStreamSink::GrpcStreamSink(std::shared_ptr<EventQueue> queue,
                               ::nids::DetectionFilter filter)
    : queue_(std::move(queue)), filter_(filter) {}

void GrpcStreamSink::onFlowResult(
    std::size_t flowIndex,
    const nids::core::DetectionResult& result,
    const nids::core::FlowInfo& flow) {

    // Apply client-requested filter
    const bool isAttack = result.isFlagged();
    if (filter_ == ::nids::FILTER_FLAGGED && !isAttack) {
        return;
    }
    if (filter_ == ::nids::FILTER_CLEAN && isAttack) {
        return;
    }

    ::nids::DetectionEvent event;
    populateDetectionEvent(event, flowIndex, result, flow);
    std::ignore = queue_->tryPush(std::move(event));
}

void GrpcStreamSink::populateDetectionEvent(
    ::nids::DetectionEvent& event,
    std::size_t flowIndex,
    const nids::core::DetectionResult& result,
    const nids::core::FlowInfo& flow) {

    event.set_flow_index(flowIndex);

    // Flow metadata
    auto* meta = event.mutable_flow();
    meta->set_src_ip(flow.srcIp);
    meta->set_dst_ip(flow.dstIp);
    meta->set_src_port(flow.srcPort);
    meta->set_dst_port(flow.dstPort);
    // Convert protocol number to human-readable name
    meta->set_protocol(std::string(nids::core::protocolToName(flow.protocol)));
    meta->set_total_fwd_packets(flow.totalFwdPackets);
    meta->set_total_bwd_packets(flow.totalBwdPackets);
    meta->set_flow_duration_us(static_cast<std::uint64_t>(flow.flowDurationUs));

    // ML classification
    event.set_ml_classification(
        std::string(nids::core::attackTypeToString(result.mlResult.classification)));
    event.set_ml_confidence(result.mlResult.confidence);

    // ML probabilities (16 classes)
    for (const auto prob : result.mlResult.probabilities) {
        event.add_ml_probabilities(prob);
    }

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

    // Combined result
    event.set_verdict(result.finalVerdict == nids::core::AttackType::Benign
                          ? ::nids::VERDICT_BENIGN
                          : ::nids::VERDICT_ATTACK);
    event.set_combined_score(result.combinedScore);
    event.set_source(
        static_cast<::nids::DetectionSourceType>(result.detectionSource));
}

} // namespace nids::server
