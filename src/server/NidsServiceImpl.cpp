#include "server/NidsServiceImpl.h"

#include "core/model/AttackType.h"
#include "core/model/DetectionSource.h"
#include "core/model/FlowQuery.h"
#include "core/model/FlowKey.h"

#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <format>
#include <map>
#include <string>
#include <thread>

namespace nids::server {

namespace {
/// Capacity of the per-client event queue for gRPC detection streaming.
constexpr std::size_t kStreamEventQueueCapacity = 1024;
} // namespace

NidsServiceImpl::NidsServiceImpl(
    core::IPacketCapture& capture,
    core::IFlowExtractor& extractor,
    core::IPacketAnalyzer& analyzer,
    core::IFeatureNormalizer& normalizer,
    app::HybridDetectionService& hybridService)
    : capture_(capture),
      extractor_(extractor),
      analyzer_(analyzer),
      normalizer_(normalizer),
      hybridService_(hybridService) {}

grpc::Status NidsServiceImpl::ListInterfaces(
    grpc::ServerContext* /*context*/,
    const ListInterfacesRequest* /*request*/,
    ListInterfacesResponse* response) {

    auto interfaces = capture_.listInterfaces();
    for (auto& iface : interfaces) {
        response->add_interfaces(std::move(iface));
    }
    spdlog::debug("ListInterfaces: returned {} interfaces",
                  response->interfaces_size());
    return grpc::Status::OK;
}

grpc::Status NidsServiceImpl::StartCapture(
    grpc::ServerContext* /*context*/,
    const StartCaptureRequest* request,
    StartCaptureResponse* response) {

    std::scoped_lock lock(sessionMutex_);

    if (capturing_.load()) {
        response->set_success(false);
        response->set_message("Capture already in progress");
        return grpc::Status::OK;
    }

    const auto& iface = request->interface();
    if (iface.empty()) {
        response->set_success(false);
        response->set_message("Interface name is required");
        return grpc::Status::OK;
    }

    // Build BPF filter from request
    std::string bpfFilter;
    if (request->has_filter()) {
        bpfFilter = request->filter().custom_bpf();
    }

    // Initialize capture
    if (auto result = capture_.initialize(iface, bpfFilter); !result) {
        response->set_success(false);
        response->set_message("Failed to initialize capture on " + iface +
                              ": " + result.error());
        return grpc::Status::OK;
    }

    createSessionPipeline(iface);
    capture_.startCapture(request->dump_file());
    capturing_.store(true);

    response->set_success(true);
    response->set_message("Capture started on " + iface);
    response->set_session_id(sessionId_);

    spdlog::info("gRPC: Capture started on '{}', session '{}'",
                 iface, sessionId_);
    return grpc::Status::OK;
}

grpc::Status NidsServiceImpl::StopCapture(
    grpc::ServerContext* /*context*/,
    const StopCaptureRequest* /*request*/,
    StopCaptureResponse* response) {

    std::scoped_lock lock(sessionMutex_);

    if (!capturing_.load()) {
        response->set_success(false);
        return grpc::Status::OK;
    }

    // Read counts before stopping
    const auto flowsDetected = pipeline_ ? pipeline_->flowsDetected() : 0;
    const auto droppedFlows = pipeline_ ? pipeline_->droppedFlows() : 0;

    // Stop capture and pipeline
    capture_.stopCapture();
    if (pipeline_) {
        pipeline_->stop();
    }
    capturing_.store(false);

    response->set_success(true);
    response->set_total_packets(session_ ? session_->packetCount() : 0);
    response->set_total_flows(flowsDetected);
    response->set_flagged_flows(session_ ? session_->flaggedResultCount() : 0);
    response->set_dropped_flows(droppedFlows);

    spdlog::info("gRPC: Capture stopped — {} flows detected, {} dropped",
                 flowsDetected, droppedFlows);
    return grpc::Status::OK;
}

grpc::Status NidsServiceImpl::StreamDetections(
    grpc::ServerContext* context,
    const StreamDetectionsRequest* request,
    grpc::ServerWriter<DetectionEvent>* writer) {

    spdlog::info("gRPC: Client connected for detection streaming (filter={})",
                 static_cast<int>(request->filter()));

    // Create a per-client event queue and sink
    auto eventQueue =
        std::make_shared<GrpcStreamSink::EventQueue>(kStreamEventQueueCapacity);
    auto sink = std::make_unique<GrpcStreamSink>(eventQueue, request->filter());

    // Register sink with service (will be added to pipeline)
    registerSink(sink.get());

    // If pipeline is already running, add the sink
    {
        std::scoped_lock lock(sessionMutex_);
        if (pipeline_ && pipeline_->isRunning()) {
            pipeline_->addOutputSink(sink.get());
        }
    }

    // Stream events to the client until cancelled
    while (!context->IsCancelled()) {
        auto maybeEvent = eventQueue->pop();
        if (maybeEvent) {
            if (!writer->Write(*maybeEvent)) {
                break; // Client disconnected
            }
        } else {
            // Queue closed (pipeline stopped) — drain remaining
            break;
        }
    }

    // Drain any remaining events
    while (auto maybeEvent = eventQueue->pop()) {
        if (!writer->Write(*maybeEvent)) {
            break;
        }
    }

    unregisterSink(sink.get());
    spdlog::info("gRPC: Detection stream client disconnected");
    return grpc::Status::OK;
}

grpc::Status NidsServiceImpl::StreamPackets(
    grpc::ServerContext* context,
    const StreamPacketsRequest* /*request*/,
    grpc::ServerWriter<PacketEvent>* writer) {

    if (!capturing_.load()) {
        return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                            "No active capture session");
    }

    // Poll the session's packet table and stream new entries.
    std::uint64_t lastIndex = 0;
    if (session_) {
        lastIndex = session_->packetCount();
    }

    while (!context->IsCancelled() && capturing_.load()) {
        std::scoped_lock lock{sessionMutex_};
        if (!session_) break;

        auto currentCount = session_->packetCount();
        if (currentCount > lastIndex) {
            // Stream the count delta as a simple event.
            PacketEvent event;
            event.set_index(currentCount);
            if (!writer->Write(event)) break;
            lastIndex = currentCount;
        }

        // Avoid busy-spinning.
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    return grpc::Status::OK;
}

grpc::Status NidsServiceImpl::AnalyzeCapture(
    [[maybe_unused]] grpc::ServerContext* context,
    const AnalyzeCaptureRequest* request,
    AnalyzeCaptureResponse* response) {

    const auto& pcapPath = request->pcap_path();
    if (pcapPath.empty()) {
        response->set_success(false);
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                            "pcap_path is required");
    }

    if (!std::filesystem::exists(pcapPath)) {
        response->set_success(false);
        return grpc::Status(grpc::StatusCode::NOT_FOUND,
                            "PCAP file not found: " + pcapPath);
    }

    // Extract flows from the PCAP file.
    auto features = extractor_.extractFeatures(pcapPath);
    const auto& metadata = extractor_.flowMetadata();

    std::map<std::string, std::uint32_t> attackCounts;
    std::uint32_t flaggedCount = 0;

    for (std::size_t i = 0; i < features.size(); ++i) {
        auto prediction = analyzer_.predictWithConfidence(features[i]);
        auto detection = hybridService_.evaluate(
            prediction, metadata[i].srcIp, metadata[i].dstIp, metadata[i]);

        auto label = std::string{
            core::attackTypeToString(detection.finalVerdict)};
        attackCounts[label]++;

        if (detection.isFlagged()) {
            ++flaggedCount;
        }
    }

    response->set_success(true);
    response->set_total_analyzed(static_cast<std::uint32_t>(features.size()));
    response->set_flagged_count(flaggedCount);
    for (const auto& [label, count] : attackCounts) {
        (*response->mutable_attack_counts())[label] = count;
    }

    return grpc::Status::OK;
}

grpc::Status NidsServiceImpl::GetStatus(
    grpc::ServerContext* /*context*/,
    const GetStatusRequest* /*request*/,
    GetStatusResponse* response) {

    std::scoped_lock lock(sessionMutex_);

    response->set_capturing(capturing_.load());
    response->set_current_interface(currentInterface_);
    response->set_session_id(sessionId_);

    if (session_) {
        response->set_packets_captured(session_->packetCount());
    }
    if (pipeline_) {
        response->set_flows_detected(pipeline_->flowsDetected());
        response->set_flows_dropped(pipeline_->droppedFlows());
    }

    if (session_) {
        response->set_flows_flagged(session_->flaggedResultCount());
    }

    return grpc::Status::OK;
}

// ── Phase 13: Threat hunting RPCs ───────────────────────────────────

grpc::Status NidsServiceImpl::SearchFlows(
    [[maybe_unused]] grpc::ServerContext* context,
    const SearchFlowsRequest* request,
    SearchFlowsResponse* response) {
    if (!flowIndex_) {
        return grpc::Status(grpc::StatusCode::UNAVAILABLE,
                            "Flow index not configured");
    }

    core::FlowQuery query;
    if (!request->src_ip().empty()) query.srcIp = request->src_ip();
    if (!request->dst_ip().empty()) query.dstIp = request->dst_ip();
    if (!request->any_ip().empty()) query.anyIp = request->any_ip();
    if (request->dst_port() > 0)
        query.dstPort = static_cast<std::uint16_t>(request->dst_port());
    if (request->protocol() > 0)
        query.protocol = static_cast<std::uint8_t>(request->protocol());
    if (request->flagged_only()) query.flaggedOnly = true;
    if (request->min_score() > 0.0f) query.minCombinedScore = request->min_score();
    if (request->start_time_us() > 0) query.startTimeUs = request->start_time_us();
    if (request->end_time_us() > 0) query.endTimeUs = request->end_time_us();
    query.limit = request->limit() > 0 ? request->limit() : 100;
    query.offset = request->offset();

    auto flows = flowIndex_->query(query);
    auto total = flowIndex_->count(query);

    for (const auto& f : flows) {
        auto* proto = response->add_flows();
        proto->set_id(f.id);
        proto->set_timestamp_us(f.timestampUs);
        proto->set_src_ip(f.srcIp);
        proto->set_dst_ip(f.dstIp);
        proto->set_src_port(f.srcPort);
        proto->set_dst_port(f.dstPort);
        proto->set_protocol(f.protocol);
        proto->set_packet_count(f.packetCount);
        proto->set_byte_count(f.byteCount);
        proto->set_duration_us(f.durationUs);
        proto->set_verdict(std::string{core::attackTypeToString(f.verdict)});
        proto->set_ml_confidence(f.mlConfidence);
        proto->set_combined_score(f.combinedScore);
        proto->set_detection_source(
            std::string{core::detectionSourceToString(f.detectionSource)});
        proto->set_is_flagged(f.isFlagged);
    }
    response->set_total_count(total);

    return grpc::Status::OK;
}

grpc::Status NidsServiceImpl::IocSearch(
    [[maybe_unused]] grpc::ServerContext* context,
    const IocSearchRequest* request,
    IocSearchResponse* response) {
    if (!flowIndex_) {
        return grpc::Status(grpc::StatusCode::UNAVAILABLE,
                            "Flow index not configured");
    }

    // Search for each IP.
    std::size_t totalScanned = 0;
    for (const auto& ip : request->ips()) {
        core::FlowQuery query;
        query.anyIp = ip;
        if (request->start_time_us() > 0) query.startTimeUs = request->start_time_us();
        if (request->end_time_us() > 0) query.endTimeUs = request->end_time_us();

        auto flows = flowIndex_->query(query);
        totalScanned += flows.size();
        for (const auto& f : flows) {
            auto* proto = response->add_matched_flows();
            proto->set_id(f.id);
            proto->set_src_ip(f.srcIp);
            proto->set_dst_ip(f.dstIp);
            proto->set_src_port(f.srcPort);
            proto->set_dst_port(f.dstPort);
            proto->set_verdict(std::string{core::attackTypeToString(f.verdict)});
            proto->set_combined_score(f.combinedScore);
            proto->set_is_flagged(f.isFlagged);
        }
    }
    response->set_total_scanned(totalScanned);

    return grpc::Status::OK;
}

// ── Phase 15: Signature management RPCs ─────────────────────────────

grpc::Status NidsServiceImpl::LoadRules(
    [[maybe_unused]] grpc::ServerContext* context,
    const LoadRulesRequest* request,
    LoadRulesResponse* response) {
    if (!signatureEngine_) {
        response->set_success(false);
        response->set_message("Signature engine not configured");
        return grpc::Status::OK;
    }

    bool ok = signatureEngine_->loadRules(request->path());
    response->set_success(ok);
    response->set_rules_loaded(
        static_cast<std::uint32_t>(signatureEngine_->ruleCount()));
    response->set_message(ok ? "Rules loaded successfully" : "Failed to load rules");
    return grpc::Status::OK;
}

grpc::Status NidsServiceImpl::GetRuleStats(
    [[maybe_unused]] grpc::ServerContext* context,
    [[maybe_unused]] const GetRuleStatsRequest* request,
    GetRuleStatsResponse* response) {
    if (signatureEngine_) {
        response->set_total_rules(
            static_cast<std::uint32_t>(signatureEngine_->ruleCount()));
        response->set_rule_files(
            static_cast<std::uint32_t>(signatureEngine_->fileCount()));
    }
    if (contentScanner_) {
        response->set_yara_rules(
            static_cast<std::uint32_t>(contentScanner_->ruleCount()));
        response->set_yara_files(
            static_cast<std::uint32_t>(contentScanner_->fileCount()));
    }
    return grpc::Status::OK;
}

// ── Phase 16: Inline IPS RPCs ───────────────────────────────────────

grpc::Status NidsServiceImpl::GetInlineStats(
    [[maybe_unused]] grpc::ServerContext* context,
    [[maybe_unused]] const GetInlineStatsRequest* request,
    GetInlineStatsResponse* response) {
    response->set_inline_active(verdictEngine_ != nullptr);
    if (verdictEngine_) {
        response->set_blocked_flows(verdictEngine_->blockCount());
    }
    return grpc::Status::OK;
}

grpc::Status NidsServiceImpl::BlockFlow(
    [[maybe_unused]] grpc::ServerContext* context,
    const BlockFlowRequest* request,
    BlockFlowResponse* response) {
    if (!verdictEngine_) {
        response->set_success(false);
        response->set_message("Inline IPS not active");
        return grpc::Status::OK;
    }

    core::FlowKey key{
        request->src_ip(), request->dst_ip(),
        static_cast<std::uint16_t>(request->src_port()),
        static_cast<std::uint16_t>(request->dst_port()),
        static_cast<std::uint8_t>(request->protocol())};

    verdictEngine_->blockFlow(key, request->reason());
    response->set_success(true);
    response->set_message("Flow blocked");
    return grpc::Status::OK;
}

grpc::Status NidsServiceImpl::UnblockFlow(
    [[maybe_unused]] grpc::ServerContext* context,
    const UnblockFlowRequest* request,
    UnblockFlowResponse* response) {
    if (!verdictEngine_) {
        response->set_success(false);
        return grpc::Status::OK;
    }

    core::FlowKey key{
        request->src_ip(), request->dst_ip(),
        static_cast<std::uint16_t>(request->src_port()),
        static_cast<std::uint16_t>(request->dst_port()),
        static_cast<std::uint8_t>(request->protocol())};

    verdictEngine_->unblockFlow(key);
    response->set_success(true);
    return grpc::Status::OK;
}

// ── Health check ────────────────────────────────────────────────────

grpc::Status NidsServiceImpl::HealthCheck(
    [[maybe_unused]] grpc::ServerContext* context,
    [[maybe_unused]] const HealthCheckRequest* request,
    HealthCheckResponse* response) {
    response->set_healthy(true);
    response->set_version("0.2.0");

    // Calculate uptime (approximate — from process start).
    static const auto startTime = std::chrono::steady_clock::now();
    const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - startTime);
    response->set_uptime_seconds(static_cast<uint64_t>(uptime.count()));

    std::scoped_lock lock{sessionMutex_};
    if (pipeline_) {
        response->set_total_flows_processed(pipeline_->flowsDetected());
    }
    if (session_) {
        response->set_total_alerts(session_->flaggedResultCount());
    }

    return grpc::Status::OK;
}

// ── Session management ──────────────────────────────────────────────

void NidsServiceImpl::createSessionPipeline(const std::string& iface) {
    // Create session and pipeline
    session_ = std::make_unique<core::CaptureSession>();
    pipeline_ = std::make_unique<app::LiveDetectionPipeline>(
        extractor_, analyzer_, normalizer_, *session_);
    pipeline_->setHybridDetection(&hybridService_);

    // Register all active stream sinks
    {
        std::scoped_lock sinkLock(sinksMutex_);
        for (auto* sink : activeSinks_) {
            pipeline_->addOutputSink(sink);
        }
    }

    // Generate session ID
    auto now = std::chrono::system_clock::now();
    auto epoch = now.time_since_epoch();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    sessionId_ = std::format("session-{}", ms);
    currentInterface_ = iface;

    // Wire raw packets into pipeline
    capture_.setRawPacketCallback(
        [this](const std::uint8_t* data, std::size_t length,
               std::int64_t timestampUs) {
            pipeline_->feedPacket(data, length, timestampUs);
        });

    // Start pipeline
    pipeline_->start();
}

void NidsServiceImpl::registerSink(GrpcStreamSink* sink) {
    std::scoped_lock lock(sinksMutex_);
    activeSinks_.push_back(sink);
}

void NidsServiceImpl::unregisterSink(GrpcStreamSink* sink) {
    std::scoped_lock lock(sinksMutex_);
    std::erase(activeSinks_, sink);
}

} // namespace nids::server
