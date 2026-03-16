#include "server/NidsServer.h"

#include "core/model/AttackType.h"
#include "core/model/ProtocolConstants.h"

#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <sstream>

namespace nids::server {

// ────────────────────────────────────────────────────────────────
// GrpcStreamSink
// ────────────────────────────────────────────────────────────────

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
        match->set_severity(static_cast<std::uint32_t>(rule.severity));
    }

    // Combined result
    event.set_verdict(result.finalVerdict == nids::core::AttackType::Benign
                          ? ::nids::VERDICT_BENIGN
                          : ::nids::VERDICT_ATTACK);
    event.set_combined_score(result.combinedScore);
    event.set_source(
        static_cast<::nids::DetectionSourceType>(result.detectionSource));
}

// ────────────────────────────────────────────────────────────────
// NidsServiceImpl
// ────────────────────────────────────────────────────────────────

NidsServiceImpl::NidsServiceImpl(
    nids::core::IPacketCapture& capture,
    nids::core::IFlowExtractor& extractor,
    nids::core::IPacketAnalyzer& analyzer,
    nids::core::IFeatureNormalizer& normalizer,
    nids::app::HybridDetectionService& hybridService)
    : capture_(capture),
      extractor_(extractor),
      analyzer_(analyzer),
      normalizer_(normalizer),
      hybridService_(hybridService) {}

grpc::Status NidsServiceImpl::ListInterfaces(
    grpc::ServerContext* /*context*/,
    const ::nids::ListInterfacesRequest* /*request*/,
    ::nids::ListInterfacesResponse* response) {

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
    const ::nids::StartCaptureRequest* request,
    ::nids::StartCaptureResponse* response) {

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

    // Create session and pipeline
    session_ = std::make_unique<nids::core::CaptureSession>();
    pipeline_ = std::make_unique<nids::app::LiveDetectionPipeline>(
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
    std::ostringstream oss;
    oss << "session-" << ms;
    sessionId_ = oss.str();
    currentInterface_ = iface;

    // Wire raw packets into pipeline
    capture_.setRawPacketCallback(
        [this](const std::uint8_t* data, std::size_t length,
               std::int64_t timestampUs) {
            pipeline_->feedPacket(data, length, timestampUs);
        });

    // Start pipeline and capture
    pipeline_->start();
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
    const ::nids::StopCaptureRequest* /*request*/,
    ::nids::StopCaptureResponse* response) {

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
    response->set_flagged_flows(session_ ? session_->detectionResultCount() : 0);
    response->set_dropped_flows(droppedFlows);

    spdlog::info("gRPC: Capture stopped — {} flows detected, {} dropped",
                 flowsDetected, droppedFlows);
    return grpc::Status::OK;
}

grpc::Status NidsServiceImpl::StreamDetections(
    grpc::ServerContext* context,
    const ::nids::StreamDetectionsRequest* request,
    grpc::ServerWriter<::nids::DetectionEvent>* writer) {

    spdlog::info("gRPC: Client connected for detection streaming (filter={})",
                 static_cast<int>(request->filter()));

    // Create a per-client event queue and sink
    auto eventQueue =
        std::make_shared<GrpcStreamSink::EventQueue>(1024);
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
    grpc::ServerContext* /*context*/,
    const ::nids::StreamPacketsRequest* /*request*/,
    grpc::ServerWriter<::nids::PacketEvent>* /*writer*/) {

    return grpc::Status(grpc::StatusCode::UNIMPLEMENTED,
                        "Packet streaming not yet implemented");
}

grpc::Status NidsServiceImpl::AnalyzeCapture(
    grpc::ServerContext* /*context*/,
    const ::nids::AnalyzeCaptureRequest* /*request*/,
    ::nids::AnalyzeCaptureResponse* response) {

    response->set_success(false);
    return grpc::Status(grpc::StatusCode::UNIMPLEMENTED,
                        "Batch analysis via gRPC not yet implemented");
}

grpc::Status NidsServiceImpl::GetStatus(
    grpc::ServerContext* /*context*/,
    const ::nids::GetStatusRequest* /*request*/,
    ::nids::GetStatusResponse* response) {

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

    // Count flagged flows
    if (session_) {
        std::size_t flagged = 0;
        const auto total = session_->detectionResultCount();
        for (std::size_t i = 0; i < total; ++i) {
            const auto& result = session_->getDetectionResult(i);
            if (result.isFlagged()) {
                ++flagged;
            }
        }
        response->set_flows_flagged(flagged);
    }

    return grpc::Status::OK;
}

void NidsServiceImpl::registerSink(GrpcStreamSink* sink) {
    std::scoped_lock lock(sinksMutex_);
    activeSinks_.push_back(sink);
}

void NidsServiceImpl::unregisterSink(GrpcStreamSink* sink) {
    std::scoped_lock lock(sinksMutex_);
    std::erase(activeSinks_, sink);
}

// ────────────────────────────────────────────────────────────────
// NidsServer
// ────────────────────────────────────────────────────────────────

NidsServer::NidsServer(const ServerConfig& config) : config_(config) {}

NidsServer::~NidsServer() noexcept {
    try {
        stop();
    } catch (...) {
        spdlog::error("Exception in NidsServer destructor during stop()");
    }
}

void NidsServer::setService(std::unique_ptr<NidsServiceImpl> service) {
    service_ = std::move(service);
}

void NidsServer::start() {
    if (running_.load()) {
        return;
    }
    if (!service_) {
        spdlog::error("NidsServer::start() called without a service");
        return;
    }

    grpc::ServerBuilder builder;
    builder.AddListeningPort(config_.listenAddress,
                             grpc::InsecureServerCredentials());
    builder.RegisterService(service_.get());

    builder.SetSyncServerOption(
        grpc::ServerBuilder::SyncServerOption::NUM_CQS,
        config_.maxConcurrentSessions);

    server_ = builder.BuildAndStart();
    if (!server_) {
        spdlog::critical("Failed to start gRPC server on {}",
                         config_.listenAddress);
        return;
    }

    running_.store(true);
    spdlog::info("NIDS gRPC server listening on {}", config_.listenAddress);
}

void NidsServer::stop() {
    if (!running_.load()) {
        return;
    }
    running_.store(false);

    if (server_) {
        auto deadline = std::chrono::system_clock::now() +
                        std::chrono::seconds(5);
        server_->Shutdown(deadline);
        spdlog::info("NIDS gRPC server stopped");
    }
}

void NidsServer::waitForShutdown() {
    if (server_) {
        server_->Wait();
    }
}

} // namespace nids::server
