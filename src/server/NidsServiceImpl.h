#pragma once

/// gRPC service implementation for NidsService.
///
/// Handles RPC methods: ListInterfaces, StartCapture, StopCapture,
/// StreamDetections, StreamPackets, AnalyzeCapture, GetStatus.
///
/// Thread model: gRPC server runs on its own thread pool; each RPC handler
/// may run on any thread.  Streaming RPCs bridge the detection pipeline
/// to gRPC writers via per-stream queues.

#include "server/GrpcStreamSink.h"

#include "app/HybridDetectionService.h"
#include "app/LiveDetectionPipeline.h"
#include "core/model/CaptureSession.h"
#include "core/services/IFeatureNormalizer.h"
#include "core/services/IFlowExtractor.h"
#include "core/services/IPacketAnalyzer.h"
#include "core/services/IPacketCapture.h"

#include <nids.grpc.pb.h>
#include <nids.pb.h>

#include <grpcpp/grpcpp.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace nids::server {

/** gRPC service implementation for NidsService. */
class NidsServiceImpl final : public NidsService::Service {
public:
    /**
     * Construct with injected dependencies.
     * All references are non-owning and must outlive the service.
     */
    NidsServiceImpl(core::IPacketCapture& capture,
                    core::IFlowExtractor& extractor,
                    core::IPacketAnalyzer& analyzer,
                    core::IFeatureNormalizer& normalizer,
                    app::HybridDetectionService& hybridService);

    ~NidsServiceImpl() override = default;

    grpc::Status ListInterfaces(
        grpc::ServerContext* context,
        const ListInterfacesRequest* request,
        ListInterfacesResponse* response) override;

    grpc::Status StartCapture(
        grpc::ServerContext* context,
        const StartCaptureRequest* request,
        StartCaptureResponse* response) override;

    grpc::Status StopCapture(
        grpc::ServerContext* context,
        const StopCaptureRequest* request,
        StopCaptureResponse* response) override;

    grpc::Status StreamDetections(
        grpc::ServerContext* context,
        const StreamDetectionsRequest* request,
        grpc::ServerWriter<DetectionEvent>* writer) override;

    grpc::Status StreamPackets(
        grpc::ServerContext* context,
        const StreamPacketsRequest* request,
        grpc::ServerWriter<PacketEvent>* writer) override;

    grpc::Status AnalyzeCapture(
        grpc::ServerContext* context,
        const AnalyzeCaptureRequest* request,
        AnalyzeCaptureResponse* response) override;

    grpc::Status GetStatus(
        grpc::ServerContext* context,
        const GetStatusRequest* request,
        GetStatusResponse* response) override;

private:
    core::IPacketCapture& capture_;
    core::IFlowExtractor& extractor_;
    core::IPacketAnalyzer& analyzer_;
    core::IFeatureNormalizer& normalizer_;
    app::HybridDetectionService& hybridService_;

    // Session state
    mutable std::mutex sessionMutex_;
    std::unique_ptr<core::CaptureSession> session_;
    std::unique_ptr<app::LiveDetectionPipeline> pipeline_;
    std::string sessionId_;
    std::string currentInterface_;
    std::atomic<bool> capturing_{false};

    // Stream sinks (one per connected StreamDetections client)
    mutable std::mutex sinksMutex_;
    std::vector<GrpcStreamSink*> activeSinks_;

    void registerSink(GrpcStreamSink* sink);
    void unregisterSink(GrpcStreamSink* sink);

    /// Create session, pipeline, wire callbacks and generate session ID.
    /// Called from StartCapture with sessionMutex_ held.
    void createSessionPipeline(const std::string& iface);
};

} // namespace nids::server
