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
class NidsServiceImpl final : public ::nids::NidsService::Service {
public:
    /**
     * Construct with injected dependencies.
     * All references are non-owning and must outlive the service.
     */
    NidsServiceImpl(nids::core::IPacketCapture& capture,
                    nids::core::IFlowExtractor& extractor,
                    nids::core::IPacketAnalyzer& analyzer,
                    nids::core::IFeatureNormalizer& normalizer,
                    nids::app::HybridDetectionService& hybridService);

    ~NidsServiceImpl() override = default;

    grpc::Status ListInterfaces(
        grpc::ServerContext* context,
        const ::nids::ListInterfacesRequest* request,
        ::nids::ListInterfacesResponse* response) override;

    grpc::Status StartCapture(
        grpc::ServerContext* context,
        const ::nids::StartCaptureRequest* request,
        ::nids::StartCaptureResponse* response) override;

    grpc::Status StopCapture(
        grpc::ServerContext* context,
        const ::nids::StopCaptureRequest* request,
        ::nids::StopCaptureResponse* response) override;

    grpc::Status StreamDetections(
        grpc::ServerContext* context,
        const ::nids::StreamDetectionsRequest* request,
        grpc::ServerWriter<::nids::DetectionEvent>* writer) override;

    grpc::Status StreamPackets(
        grpc::ServerContext* context,
        const ::nids::StreamPacketsRequest* request,
        grpc::ServerWriter<::nids::PacketEvent>* writer) override;

    grpc::Status AnalyzeCapture(
        grpc::ServerContext* context,
        const ::nids::AnalyzeCaptureRequest* request,
        ::nids::AnalyzeCaptureResponse* response) override;

    grpc::Status GetStatus(
        grpc::ServerContext* context,
        const ::nids::GetStatusRequest* request,
        ::nids::GetStatusResponse* response) override;

private:
    nids::core::IPacketCapture& capture_;
    nids::core::IFlowExtractor& extractor_;
    nids::core::IPacketAnalyzer& analyzer_;
    nids::core::IFeatureNormalizer& normalizer_;
    nids::app::HybridDetectionService& hybridService_;

    // Session state
    mutable std::mutex sessionMutex_;
    std::unique_ptr<nids::core::CaptureSession> session_;
    std::unique_ptr<nids::app::LiveDetectionPipeline> pipeline_;
    std::string sessionId_;
    std::string currentInterface_;
    std::atomic<bool> capturing_{false};

    // Stream sinks (one per connected StreamDetections client)
    mutable std::mutex sinksMutex_;
    std::vector<GrpcStreamSink*> activeSinks_;

    void registerSink(GrpcStreamSink* sink);
    void unregisterSink(GrpcStreamSink* sink);
};

} // namespace nids::server
