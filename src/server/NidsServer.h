#pragma once

/// gRPC Server for the NIDS headless daemon.
///
/// Implements the NidsService defined in proto/nids.proto.
/// Manages capture sessions and streams detection results to clients.
///
/// Thread model:
///   - gRPC server runs on its own thread pool (managed by grpc::Server).
///   - Each RPC handler may run on any thread in the pool.
///   - Streaming RPCs (StreamDetections, StreamPackets) use per-stream
///     queues to bridge the detection pipeline to gRPC writers.
///   - Capture/detection pipeline runs on its own threads (PcapCapture
///     thread + FlowAnalysisWorker jthread), independent of gRPC threads.

#include "app/HybridDetectionService.h"
#include "app/LiveDetectionPipeline.h"
#include "core/model/CaptureSession.h"
#include "core/model/DetectionResult.h"
#include "core/services/Configuration.h"
#include "core/services/IFeatureNormalizer.h"
#include "core/services/IFlowExtractor.h"
#include "core/services/IOutputSink.h"
#include "core/services/IPacketAnalyzer.h"
#include "core/services/IPacketCapture.h"

#include <nids.grpc.pb.h>
#include <nids.pb.h>

#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace nids::server {

/** Configuration for the gRPC server. */
struct ServerConfig {
    /** Address and port to listen on (e.g. "0.0.0.0:50051"). */
    std::string listenAddress = "0.0.0.0:50051";
    /** Maximum number of concurrent capture/analysis sessions. */
    int maxConcurrentSessions = 4;
};

/** gRPC output sink that queues detection events for streaming to clients. */
class GrpcStreamSink : public nids::core::IOutputSink {
public:
    using EventQueue = nids::core::BoundedQueue<::nids::DetectionEvent>;

    explicit GrpcStreamSink(std::shared_ptr<EventQueue> queue,
                            ::nids::DetectionFilter filter);

    [[nodiscard]] std::string_view name() const noexcept override {
        return "GrpcStreamSink";
    }

    void onFlowResult(std::size_t flowIndex,
                      const nids::core::DetectionResult& result,
                      const nids::core::FlowInfo& flow) override;

private:
    std::shared_ptr<EventQueue> queue_;
    ::nids::DetectionFilter filter_;

    static void populateDetectionEvent(::nids::DetectionEvent& event,
                                       std::size_t flowIndex,
                                       const nids::core::DetectionResult& result,
                                       const nids::core::FlowInfo& flow);
};

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

/** Top-level gRPC server that owns the grpc::Server instance. */
class NidsServer {
public:
    explicit NidsServer(const ServerConfig& config);
    ~NidsServer() noexcept;

    NidsServer(const NidsServer&) = delete;
    NidsServer& operator=(const NidsServer&) = delete;
    NidsServer(NidsServer&&) = delete;
    NidsServer& operator=(NidsServer&&) = delete;

    /** Register the service implementation. Must be called before start(). */
    void setService(std::unique_ptr<NidsServiceImpl> service);

    /** Start the gRPC server and begin accepting connections. */
    void start();

    /** Initiate a graceful shutdown of the server. */
    void stop();

    /** Block the calling thread until the server has fully shut down. */
    void waitForShutdown();

private:
    ServerConfig config_;
    std::unique_ptr<NidsServiceImpl> service_;
    std::unique_ptr<grpc::Server> server_;
    std::atomic<bool> running_{false};
};

} // namespace nids::server
