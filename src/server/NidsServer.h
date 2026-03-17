#pragma once

/// gRPC Server for the NIDS headless daemon.
///
/// This header provides the top-level NidsServer class and re-exports
/// the split sub-headers for backward compatibility:
///   - ServerConfig      (server/ServerConfig.h)
///   - GrpcStreamSink    (server/GrpcStreamSink.h)
///   - NidsServiceImpl   (server/NidsServiceImpl.h)

#include "server/ServerConfig.h"
#include "server/NidsServiceImpl.h"

#include <grpcpp/grpcpp.h>

#include <atomic>
#include <memory>

namespace nids::server {

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
