#pragma once

/// Configuration struct for the NIDS gRPC server.

#include <string>

namespace nids::server {

/** Configuration for the gRPC server. */
struct ServerConfig {
    /** Address and port to listen on (e.g. "0.0.0.0:50051"). */
    std::string listenAddress = "0.0.0.0:50051";
    /** Maximum number of concurrent capture/analysis sessions. */
    int maxConcurrentSessions = 4;
};

} // namespace nids::server
