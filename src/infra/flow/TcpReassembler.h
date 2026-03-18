#pragma once

/// TcpReassembler — reassembles TCP streams for deep content scanning.
///
/// Wraps PcapPlusPlus TcpReassembly to collect client/server payload data
/// per TCP connection. When a stream completes (or exceeds the size limit),
/// invokes a callback with the reassembled data for YARA scanning.

#include "core/model/FlowInfo.h"

#include <pcapplusplus/TcpReassembly.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace nids::infra {

struct ReassemblyConfig {
    std::size_t maxStreamSize = 1 * 1024 * 1024;  ///< 1 MB per stream
    std::size_t maxConcurrentStreams = 10000;
};

/// Callback invoked when a TCP stream is complete or reaches maxStreamSize.
using StreamCallback = std::function<void(
    const core::FlowInfo& flow,
    std::span<const std::uint8_t> clientData,
    std::span<const std::uint8_t> serverData)>;

class TcpReassembler {
public:
    explicit TcpReassembler(ReassemblyConfig config = {});
    ~TcpReassembler();

    TcpReassembler(const TcpReassembler&) = delete;
    TcpReassembler& operator=(const TcpReassembler&) = delete;

    /// Set callback for completed/flushed streams.
    void setCallback(StreamCallback cb);

    /// Feed a raw packet for reassembly.
    void processPacket(pcpp::RawPacket& packet);

    /// Flush all active streams (e.g., at end of capture).
    void flushAll();

    /// Reset all state.
    void reset();

    /// Number of currently active streams.
    [[nodiscard]] std::size_t activeStreams() const noexcept;

    /// Total number of completed streams.
    [[nodiscard]] std::size_t completedStreams() const noexcept;

private:
    /// Per-connection stream state.
    struct StreamState {
        core::FlowInfo flow;
        std::vector<std::uint8_t> clientData;
        std::vector<std::uint8_t> serverData;
        std::size_t totalBytes = 0;
    };

    /// PcapPlusPlus callbacks.
    static void onMessageReady(std::int8_t side,
                                const pcpp::TcpStreamData& streamData,
                                void* userData);
    static void onConnectionStart(const pcpp::ConnectionData& connectionData,
                                   void* userData);
    static void onConnectionEnd(const pcpp::ConnectionData& connectionData,
                                 pcpp::TcpReassembly::ConnectionEndReason reason,
                                 void* userData);

    void deliverStream(std::uint32_t connId);

    ReassemblyConfig config_;
    std::unique_ptr<pcpp::TcpReassembly> reassembly_;
    StreamCallback callback_;
    std::unordered_map<std::uint32_t, StreamState> streams_;
    std::size_t completedStreams_ = 0;
    mutable std::mutex mutex_;
};

} // namespace nids::infra
