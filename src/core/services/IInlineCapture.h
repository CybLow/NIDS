#pragma once

/// IInlineCapture — interface for inline packet capture with verdict.
///
/// Abstracts the packet capture backend (AF_PACKET, NFQUEUE) for
/// inline IPS mode. The verdict callback is called on the hot path
/// for every received packet and must complete in <1ms.

#include "core/model/PacketVerdict.h"

#include <cstdint>
#include <functional>
#include <span>
#include <string>

namespace nids::core {

/// Configuration for inline IPS capture.
struct InlineConfig {
    std::string inputInterface;     ///< NIC receiving traffic (e.g., "eth0")
    std::string outputInterface;    ///< NIC forwarding traffic (e.g., "eth1")

    enum class FailMode : std::uint8_t {
        FailOpen,   ///< Forward all traffic if IPS fails (safety)
        FailClosed  ///< Drop all traffic if IPS fails (security)
    } failMode = FailMode::FailOpen;

    bool promiscuous = true;
    int snaplen = 65535;
};

/// Callback invoked for each received packet. Must return a verdict.
using VerdictCallback = std::function<PacketVerdict(
    std::span<const std::uint8_t> packet,
    int64_t timestampUs)>;

/// Interface for inline packet capture with verdict capability.
class IInlineCapture {
public:
    virtual ~IInlineCapture() = default;

    /// Initialize with two interfaces (input and output).
    [[nodiscard]] virtual bool initialize(const InlineConfig& config) = 0;

    /// Set the verdict callback (called for EVERY packet).
    virtual void setVerdictCallback(VerdictCallback cb) = 0;

    /// Start capture (blocking until stop()).
    virtual void start() = 0;

    /// Stop capture gracefully.
    virtual void stop() = 0;

    /// Performance counters.
    struct Stats {
        std::uint64_t packetsReceived = 0;
        std::uint64_t packetsForwarded = 0;
        std::uint64_t packetsDropped = 0;
        std::uint64_t packetsRejected = 0;
        std::uint64_t packetsBypassed = 0;
        std::uint64_t bytesReceived = 0;
        std::uint64_t bytesForwarded = 0;
        std::uint64_t kernelDrops = 0;
    };
    [[nodiscard]] virtual Stats stats() const noexcept = 0;
};

} // namespace nids::core
