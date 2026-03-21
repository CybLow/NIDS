#pragma once

/// AfPacketCapture — AF_PACKET inline capture for IPS mode.
///
/// Inline packet capture using Linux AF_PACKET raw sockets with
/// poll()-based receive and per-packet verdict callback. Currently
/// uses recv() (copy-based); TPACKET_V3 mmap ring buffers and
/// PACKET_FANOUT multi-queue are planned optimizations.
/// Linux-only — compiled only on Linux via CMake generator expression.

#ifdef __linux__

#include "core/services/IInlineCapture.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

namespace nids::infra {

class AfPacketCapture final : public core::IInlineCapture {
public:
    AfPacketCapture();
    ~AfPacketCapture() override;

    AfPacketCapture(const AfPacketCapture&) = delete;
    AfPacketCapture& operator=(const AfPacketCapture&) = delete;

    [[nodiscard]] bool initialize(const core::InlineConfig& config) override;
    void setVerdictCallback(core::VerdictCallback cb) override;
    void start() override;
    void stop() override;
    [[nodiscard]] core::IInlineCapture::Stats stats() const noexcept override;

private:
    [[nodiscard]] bool createSocket(const std::string& iface, int& fd) const;
    [[nodiscard]] bool bindToInterface(int fd, const std::string& iface) const;
    [[nodiscard]] bool setPromiscuous(const std::string& iface, int fd) const;
    void forwardPacket(const std::uint8_t* data, std::size_t len);
    void captureLoop();

    core::InlineConfig config_;
    core::VerdictCallback verdictCb_;

    int rxFd_ = -1;   ///< AF_PACKET socket for input NIC
    int txFd_ = -1;   ///< Raw socket for output NIC

    std::atomic<bool> running_{false};
    mutable std::atomic<std::uint64_t> packetsReceived_{0};
    mutable std::atomic<std::uint64_t> packetsForwarded_{0};
    mutable std::atomic<std::uint64_t> packetsDropped_{0};
    mutable std::atomic<std::uint64_t> bytesReceived_{0};
    mutable std::atomic<std::uint64_t> bytesForwarded_{0};
};

} // namespace nids::infra

#endif // __linux__
