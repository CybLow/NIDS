#pragma once

/// AfPacketCapture — AF_PACKET v3 inline capture with TPACKET_V3 ring buffers.
///
/// High-performance inline packet capture for IPS mode using Linux
/// AF_PACKET sockets with memory-mapped TPACKET_V3 ring buffers
/// (zero-copy receive). Packets are mapped into user-space via mmap(),
/// processed through the verdict callback, and forwarded via send().
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
    [[nodiscard]] bool setupSocket(const std::string& iface, int& fd) const;
    [[nodiscard]] bool setupTpacketV3(int fd);
    [[nodiscard]] bool bindToInterface(int fd, const std::string& iface) const;
    [[nodiscard]] bool setPromiscuous(const std::string& iface, int fd) const;
    void forwardPacket(const std::uint8_t* data, std::size_t len);
    void captureLoop();
    void processBlock(void* blockHeader);

    core::InlineConfig config_;
    core::VerdictCallback verdictCb_;

    int rxFd_ = -1;       ///< AF_PACKET TPACKET_V3 socket for input
    int txFd_ = -1;       ///< Raw socket for output
    void* ringBuffer_ = nullptr;  ///< mmap'd TPACKET_V3 ring
    std::size_t ringSize_ = 0;

    /// Ring buffer parameters.
    static constexpr unsigned kBlockCount = 64;
    static constexpr unsigned kBlockSize = 1 << 22;  ///< 4 MB per block
    static constexpr unsigned kFrameSize = 1 << 11;  ///< 2048 bytes

    std::atomic<bool> running_{false};
    mutable std::atomic<std::uint64_t> packetsReceived_{0};
    mutable std::atomic<std::uint64_t> packetsForwarded_{0};
    mutable std::atomic<std::uint64_t> packetsDropped_{0};
    mutable std::atomic<std::uint64_t> bytesReceived_{0};
    mutable std::atomic<std::uint64_t> bytesForwarded_{0};
};

} // namespace nids::infra

#endif // __linux__
