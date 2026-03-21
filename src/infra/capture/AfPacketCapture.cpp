#ifdef __linux__

#include "infra/capture/AfPacketCapture.h"

#include <spdlog/spdlog.h>

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

namespace nids::infra {

AfPacketCapture::AfPacketCapture() = default;

AfPacketCapture::~AfPacketCapture() {
    stop();
    if (ringBuffer_ && ringBuffer_ != MAP_FAILED) {
        ::munmap(ringBuffer_, ringSize_);
    }
    if (rxFd_ >= 0) ::close(rxFd_);
    if (txFd_ >= 0) ::close(txFd_);
}

bool AfPacketCapture::initialize(const core::InlineConfig& config) {
    config_ = config;

    if (!setupSocket(config.inputInterface, rxFd_)) return false;
    if (!setupTpacketV3(rxFd_)) return false;
    if (!bindToInterface(rxFd_, config.inputInterface)) return false;
    if (config.promiscuous) {
        [[maybe_unused]] auto ok = setPromiscuous(config.inputInterface, rxFd_);
    }

    // TX socket (plain raw socket for forwarding).
    txFd_ = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (txFd_ < 0) {
        spdlog::error("AfPacketCapture: TX socket() failed: {}",
                      std::strerror(errno));
        return false;
    }
    if (!bindToInterface(txFd_, config.outputInterface)) return false;

    spdlog::info("AfPacketCapture: initialized {} -> {} "
                 "(TPACKET_V3, {} blocks x {} bytes)",
                 config.inputInterface, config.outputInterface,
                 kBlockCount, kBlockSize);
    return true;
}

bool AfPacketCapture::setupSocket(
    [[maybe_unused]] const std::string& iface, int& fd) const {
    fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        spdlog::error("AfPacketCapture: socket() failed for {}: {}",
                      iface, std::strerror(errno));
        return false;
    }
    return true;
}

bool AfPacketCapture::setupTpacketV3(int fd) {
    int version = TPACKET_V3;
    if (::setsockopt(fd, SOL_PACKET, PACKET_VERSION,
                     &version, sizeof(version)) < 0) {
        spdlog::error("AfPacketCapture: PACKET_VERSION V3 failed: {}",
                      std::strerror(errno));
        return false;
    }

    tpacket_req3 req{};
    req.tp_block_size = kBlockSize;
    req.tp_block_nr = kBlockCount;
    req.tp_frame_size = kFrameSize;
    req.tp_frame_nr = (kBlockSize / kFrameSize) * kBlockCount;
    req.tp_retire_blk_tov = 60;
    req.tp_sizeof_priv = 0;
    req.tp_feature_req_word = 0;

    if (::setsockopt(fd, SOL_PACKET, PACKET_RX_RING,
                     &req, sizeof(req)) < 0) {
        spdlog::error("AfPacketCapture: PACKET_RX_RING failed: {}",
                      std::strerror(errno));
        return false;
    }

    ringSize_ = static_cast<std::size_t>(kBlockSize) * kBlockCount;
    ringBuffer_ = ::mmap(nullptr, ringSize_,
                         PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_LOCKED,
                         fd, 0);

    if (ringBuffer_ == MAP_FAILED) {
        spdlog::error("AfPacketCapture: mmap() failed: {}",
                      std::strerror(errno));
        ringBuffer_ = nullptr;
        return false;
    }

    return true;
}

bool AfPacketCapture::bindToInterface(
    int fd, const std::string& iface) const {
    unsigned int ifIndex = ::if_nametoindex(iface.c_str());
    if (ifIndex == 0) {
        spdlog::error("AfPacketCapture: interface '{}' not found", iface);
        return false;
    }

    sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = static_cast<int>(ifIndex);

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), // NOLINT
               sizeof(addr)) < 0) {
        spdlog::error("AfPacketCapture: bind() failed for {}: {}",
                      iface, std::strerror(errno));
        return false;
    }
    return true;
}

bool AfPacketCapture::setPromiscuous(
    const std::string& iface, int fd) const {
    struct ifreq ifr{};
    iface.copy(ifr.ifr_name, IFNAMSIZ - 1);

    if (::ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        spdlog::warn("AfPacketCapture: SIOCGIFFLAGS failed for {}", iface);
        return false;
    }

    ifr.ifr_flags |= IFF_PROMISC;
    if (::ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        spdlog::warn("AfPacketCapture: cannot set promiscuous on {}", iface);
        return false;
    }
    return true;
}

void AfPacketCapture::setVerdictCallback(core::VerdictCallback cb) {
    verdictCb_ = std::move(cb);
}

void AfPacketCapture::forwardPacket(const std::uint8_t* data,
                                     std::size_t len) {
    if (auto sent = ::send(txFd_, data, len, 0); sent < 0) {
        spdlog::debug("AfPacketCapture: send() failed: {}",
                      std::strerror(errno));
    } else {
        packetsForwarded_.fetch_add(1);
        bytesForwarded_.fetch_add(len);
    }
}

// ── TPACKET_V3 capture loop ────────────────────────────────────────

void AfPacketCapture::start() {
    running_.store(true);
    captureLoop();
}

void AfPacketCapture::stop() {
    running_.store(false);
}

void AfPacketCapture::captureLoop() {
    if (!ringBuffer_) {
        spdlog::error("AfPacketCapture: ring buffer not initialized");
        return;
    }

    pollfd pfd{};
    pfd.fd = rxFd_;
    pfd.events = POLLIN | POLLERR;

    unsigned blockIdx = 0;

    while (running_.load()) {
        auto* blockPtr = static_cast<std::uint8_t*>(ringBuffer_) +
                         blockIdx * kBlockSize;
        auto* hdr = reinterpret_cast<tpacket_block_desc*>(blockPtr); // NOLINT

        if ((hdr->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
            if (int ret = ::poll(&pfd, 1, 100); ret <= 0) continue;
            if ((hdr->hdr.bh1.block_status & TP_STATUS_USER) == 0) continue;
        }

        processBlock(hdr);

        hdr->hdr.bh1.block_status = TP_STATUS_KERNEL;
        blockIdx = (blockIdx + 1) % kBlockCount;
    }
}

void AfPacketCapture::processBlock(void* blockHeader) {
    auto* hdr = static_cast<tpacket_block_desc*>(blockHeader);
    auto numPkts = hdr->hdr.bh1.num_pkts;
    auto* pkt = reinterpret_cast<tpacket3_hdr*>( // NOLINT
        static_cast<std::uint8_t*>(blockHeader) +
        hdr->hdr.bh1.offset_to_first_pkt);

    for (std::uint32_t i = 0; i < numPkts; ++i) {
        auto* data = reinterpret_cast<const std::uint8_t*>(pkt) + // NOLINT
                     pkt->tp_mac;
        auto len = pkt->tp_snaplen;

        packetsReceived_.fetch_add(1);
        bytesReceived_.fetch_add(len);

        auto timestampUs = static_cast<int64_t>(pkt->tp_sec) * 1'000'000 +
                           static_cast<int64_t>(pkt->tp_nsec) / 1'000;

        auto verdict = core::PacketVerdict::Forward;
        if (verdictCb_) {
            verdict = verdictCb_(
                std::span<const std::uint8_t>(data, len), timestampUs);
        }

        using enum core::PacketVerdict;
        switch (verdict) {
        case Forward:
        case Alert:
        case Bypass:
            forwardPacket(data, len);
            break;
        case Drop:
        case Reject:
            packetsDropped_.fetch_add(1);
            break;
        }

        pkt = reinterpret_cast<tpacket3_hdr*>( // NOLINT
            reinterpret_cast<std::uint8_t*>(pkt) + pkt->tp_next_offset);
    }
}

core::IInlineCapture::Stats AfPacketCapture::stats() const noexcept {
    Stats s;
    s.packetsReceived = packetsReceived_.load();
    s.packetsForwarded = packetsForwarded_.load();
    s.packetsDropped = packetsDropped_.load();
    s.bytesReceived = bytesReceived_.load();
    s.bytesForwarded = bytesForwarded_.load();
    return s;
}

} // namespace nids::infra

#endif // __linux__
