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
#include <sys/socket.h>
#include <unistd.h>

namespace nids::infra {

AfPacketCapture::AfPacketCapture() = default;

AfPacketCapture::~AfPacketCapture() {
    stop();
    if (rxFd_ >= 0) ::close(rxFd_);
    if (txFd_ >= 0) ::close(txFd_);
}

bool AfPacketCapture::initialize(const core::InlineConfig& config) {
    config_ = config;

    if (!createSocket(config.inputInterface, rxFd_)) return false;
    if (!bindToInterface(rxFd_, config.inputInterface)) return false;
    if (config.promiscuous) {
        [[maybe_unused]] auto ok = setPromiscuous(config.inputInterface, rxFd_);
    }

    if (!createSocket(config.outputInterface, txFd_)) return false;
    if (!bindToInterface(txFd_, config.outputInterface)) return false;

    spdlog::info("AfPacketCapture: initialized {} -> {}",
                 config.inputInterface, config.outputInterface);
    return true;
}

bool AfPacketCapture::createSocket(
    [[maybe_unused]] const std::string& iface, int& fd) const {
    fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        spdlog::error("AfPacketCapture: socket() failed for {}: {}",
                      iface, std::strerror(errno));
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
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

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

void AfPacketCapture::start() {
    running_.store(true);
    captureLoop();
}

void AfPacketCapture::stop() {
    running_.store(false);
}

void AfPacketCapture::captureLoop() {
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(config_.snaplen));

    pollfd pfd{};
    pfd.fd = rxFd_;
    pfd.events = POLLIN;

    while (running_.load()) {
        if (int ret = ::poll(&pfd, 1, 100); ret <= 0) continue;

        auto len = ::recv(rxFd_, buf.data(), buf.size(), MSG_DONTWAIT);
        if (len <= 0) continue;

        auto pktLen = static_cast<std::size_t>(len);
        packetsReceived_.fetch_add(1);
        bytesReceived_.fetch_add(pktLen);

        using namespace std::chrono;
        auto nowUs = duration_cast<microseconds>(
            system_clock::now().time_since_epoch()).count();

        auto verdict = core::PacketVerdict::Forward;
        if (verdictCb_) {
            verdict = verdictCb_(
                std::span<const std::uint8_t>(buf.data(), pktLen), nowUs);
        }

        using enum core::PacketVerdict;
        switch (verdict) {
        case Forward:
        case Alert:
        case Bypass:
            forwardPacket(buf.data(), pktLen);
            break;
        case Drop:
        case Reject:
            packetsDropped_.fetch_add(1);
            break;
        }
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
