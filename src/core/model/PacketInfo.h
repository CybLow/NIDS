#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace nids::core {

/** Captured packet metadata and payload. */
struct PacketInfo {
    /** Transport/network protocol name (e.g., "TCP", "UDP", "ICMP"). */
    std::string protocol;
    /** Resolved application-layer service name (e.g., "HTTP", "SSH"). */
    std::string application;
    /** Source IPv4 address in dotted-decimal notation. */
    std::string ipSource;
    /** Source transport port (0 for protocols without ports, e.g. ICMP). */
    std::uint16_t portSource = 0;
    /** Destination IPv4 address in dotted-decimal notation. */
    std::string ipDestination;
    /** Destination transport port (0 for protocols without ports, e.g. ICMP). */
    std::uint16_t portDestination = 0;
    /** Raw packet bytes from the capture. */
    std::vector<std::uint8_t> rawData;
};

} // namespace nids::core
