#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace nids::core {

/** Captured packet metadata and payload. */
struct PacketInfo {
    /** IANA protocol number (6=TCP, 17=UDP, 1=ICMP, 0=unknown). */
    std::uint8_t protocol = 0;
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
