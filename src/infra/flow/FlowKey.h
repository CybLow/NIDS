#pragma once

/// Five-tuple flow key identifying a unique bidirectional network flow.
///
/// Used by NativeFlowExtractor to track active flows in a hash map.
/// Header-only: no .cpp file needed.

#include <cstdint>
#include <functional>
#include <string>

namespace nids::infra {

/** Five-tuple flow key identifying a unique bidirectional network flow. */
struct FlowKey {
    /** Source IP address (dotted-decimal). */
    std::string srcIp;
    /** Destination IP address (dotted-decimal). */
    std::string dstIp;
    /** Source transport port. */
    std::uint16_t srcPort = 0;
    /** Destination transport port. */
    std::uint16_t dstPort = 0;
    /** IP protocol number (6=TCP, 17=UDP, 1=ICMP). */
    std::uint8_t protocol = 0;

    bool operator==(const FlowKey& other) const = default;
};

/// Hash functor for FlowKey, combining all five tuple fields.
struct FlowKeyHash {
    /** Compute a combined hash of all five tuple fields. */
    std::size_t operator()(const FlowKey& k) const noexcept {
        std::size_t h = std::hash<std::string>{}(k.srcIp);
        h ^= std::hash<std::string>{}(k.dstIp) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<std::uint16_t>{}(k.srcPort) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<std::uint16_t>{}(k.dstPort) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<std::uint8_t>{}(k.protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

} // namespace nids::infra
