#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <set>

namespace nids::core {

/** Maps well-known TCP/UDP port numbers to service names. */
class ServiceRegistry {
public:
    /** Construct the registry and populate the default port→service mapping. */
    ServiceRegistry();

    /**
     * Look up the service name for a given port number.
     * @param port TCP/UDP port number.
     * @return Service name, or "Unknown" if the port is not registered.
     */
    [[nodiscard]] std::string getServiceByPort(int port) const;
    /** Return the set of all distinct service names in the registry. */
    [[nodiscard]] std::set<std::string, std::less<>> getUniqueServices() const;

    /**
     * Resolve the application-layer service for a packet given filter context.
     *
     * Priority: filterDstPort > filterSrcPort > packetDstPort.
     * A port value of 0 is treated as "unset" and skipped.
     *
     * @param filterSrcPort Source port from the active filter (0 = unset).
     * @param filterDstPort Destination port from the active filter (0 = unset).
     * @param packetDstPort Actual destination port of the packet.
     * @return Resolved service name, or "Unknown" if no port maps to a service.
     */
    [[nodiscard]] std::string resolveApplication(
        std::uint16_t filterSrcPort,
        std::uint16_t filterDstPort,
        std::uint16_t packetDstPort
    ) const;

private:
    std::unordered_map<int, std::string> portToService_;
};

} // namespace nids::core
