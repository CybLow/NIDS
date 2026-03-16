#pragma once

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
     * @param filterSrcPort Source port from the active filter (may be empty).
     * @param filterDstPort Destination port from the active filter (may be empty).
     * @param packetDstPort Actual destination port of the packet.
     * @return Resolved service name.
     */
    [[nodiscard]] std::string resolveApplication(
        const std::string& filterSrcPort,
        const std::string& filterDstPort,
        const std::string& packetDstPort
    ) const;

private:
    std::unordered_map<int, std::string> portToService_;
};

} // namespace nids::core
