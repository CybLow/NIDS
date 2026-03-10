#pragma once

#include <string>
#include <unordered_map>
#include <set>

namespace nids::core {

class ServiceRegistry {
public:
    ServiceRegistry();

    [[nodiscard]] std::string getServiceByPort(int port) const;
    [[nodiscard]] std::set<std::string> getUniqueServices() const;

    [[nodiscard]] std::string resolveApplication(
        const std::string& filterSrcPort,
        const std::string& filterDstPort,
        const std::string& packetDstPort
    ) const;

private:
    std::unordered_map<int, std::string> portToService_;
};

} // namespace nids::core
