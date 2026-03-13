#include "core/services/ServiceRegistry.h"
#include <stdexcept>

namespace nids::core {

ServiceRegistry::ServiceRegistry() = default;

std::string ServiceRegistry::getServiceByPort(int port) const {
  if (auto it = portToService_.find(port); it != portToService_.end()) {
    return it->second;
  }
  return "Unknown";
}

std::set<std::string, std::less<>> ServiceRegistry::getUniqueServices() const {
  std::set<std::string, std::less<>> services;
  for (const auto &[port, name] : portToService_) {
    services.insert(name);
  }
  return services;
}

std::string
ServiceRegistry::resolveApplication(const std::string &filterSrcPort,
                                    const std::string &filterDstPort,
                                    const std::string &packetDstPort) const {
  try {
    if (!filterDstPort.empty()) {
      return getServiceByPort(std::stoi(filterDstPort));
    }
    if (!filterSrcPort.empty()) {
      return getServiceByPort(std::stoi(filterSrcPort));
    }
    if (!packetDstPort.empty()) {
      return getServiceByPort(std::stoi(packetDstPort));
    }
  } catch (const std::invalid_argument &) {
    // Port string is not a valid integer — fall through to return "Unknown"
  } catch (const std::out_of_range &) {
    // Port number exceeds int range — fall through to return "Unknown"
  }
  return "Unknown";
}

} // namespace nids::core
