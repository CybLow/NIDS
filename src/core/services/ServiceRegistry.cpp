#include "core/services/ServiceRegistry.h"

#include <charconv>
#include <optional>

namespace nids::core {

namespace {

/// Try to parse a port string to int using std::from_chars (no exceptions).
/// Returns std::nullopt on empty string or parse failure.
[[nodiscard]] std::optional<int> tryParsePort(const std::string &s) noexcept {
  if (s.empty())
    return std::nullopt;
  int port = 0;
  auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), port);
  if (ec != std::errc{} || ptr != s.data() + s.size())
    return std::nullopt;
  return port;
}

} // anonymous namespace

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
  if (auto port = tryParsePort(filterDstPort)) {
    return getServiceByPort(*port);
  }
  if (auto port = tryParsePort(filterSrcPort)) {
    return getServiceByPort(*port);
  }
  if (auto port = tryParsePort(packetDstPort)) {
    return getServiceByPort(*port);
  }
  return "Unknown";
}

} // namespace nids::core
