#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace nids::core {

struct PacketInfo {
    std::string protocol;
    std::string application;
    std::string ipSource;
    std::string portSource;
    std::string ipDestination;
    std::string portDestination;
    std::vector<std::uint8_t> rawData;
};

} // namespace nids::core
