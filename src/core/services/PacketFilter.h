#pragma once

#include <string>

namespace nids::core {

struct PacketFilter {
    std::string networkCard;
    std::string protocol;
    std::string application;
    std::string sourceIP;
    std::string destinationIP;
    std::string sourcePort;
    std::string destinationPort;
    std::string customBPFFilter;

    [[nodiscard]] std::string generateBpfString() const;
};

} // namespace nids::core
