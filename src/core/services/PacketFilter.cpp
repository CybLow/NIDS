#include "core/services/PacketFilter.h"

namespace nids::core {

std::string PacketFilter::generateBpfString() const {
    if (!customBPFFilter.empty()) {
        return customBPFFilter;
    }

    std::string filter;

    auto appendClause = [&filter](const std::string& clause) {
        if (!filter.empty()) filter += " and ";
        filter += clause;
    };

    if (!protocol.empty() && protocol != "ALL" && protocol != "Unknown") {
        appendClause("proto " + protocol);
    }
    if (!sourceIP.empty()) {
        appendClause("src host " + sourceIP);
    }
    if (!destinationIP.empty()) {
        appendClause("dst host " + destinationIP);
    }
    if (!sourcePort.empty()) {
        appendClause("src port " + sourcePort);
    }
    if (!destinationPort.empty()) {
        appendClause("dst port " + destinationPort);
    }

    return filter;
}

} // namespace nids::core
