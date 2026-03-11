#pragma once

#include <string>

namespace nids::core {

/** User-specified capture filter criteria, convertible to a BPF expression. */
struct PacketFilter {
    /** Network interface name to capture on. */
    std::string networkCard;
    /** Protocol filter (e.g., "tcp", "udp", "icmp"); empty for all. */
    std::string protocol;
    /** Application-layer service filter (e.g., "HTTP"); empty for all. */
    std::string application;
    /** Source IP address filter; empty for all. */
    std::string sourceIP;
    /** Destination IP address filter; empty for all. */
    std::string destinationIP;
    /** Source port filter; empty for all. */
    std::string sourcePort;
    /** Destination port filter; empty for all. */
    std::string destinationPort;
    /** Raw BPF filter expression; overrides other fields if non-empty. */
    std::string customBPFFilter;

    /**
     * Generate a BPF filter string from the configured criteria.
     * @return Compiled BPF expression suitable for pcap_compile().
     */
    [[nodiscard]] std::string generateBpfString() const;
};

} // namespace nids::core
