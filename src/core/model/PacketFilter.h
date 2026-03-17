#pragma once

#include <string>

namespace nids::core {

/** User-specified capture filter criteria, convertible to a BPF expression. */
struct PacketFilter {
    /** Network interface name to capture on. */
    std::string networkCard;
    /** Protocol filter (e.g., "tcp", "udp", "icmp"); empty for all. */
    std::string protocol;
    /** Application-layer service filter (e.g., "HTTP"); empty for all.
     *  UI-only: not used in BPF generation (BPF cannot filter by app layer).
     *  Retained for UI state management (FilterPanel combo box selection). */
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

/**
 * Fluent builder for constructing PacketFilter instances step by step.
 *
 * Usage:
 *   auto filter = FilterBuilder()
 *       .protocol("TCP")
 *       .sourceIp("192.168.1.0/24")
 *       .destinationPort("443")
 *       .build();
 */
class FilterBuilder {
public:
    /** Set the network interface to capture on. */
    FilterBuilder& networkCard(std::string value) {
        filter_.networkCard = std::move(value);
        return *this;
    }

    /** Set the protocol filter (e.g., "tcp", "udp", "icmp"). */
    FilterBuilder& protocol(std::string value) {
        filter_.protocol = std::move(value);
        return *this;
    }

    /** Set the application-layer service filter (e.g., "HTTP"). */
    FilterBuilder& application(std::string value) {
        filter_.application = std::move(value);
        return *this;
    }

    /** Set the source IP address filter. */
    FilterBuilder& sourceIp(std::string value) {
        filter_.sourceIP = std::move(value);
        return *this;
    }

    /** Set the destination IP address filter. */
    FilterBuilder& destinationIp(std::string value) {
        filter_.destinationIP = std::move(value);
        return *this;
    }

    /** Set the source port filter. */
    FilterBuilder& sourcePort(std::string value) {
        filter_.sourcePort = std::move(value);
        return *this;
    }

    /** Set the destination port filter. */
    FilterBuilder& destinationPort(std::string value) {
        filter_.destinationPort = std::move(value);
        return *this;
    }

    /** Set a raw BPF filter expression (overrides other fields). */
    FilterBuilder& customBpf(std::string value) {
        filter_.customBPFFilter = std::move(value);
        return *this;
    }

    /** Build and return the configured PacketFilter. */
    [[nodiscard]] PacketFilter build() const& { return filter_; }

    /** Build and return the configured PacketFilter (move variant). */
    [[nodiscard]] PacketFilter build() && { return std::move(filter_); }

private:
    PacketFilter filter_;
};

} // namespace nids::core
