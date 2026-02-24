#pragma once

#include <pcap.h>
#include <memory>

namespace nids::infra {

struct PcapDeleter {
    void operator()(pcap_t* p) const noexcept {
        if (p) pcap_close(p);
    }
};

struct PcapDumperDeleter {
    void operator()(pcap_dumper_t* d) const noexcept {
        if (d) pcap_dump_close(d);
    }
};

using PcapHandle = std::unique_ptr<pcap_t, PcapDeleter>;
using PcapDumperHandle = std::unique_ptr<pcap_dumper_t, PcapDumperDeleter>;

inline PcapHandle makePcapHandle(pcap_t* raw) noexcept {
    return PcapHandle(raw);
}

inline PcapDumperHandle makePcapDumperHandle(pcap_dumper_t* raw) noexcept {
    return PcapDumperHandle(raw);
}

} // namespace nids::infra
