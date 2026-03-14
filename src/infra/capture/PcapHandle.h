#pragma once

#ifdef _WIN32
#include <winsock2.h>
#endif
#include <memory>
#include <pcap.h>

namespace nids::infra {

/** Custom deleter for pcap_t handles. */
struct PcapDeleter {
  /** Close the pcap handle if non-null. */
  void operator()(pcap_t *p) const noexcept {
    if (p)
      pcap_close(p);
  }
};

/** Custom deleter for pcap_dumper_t handles. */
struct PcapDumperDeleter {
  /** Close the pcap dump file if non-null. */
  void operator()(pcap_dumper_t *d) const noexcept {
    if (d)
      pcap_dump_close(d);
  }
};

/** RAII handle for a pcap capture session. */
using PcapHandle = std::unique_ptr<pcap_t, PcapDeleter>;
/** RAII handle for a pcap dump file writer. */
using PcapDumperHandle = std::unique_ptr<pcap_dumper_t, PcapDumperDeleter>;

/** Wrap a raw pcap_t pointer in an RAII PcapHandle. */
inline PcapHandle makePcapHandle(pcap_t *raw) noexcept {
  return PcapHandle(raw);
}

/** Wrap a raw pcap_dumper_t pointer in an RAII PcapDumperHandle. */
inline PcapDumperHandle makePcapDumperHandle(pcap_dumper_t *raw) noexcept {
  return PcapDumperHandle(raw);
}

} // namespace nids::infra
