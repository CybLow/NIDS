#pragma once

#include "core/model/PacketInfo.h"

#include <functional>
#include <string>
#include <vector>

namespace nids::core {

/** Abstract interface for packet capture backends (pcap, npcap). */
class IPacketCapture {
public:
    virtual ~IPacketCapture() = default;

    /** Callback invoked for each captured packet. */
    using PacketCallback = std::function<void(const PacketInfo&)>;
    /** Callback invoked when a capture error occurs. */
    using ErrorCallback = std::function<void(const std::string&)>;

    /**
     * Open a capture handle on the given network interface.
     * @param interface Network interface name (e.g., "eth0").
     * @param bpfFilter BPF filter expression (empty string for no filter).
     * @return True on success, false on failure.
     */
    [[nodiscard]] virtual bool initialize(const std::string& interface,
                                          const std::string& bpfFilter) = 0;
    /**
     * Begin capturing packets, optionally writing raw frames to a pcap dump file.
     * @param dumpFile Path for the pcap dump file (empty to disable dumping).
     */
    virtual void startCapture(const std::string& dumpFile) = 0;
    /** Stop an active capture session. */
    virtual void stopCapture() = 0;
    /** Check whether a capture is currently in progress. */
    [[nodiscard]] virtual bool isCapturing() const = 0;

    /** Register the callback invoked for each captured packet. */
    virtual void setPacketCallback(PacketCallback callback) = 0;
    /** Register the callback invoked on capture errors. */
    virtual void setErrorCallback(ErrorCallback callback) = 0;

    /** Enumerate available network interfaces. */
    [[nodiscard]] virtual std::vector<std::string> listInterfaces() = 0;
};

} // namespace nids::core
