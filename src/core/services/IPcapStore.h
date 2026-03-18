#pragma once

/// IPcapStore — interface for rolling PCAP packet storage.
///
/// Abstracts the storage backend so that PcapRingBuffer (infra/) can be
/// swapped or mocked in tests. Called from the capture thread to persist
/// raw packets for later threat-hunting analysis.

#include "core/model/HuntResult.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace nids::core {

class IPcapStore {
public:
    virtual ~IPcapStore() = default;

    /// Store a raw packet (called from the capture thread — must be fast).
    virtual void store(std::span<const std::uint8_t> packet,
                       int64_t timestampUs) = 0;

    /// Current total storage usage in bytes.
    [[nodiscard]] virtual std::size_t sizeBytes() const noexcept = 0;

    /// Evict oldest files until total storage is under targetBytes.
    virtual void evict(std::size_t targetBytes) = 0;

    /// List all stored PCAP files with metadata.
    [[nodiscard]] virtual std::vector<PcapFileInfo> listFiles() const = 0;

    /// Flush any buffered data to disk.
    virtual void flush() = 0;
};

} // namespace nids::core
