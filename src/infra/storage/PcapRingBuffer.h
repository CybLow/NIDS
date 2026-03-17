#pragma once

/// Rolling PCAP ring-buffer for raw packet storage.
///
/// Writes captured packets to sequentially-named PCAP files with automatic
/// rotation, size-based eviction, and time-based retention policies.

#include "core/services/IPcapStore.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <vector>

namespace pcpp {
class PcapFileWriterDevice;
} // namespace pcpp

namespace nids::infra {

struct PcapStorageConfig {
    std::filesystem::path storageDir = "data/pcap";
    std::size_t maxTotalSizeBytes = 10ULL * 1024 * 1024 * 1024; ///< 10 GB
    int64_t maxRetentionHours = 168;                             ///< 7 days
    std::size_t maxFileSizeBytes = 100 * 1024 * 1024;            ///< 100 MB
    std::string filePrefix = "nids_capture";
};

class PcapRingBuffer final : public core::IPcapStore {
public:
    explicit PcapRingBuffer(PcapStorageConfig config);
    ~PcapRingBuffer() override;

    PcapRingBuffer(const PcapRingBuffer&) = delete;
    PcapRingBuffer& operator=(const PcapRingBuffer&) = delete;
    PcapRingBuffer(PcapRingBuffer&&) = delete;
    PcapRingBuffer& operator=(PcapRingBuffer&&) = delete;

    void store(std::span<const std::uint8_t> packet,
               int64_t timestampUs) override;

    [[nodiscard]] std::size_t sizeBytes() const noexcept override;

    void evict(std::size_t targetBytes) override;

    [[nodiscard]] std::vector<core::PcapFileInfo> listFiles() const override;

    void flush() override;

private:
    void openNewFile();
    void closeCurrentFile();
    void rotateIfNeeded();
    void evictExpired();
    void evictBySize();
    [[nodiscard]] std::filesystem::path generateFilePath() const;
    [[nodiscard]] std::size_t computeTotalSize() const;

    PcapStorageConfig config_;
    std::unique_ptr<pcpp::PcapFileWriterDevice> currentWriter_;
    std::filesystem::path currentFilePath_;
    std::size_t currentFileSize_ = 0;
    std::size_t totalSize_ = 0;
    int fileSequence_ = 0;
    mutable std::mutex mutex_;
};

} // namespace nids::infra
