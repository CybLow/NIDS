#include "infra/storage/PcapRingBuffer.h"

#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/RawPacket.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <iterator>
#include <numeric>
#include <ranges>

namespace nids::infra {

namespace fs = std::filesystem;

PcapRingBuffer::PcapRingBuffer(PcapStorageConfig config)
    : config_(std::move(config)) {
    // Ensure storage directory exists.
    std::error_code ec;
    fs::create_directories(config_.storageDir, ec);
    if (ec) {
        spdlog::error("PcapRingBuffer: cannot create storage dir '{}': {}",
                      config_.storageDir.string(), ec.message());
    }

    // Scan existing files for initial total size and sequence number.
    totalSize_ = computeTotalSize();
    fileSequence_ = static_cast<int>(std::ranges::count_if(
        fs::directory_iterator(config_.storageDir, ec),
        [](const auto& entry) {
            return entry.is_regular_file() &&
                   entry.path().extension() == ".pcap";
        }));

    openNewFile();
    spdlog::info("PcapRingBuffer: started in '{}' (existing: {} bytes, "
                 "max: {} bytes)",
                 config_.storageDir.string(), totalSize_,
                 config_.maxTotalSizeBytes);
}

PcapRingBuffer::~PcapRingBuffer() {
    try {
        closeCurrentFile();
    } catch (...) {
        // Destructors must not throw.
    }
}

// ── store() ─────────────────────────────────────────────────────────

void PcapRingBuffer::store(std::span<const std::uint8_t> packet,
                           int64_t timestampUs) {
    if (packet.empty()) return;

    std::scoped_lock lock{mutex_};

    if (!currentWriter_) {
        openNewFile();
        if (!currentWriter_) return; // Failed to open
    }

    timeval tv{};
    tv.tv_sec = static_cast<decltype(tv.tv_sec)>(timestampUs / 1'000'000);
    tv.tv_usec = static_cast<decltype(tv.tv_usec)>(timestampUs % 1'000'000);

    pcpp::RawPacket rawPacket(
        packet.data(),
        static_cast<int>(packet.size()),
        tv,
        false); // false = don't take ownership of data

    if (currentWriter_->writePacket(rawPacket)) {
        currentFileSize_ += packet.size() + 16; // 16-byte pcap record header
        totalSize_ += packet.size() + 16;
    }

    rotateIfNeeded();
}

// ── File management ─────────────────────────────────────────────────

void PcapRingBuffer::openNewFile() {
    closeCurrentFile();

    currentFilePath_ = generateFilePath();
    currentWriter_ = std::make_unique<pcpp::PcapFileWriterDevice>(
        currentFilePath_.string());

    if (!currentWriter_->open()) {
        spdlog::error("PcapRingBuffer: cannot open '{}'",
                      currentFilePath_.string());
        currentWriter_.reset();
        return;
    }

    currentFileSize_ = 24; // PCAP global header size
    totalSize_ += 24;
    ++fileSequence_;
}

void PcapRingBuffer::closeCurrentFile() {
    if (currentWriter_) {
        currentWriter_->close();
        currentWriter_.reset();
    }
}

void PcapRingBuffer::rotateIfNeeded() {
    if (currentFileSize_ < config_.maxFileSizeBytes) return;

    openNewFile();

    // Evict after rotation.
    evictExpired();
    evictBySize();
}

void PcapRingBuffer::evictExpired() {
    if (config_.maxRetentionHours <= 0) return;

    const auto now = fs::file_time_type::clock::now();
    const auto maxAge = std::chrono::hours(config_.maxRetentionHours);

    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(config_.storageDir, ec)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".pcap")
            continue;
        if (entry.path() == currentFilePath_) continue;

        const auto lastWrite = entry.last_write_time(ec);
        if (ec) continue;

        if ((now - lastWrite) > maxAge) {
            const auto size = entry.file_size(ec);
            if (fs::remove(entry.path(), ec)) {
                totalSize_ = (totalSize_ > size) ? totalSize_ - size : 0;
                spdlog::debug("PcapRingBuffer: evicted expired '{}'",
                              entry.path().filename().string());
            }
        }
    }
}

void PcapRingBuffer::evictBySize() {
    if (totalSize_ <= config_.maxTotalSizeBytes) return;
    evict(config_.maxTotalSizeBytes);
}

// ── Public API ──────────────────────────────────────────────────────

void PcapRingBuffer::evict(std::size_t targetBytes) {
    std::error_code ec;

    // Collect evictable files (oldest first, since names are timestamped).
    std::vector<fs::directory_entry> files;
    auto dirIter = fs::directory_iterator(config_.storageDir, ec);
    std::ranges::copy_if(dirIter, std::back_inserter(files),
        [this](const auto& entry) {
            return entry.is_regular_file() &&
                   entry.path().extension() == ".pcap" &&
                   entry.path() != currentFilePath_;
        });
    std::ranges::sort(files, {}, [](const auto& e) {
        return e.path().filename().string();
    });

    for (const auto& entry : files) {
        if (totalSize_ <= targetBytes) break;
        const auto size = entry.file_size(ec);
        if (ec) continue;
        if (fs::remove(entry.path(), ec)) {
            totalSize_ = (totalSize_ > size) ? totalSize_ - size : 0;
            spdlog::debug("PcapRingBuffer: evicted '{}' ({} bytes)",
                          entry.path().filename().string(), size);
        }
    }
}

std::vector<core::PcapFileInfo> PcapRingBuffer::listFiles() const {
    std::scoped_lock lock{mutex_};
    std::vector<core::PcapFileInfo> result;

    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(config_.storageDir, ec)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".pcap")
            continue;
        core::PcapFileInfo info;
        info.path = entry.path().string();
        info.sizeBytes = entry.file_size(ec);
        result.push_back(std::move(info));
    }

    std::ranges::sort(result, {}, &core::PcapFileInfo::path);
    return result;
}

void PcapRingBuffer::flush() {
    std::scoped_lock lock{mutex_};
    if (currentWriter_) {
        currentWriter_->flush();
    }
}

std::size_t PcapRingBuffer::sizeBytes() const noexcept {
    return totalSize_;
}

std::size_t PcapRingBuffer::computeTotalSize() const {
    std::error_code ec;
    auto dirIter = fs::directory_iterator(config_.storageDir, ec);
    return std::accumulate(
        fs::begin(dirIter), fs::end(dirIter), std::size_t{0},
        [&ec](std::size_t acc, const auto& entry) {
            if (entry.is_regular_file() &&
                entry.path().extension() == ".pcap") {
                return acc + entry.file_size(ec);
            }
            return acc;
        });
}

fs::path PcapRingBuffer::generateFilePath() const {
    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto time = system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &time);
#else
    gmtime_r(&time, &tm);
#endif

    char buf[64]{};
    std::snprintf(buf, sizeof(buf), "%s_%04d%02d%02d_%02d%02d%02d_%03d.pcap",
                  config_.filePrefix.c_str(),
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec,
                  fileSequence_ % 1000);

    return config_.storageDir / buf;
}

} // namespace nids::infra
