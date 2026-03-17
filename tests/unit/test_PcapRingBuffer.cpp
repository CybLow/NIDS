#include "infra/storage/PcapRingBuffer.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <vector>

using namespace nids;
namespace fs = std::filesystem;

namespace {

/// RAII helper to remove test pcap directory on scope exit.
struct DirGuard {
    fs::path path;
    ~DirGuard() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

} // namespace

TEST(PcapRingBuffer, constructor_createsStorageDirectory) {
    auto dir = fs::temp_directory_path() / "nids_test_pcap_ring";
    DirGuard guard{dir};
    std::error_code ec;
    fs::remove_all(dir, ec);

    infra::PcapStorageConfig cfg;
    cfg.storageDir = dir;
    cfg.maxFileSizeBytes = 1024;

    infra::PcapRingBuffer ring(std::move(cfg));
    EXPECT_TRUE(fs::exists(dir));
}

TEST(PcapRingBuffer, store_writesPacketData) {
    auto dir = fs::temp_directory_path() / "nids_test_pcap_store";
    DirGuard guard{dir};

    infra::PcapStorageConfig cfg;
    cfg.storageDir = dir;
    cfg.maxFileSizeBytes = 10 * 1024 * 1024; // 10 MB

    infra::PcapRingBuffer ring(std::move(cfg));

    // Store a simple packet.
    std::vector<std::uint8_t> packet(100, 0xAB);
    ring.store(packet, 1000000);

    EXPECT_GT(ring.sizeBytes(), 0u);
}

TEST(PcapRingBuffer, store_multiplePackets_increaseSize) {
    auto dir = fs::temp_directory_path() / "nids_test_pcap_multi";
    DirGuard guard{dir};

    infra::PcapStorageConfig cfg;
    cfg.storageDir = dir;
    cfg.maxFileSizeBytes = 10 * 1024 * 1024;

    infra::PcapRingBuffer ring(std::move(cfg));

    std::vector<std::uint8_t> packet(64, 0xCD);
    ring.store(packet, 1000000);
    const auto size1 = ring.sizeBytes();

    ring.store(packet, 2000000);
    const auto size2 = ring.sizeBytes();

    EXPECT_GT(size2, size1);
}

TEST(PcapRingBuffer, store_emptyPacket_isIgnored) {
    auto dir = fs::temp_directory_path() / "nids_test_pcap_empty";
    DirGuard guard{dir};

    infra::PcapStorageConfig cfg;
    cfg.storageDir = dir;
    cfg.maxFileSizeBytes = 10 * 1024 * 1024;

    infra::PcapRingBuffer ring(std::move(cfg));
    const auto sizeBefore = ring.sizeBytes();

    std::span<const std::uint8_t> empty;
    ring.store(empty, 1000000);

    // Size should not change for empty packet (only header accounted).
    EXPECT_EQ(ring.sizeBytes(), sizeBefore);
}

TEST(PcapRingBuffer, listFiles_returnsStoredFiles) {
    auto dir = fs::temp_directory_path() / "nids_test_pcap_list";
    DirGuard guard{dir};

    infra::PcapStorageConfig cfg;
    cfg.storageDir = dir;
    cfg.maxFileSizeBytes = 10 * 1024 * 1024;

    infra::PcapRingBuffer ring(std::move(cfg));

    std::vector<std::uint8_t> packet(64, 0xEF);
    ring.store(packet, 1000000);
    ring.flush();

    auto files = ring.listFiles();
    EXPECT_GE(files.size(), 1u);
    for (const auto& f : files) {
        EXPECT_FALSE(f.path.empty());
    }
}

TEST(PcapRingBuffer, rotation_createsNewFileWhenSizeExceeded) {
    auto dir = fs::temp_directory_path() / "nids_test_pcap_rotate";
    DirGuard guard{dir};

    infra::PcapStorageConfig cfg;
    cfg.storageDir = dir;
    cfg.maxFileSizeBytes = 200; // Very small for testing

    infra::PcapRingBuffer ring(std::move(cfg));

    std::vector<std::uint8_t> packet(100, 0xAA);
    // Write enough to trigger rotation.
    for (int i = 0; i < 10; ++i) {
        ring.store(packet, static_cast<int64_t>(i) * 1000000);
    }

    auto files = ring.listFiles();
    EXPECT_GT(files.size(), 1u);
}

TEST(PcapRingBuffer, evict_reducesTotalSize) {
    auto dir = fs::temp_directory_path() / "nids_test_pcap_evict";
    DirGuard guard{dir};

    infra::PcapStorageConfig cfg;
    cfg.storageDir = dir;
    cfg.maxFileSizeBytes = 200;
    cfg.maxTotalSizeBytes = 100000; // Don't auto-evict

    infra::PcapRingBuffer ring(std::move(cfg));

    std::vector<std::uint8_t> packet(100, 0xBB);
    for (int i = 0; i < 20; ++i) {
        ring.store(packet, static_cast<int64_t>(i) * 1000000);
    }

    auto sizeBefore = ring.sizeBytes();
    ring.evict(sizeBefore / 2); // Evict to half the size

    EXPECT_LT(ring.sizeBytes(), sizeBefore);
}

TEST(PcapRingBuffer, flush_doesNotCrash) {
    auto dir = fs::temp_directory_path() / "nids_test_pcap_flush";
    DirGuard guard{dir};

    infra::PcapStorageConfig cfg;
    cfg.storageDir = dir;

    infra::PcapRingBuffer ring(std::move(cfg));
    EXPECT_NO_THROW(ring.flush());
}

TEST(PcapRingBuffer, destructor_closesCleanly) {
    auto dir = fs::temp_directory_path() / "nids_test_pcap_dtor";
    DirGuard guard{dir};

    EXPECT_NO_THROW({
        infra::PcapStorageConfig cfg;
        cfg.storageDir = dir;
        infra::PcapRingBuffer ring(std::move(cfg));
        std::vector<std::uint8_t> packet(64, 0xCC);
        ring.store(packet, 1000000);
    });
}

TEST(PcapRingBuffer, sizeEviction_autoEvictsWhenMaxExceeded) {
    auto dir = fs::temp_directory_path() / "nids_test_pcap_autoevict";
    DirGuard guard{dir};

    infra::PcapStorageConfig cfg;
    cfg.storageDir = dir;
    cfg.maxFileSizeBytes = 200;
    cfg.maxTotalSizeBytes = 1000; // Very small

    infra::PcapRingBuffer ring(std::move(cfg));

    std::vector<std::uint8_t> packet(100, 0xDD);
    for (int i = 0; i < 50; ++i) {
        ring.store(packet, static_cast<int64_t>(i) * 1000000);
    }

    // Total size should be bounded near maxTotalSizeBytes.
    // May exceed slightly due to current file.
    EXPECT_LT(ring.sizeBytes(), cfg.maxTotalSizeBytes * 2);
}
