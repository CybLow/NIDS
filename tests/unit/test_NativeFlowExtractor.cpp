#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include "infra/flow/NativeFlowExtractor.h"

using nids::infra::FlowKey;
using nids::infra::FlowStats;
using nids::infra::NativeFlowExtractor;

namespace fs = std::filesystem;

TEST(FlowKey, Ordering) {
    FlowKey a{"10.0.0.1", "192.168.1.1", 12345, 443, 6};
    FlowKey b{"10.0.0.1", "192.168.1.1", 12345, 443, 6};
    FlowKey c{"10.0.0.2", "192.168.1.1", 12345, 443, 6};
    FlowKey d{"10.0.0.1", "192.168.1.2", 12345, 443, 6};

    EXPECT_FALSE(a < b);
    EXPECT_FALSE(b < a);
    EXPECT_TRUE(a < c);
    EXPECT_FALSE(c < a);
    EXPECT_TRUE(a < d);
}

TEST(FlowStats, ToFeatureVectorSizeAndOrder) {
    FlowStats stats;
    stats.startTimeUs = 0;
    stats.lastTimeUs = 1'000'000;
    stats.totalFwdPackets = 5;
    stats.totalBwdPackets = 3;
    stats.totalFwdBytes = 500;
    stats.totalBwdBytes = 300;

    auto features = stats.toFeatureVector(443);
    EXPECT_EQ(features.size(), 79u);
    EXPECT_FLOAT_EQ(features[0], 443.0f);   // Destination Port
    EXPECT_FLOAT_EQ(features[1], 1000000.0f);  // Flow Duration
    EXPECT_FLOAT_EQ(features[2], 5.0f);     // Total Fwd Packets
    EXPECT_FLOAT_EQ(features[3], 3.0f);     // Total Bwd Packets
    EXPECT_FLOAT_EQ(features[4], 500.0f);   // Total Fwd Bytes
    EXPECT_FLOAT_EQ(features[5], 300.0f);   // Total Bwd Bytes
}

TEST(NativeFlowExtractor, ExtractFlowsWithMinimalPcap) {
    // Create minimal pcap: global header (24 bytes) + one packet
    // PCAP global header (libpcap format): magic 0xa1b2c3d4, version 2.4, linktype 1 (Ethernet)
    std::uint8_t pcapGlobalHeader[] = {
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    };
    // Packet header: ts_sec=0, ts_usec=0, caplen=54, len=54
    std::uint8_t pcapPktHeader[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x36, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00,
    };
    // Ethernet(14) + IPv4(20) + TCP(20) = 54 bytes
    std::uint8_t packet[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02,
        0x1f, 0x90, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    };
    std::string pcapPath = (fs::temp_directory_path() / "nids_test_minimal.pcap").string();
    std::ofstream ofs(pcapPath, std::ios::binary);
    ofs.write(reinterpret_cast<const char*>(pcapGlobalHeader), sizeof(pcapGlobalHeader));
    ofs.write(reinterpret_cast<const char*>(pcapPktHeader), sizeof(pcapPktHeader));
    ofs.write(reinterpret_cast<const char*>(packet), sizeof(packet));
    ofs.close();

    NativeFlowExtractor extractor;
    std::string csvPath = (fs::temp_directory_path() / "nids_test_output.csv").string();
    bool ok = extractor.extractFlows(pcapPath, csvPath);

    fs::remove(pcapPath);

    EXPECT_TRUE(ok);
    if (ok) {
        auto features = extractor.loadFeatures(csvPath);
        fs::remove(csvPath);
        EXPECT_EQ(features.size(), 1u);
        if (!features.empty()) {
            EXPECT_EQ(features[0].size(), 79u);
            EXPECT_FLOAT_EQ(features[0][0], 443.0f);  // Destination port
        }
    } else {
        fs::remove(csvPath);
    }
}

TEST(NativeFlowExtractor, LoadFeatures) {
    NativeFlowExtractor extractor;
    auto features = extractor.loadFeatures("/nonexistent_file_xyz");
    EXPECT_TRUE(features.empty());
}

TEST(NativeFlowExtractor, SetFlowTimeout) {
    NativeFlowExtractor extractor;
    extractor.setFlowTimeout(300'000'000);  // 300 seconds
}
