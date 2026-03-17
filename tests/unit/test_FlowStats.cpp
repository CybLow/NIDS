#include "infra/flow/NativeFlowExtractor.h"
#include "core/model/FlowConstants.h"

#include <gtest/gtest.h>

using nids::infra::FlowStats;
using nids::core::kFlowFeatureCount;

// ── FlowStats tests ─────────────────────────────────────────────────

TEST(FlowStats, ToFeatureVectorSizeAndOrder) {
  FlowStats stats;
  stats.startTimeUs = 0;
  stats.lastTimeUs = 1'000'000;
  stats.totalFwdPackets = 5;
  stats.totalBwdPackets = 3;
  stats.totalFwdBytes = 500;
  stats.totalBwdBytes = 300;

  auto features = stats.toFeatureVector(443);
  EXPECT_EQ(features.size(), static_cast<std::size_t>(kFlowFeatureCount));
  EXPECT_FLOAT_EQ(features[0], 443.0f);     // Destination Port
  EXPECT_FLOAT_EQ(features[1], 1000000.0f); // Flow Duration
  EXPECT_FLOAT_EQ(features[2], 5.0f);       // Total Fwd Packets
  EXPECT_FLOAT_EQ(features[3], 3.0f);       // Total Bwd Packets
  EXPECT_FLOAT_EQ(features[4], 500.0f);     // Total Fwd Bytes
  EXPECT_FLOAT_EQ(features[5], 300.0f);     // Total Bwd Bytes
}

TEST(FlowStats, ToFeatureVector_zeroDuration) {
  FlowStats stats;
  stats.startTimeUs = 100;
  stats.lastTimeUs = 100; // Same -> zero duration
  stats.totalFwdPackets = 1;
  stats.totalFwdBytes = 100;

  auto features = stats.toFeatureVector(80);
  EXPECT_EQ(features.size(), static_cast<std::size_t>(kFlowFeatureCount));
  EXPECT_FLOAT_EQ(features[0], 80.0f);
  EXPECT_FLOAT_EQ(features[1], 0.0f);  // Duration = 0
  EXPECT_FLOAT_EQ(features[14], 0.0f); // Flow Bytes/s = 0 (div by zero guarded)
  EXPECT_FLOAT_EQ(features[15], 0.0f); // Flow Packets/s = 0
}

TEST(FlowStats, ToFeatureVector_negativeDurationClampedToZero) {
  FlowStats stats;
  stats.startTimeUs = 1000;
  stats.lastTimeUs = 500; // lastTime < startTime -> negative clamped to 0
  stats.totalFwdPackets = 1;

  auto features = stats.toFeatureVector(80);
  EXPECT_FLOAT_EQ(features[1], 0.0f);
}

TEST(FlowStats, ToFeatureVector_tcpFlagCountsAndInitWindow) {
  FlowStats stats;
  stats.startTimeUs = 0;
  stats.lastTimeUs = 1'000'000;
  stats.totalFwdPackets = 2;
  stats.totalBwdPackets = 1;
  stats.totalFwdBytes = 200;
  stats.totalBwdBytes = 100;
  stats.finCount = 1;
  stats.synCount = 2;
  stats.rstCount = 3;
  stats.pshCount = 4;
  stats.ackCount = 5;
  stats.urgCount = 6;
  stats.cwrCount = 7;
  stats.eceCount = 8;
  stats.fwdPshFlags = 1;
  stats.bwdPshFlags = 2;
  stats.fwdUrgFlags = 3;
  stats.bwdUrgFlags = 4;
  stats.fwdHeaderBytes = 40;
  stats.bwdHeaderBytes = 20;
  stats.fwdInitWinBytes = 65535;
  stats.bwdInitWinBytes = 32768;
  stats.actDataPktFwd = 1;
  stats.minSegSizeForward = 50;

  auto f = stats.toFeatureVector(443);
  EXPECT_FLOAT_EQ(f[30], 1.0f); // Fwd PSH Flags
  EXPECT_FLOAT_EQ(f[31], 2.0f); // Bwd PSH Flags
  EXPECT_FLOAT_EQ(f[32], 3.0f); // Fwd URG Flags
  EXPECT_FLOAT_EQ(f[33], 4.0f); // Bwd URG Flags
  // Header lengths: features 34-35
  EXPECT_FLOAT_EQ(f[34], 40.0f);
  EXPECT_FLOAT_EQ(f[35], 20.0f);
  // TCP flag counts: features 43-50
  EXPECT_FLOAT_EQ(f[43], 1.0f); // FIN
  EXPECT_FLOAT_EQ(f[44], 2.0f); // SYN
  EXPECT_FLOAT_EQ(f[45], 3.0f); // RST
  EXPECT_FLOAT_EQ(f[46], 4.0f); // PSH
  EXPECT_FLOAT_EQ(f[47], 5.0f); // ACK
  EXPECT_FLOAT_EQ(f[48], 6.0f); // URG
  EXPECT_FLOAT_EQ(f[49], 7.0f); // CWR
  EXPECT_FLOAT_EQ(f[50], 8.0f); // ECE
  // Down/Up ratio: features[51] = bwd/fwd = 1/2 = 0.5
  EXPECT_FLOAT_EQ(f[51], 0.5f);
  // Init window: features 65-66
  EXPECT_FLOAT_EQ(f[65], 65535.0f);
  EXPECT_FLOAT_EQ(f[66], 32768.0f);
  // act_data_pkt_fwd, min_seg_size_forward: features 67-68
  EXPECT_FLOAT_EQ(f[67], 1.0f);
  EXPECT_FLOAT_EQ(f[68], 50.0f);
}

TEST(FlowStats, ToFeatureVector_withIatAndPacketLengths) {
  FlowStats stats;
  stats.startTimeUs = 0;
  stats.lastTimeUs = 2'000'000;
  stats.totalFwdPackets = 3;
  stats.totalBwdPackets = 0;
  stats.totalFwdBytes = 300;
  stats.totalBwdBytes = 0;
  for (int i = 0; i < 3; ++i) {
    stats.fwdLengthAcc.update(100);
    stats.allLengthAcc.update(100);
  }
  stats.flowIatAcc.update(500'000);
  stats.flowIatAcc.update(500'000);
  stats.fwdIatAcc.update(500'000);
  stats.fwdIatAcc.update(500'000);

  auto f = stats.toFeatureVector(80);
  // Fwd Packet Length Max/Min/Mean/Std: features 6-9
  EXPECT_FLOAT_EQ(f[6], 100.0f); // Max
  EXPECT_FLOAT_EQ(f[7], 100.0f); // Min
  EXPECT_FLOAT_EQ(f[8], 100.0f); // Mean
  EXPECT_FLOAT_EQ(f[9], 0.0f);   // Std (all same)
  // Bwd Packet Length stats (empty): features 10-13 = 0
  EXPECT_FLOAT_EQ(f[10], 0.0f);
  EXPECT_FLOAT_EQ(f[11], 0.0f);
  EXPECT_FLOAT_EQ(f[12], 0.0f);
  EXPECT_FLOAT_EQ(f[13], 0.0f);
}

TEST(FlowStats, ToFeatureVector_bulkMetrics) {
  FlowStats stats;
  stats.startTimeUs = 0;
  stats.lastTimeUs = 2'000'000;
  stats.totalFwdPackets = 5;
  stats.totalBwdPackets = 3;
  stats.totalFwdBytes = 500;
  stats.totalBwdBytes = 300;
  stats.fwdBulkBytesAcc.update(200);
  stats.fwdBulkBytesAcc.update(300);
  stats.fwdBulkPktsAcc.update(2);
  stats.fwdBulkPktsAcc.update(3);
  stats.bwdBulkBytesAcc.update(150);
  stats.bwdBulkPktsAcc.update(2);

  auto f = stats.toFeatureVector(80);
  EXPECT_FLOAT_EQ(f[55], 250.0f);
  EXPECT_FLOAT_EQ(f[56], 2.5f);
  EXPECT_FLOAT_EQ(f[57], 250.0f);
  EXPECT_FLOAT_EQ(f[58], 150.0f);
}

TEST(FlowStats, ToFeatureVector_activeIdlePeriods) {
  FlowStats stats;
  stats.startTimeUs = 0;
  stats.lastTimeUs = 10'000'000;
  stats.totalFwdPackets = 1;
  stats.totalFwdBytes = 100;
  stats.activeAcc.update(1'000'000);
  stats.activeAcc.update(2'000'000);
  stats.idleAcc.update(5'000'000);
  stats.idleAcc.update(6'000'000);

  auto f = stats.toFeatureVector(80);
  // Active Mean: features[69]
  EXPECT_FLOAT_EQ(f[69], 1'500'000.0f); // mean(1M, 2M) = 1.5M
  // Idle Mean: features[73]
  EXPECT_FLOAT_EQ(f[73], 5'500'000.0f); // mean(5M, 6M) = 5.5M
}

TEST(FlowStats, ToFeatureVector_singleFwdPacket_stddevZero) {
  FlowStats stats;
  stats.startTimeUs = 0;
  stats.lastTimeUs = 0;
  stats.totalFwdPackets = 1;
  stats.totalBwdPackets = 0;
  stats.totalFwdBytes = 100;
  stats.totalBwdBytes = 0;
  stats.fwdLengthAcc.update(100);
  stats.allLengthAcc.update(100);

  auto f = stats.toFeatureVector(80);
  // Fwd Packet Length Std (feature 9) should be 0 for single element
  EXPECT_FLOAT_EQ(f[9], 0.0f);
  // Fwd Packet Length Mean (feature 8) = 100
  EXPECT_FLOAT_EQ(f[8], 100.0f);
}

TEST(FlowStats, ToFeatureVector_bulkWithZeroDuration) {
  FlowStats stats;
  stats.startTimeUs = 100;
  stats.lastTimeUs = 100; // Zero duration
  stats.totalFwdPackets = 5;
  stats.totalBwdPackets = 0;
  stats.totalFwdBytes = 500;
  stats.fwdBulkBytesAcc.update(200);
  stats.fwdBulkPktsAcc.update(3);

  auto f = stats.toFeatureVector(80);
  // Fwd Avg Bulk Rate (feature 57) should be 0 (not NaN/Inf) when duration = 0
  EXPECT_FLOAT_EQ(f[57], 0.0f);
  // Fwd Avg Bytes/Bulk (feature 55) should still be valid
  EXPECT_FLOAT_EQ(f[55], 200.0f);
}

// ── flowFeatureNames() ──────────────────────────────────────────────

TEST(FlowFeatureNames, sizeMatchesKFlowFeatureCount) {
  const auto& names = nids::infra::flowFeatureNames();
  EXPECT_EQ(names.size(), static_cast<std::size_t>(kFlowFeatureCount));
}

TEST(FlowFeatureNames, firstAndLastNames) {
  const auto& names = nids::infra::flowFeatureNames();
  EXPECT_EQ(names.front(), "Destination Port");
  EXPECT_EQ(names.back(), "Idle Min");
}
