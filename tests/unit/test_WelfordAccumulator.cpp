#include "core/math/WelfordAccumulator.h"

#include <cmath>
#include <gtest/gtest.h>

using nids::core::WelfordAccumulator;

// ── WelfordAccumulator tests ────────────────────────────────────────

TEST(WelfordAccumulator, EmptyAccumulator) {
  WelfordAccumulator acc;
  EXPECT_EQ(acc.count(), 0u);
  EXPECT_DOUBLE_EQ(acc.mean(), 0.0);
  EXPECT_DOUBLE_EQ(acc.sum(), 0.0);
  EXPECT_DOUBLE_EQ(acc.min(), 0.0);
  EXPECT_DOUBLE_EQ(acc.max(), 0.0);
  EXPECT_DOUBLE_EQ(acc.stddev(), 0.0);
  EXPECT_DOUBLE_EQ(acc.populationVariance(), 0.0);
  EXPECT_DOUBLE_EQ(acc.sampleVariance(), 0.0);
}

TEST(WelfordAccumulator, SingleValue) {
  WelfordAccumulator acc;
  acc.update(42.0);
  EXPECT_EQ(acc.count(), 1u);
  EXPECT_DOUBLE_EQ(acc.mean(), 42.0);
  EXPECT_DOUBLE_EQ(acc.sum(), 42.0);
  EXPECT_DOUBLE_EQ(acc.min(), 42.0);
  EXPECT_DOUBLE_EQ(acc.max(), 42.0);
  EXPECT_DOUBLE_EQ(acc.stddev(), 0.0);       // N=1 -> sampleVariance=0
  EXPECT_DOUBLE_EQ(acc.populationVariance(), 0.0);
}

TEST(WelfordAccumulator, MultipleValues_meanAndStddev) {
  WelfordAccumulator acc;
  // Values: 2, 4, 4, 4, 5, 5, 7, 9 -> mean=5, population variance=4, sample
  // variance=4.571
  for (double v : {2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0})
    acc.update(v);

  EXPECT_EQ(acc.count(), 8u);
  EXPECT_DOUBLE_EQ(acc.mean(), 5.0);
  EXPECT_DOUBLE_EQ(acc.sum(), 40.0);
  EXPECT_DOUBLE_EQ(acc.min(), 2.0);
  EXPECT_DOUBLE_EQ(acc.max(), 9.0);
  EXPECT_NEAR(acc.populationVariance(), 4.0, 1e-10);
  EXPECT_NEAR(acc.sampleVariance(), 32.0 / 7.0, 1e-10);
  EXPECT_NEAR(acc.stddev(), std::sqrt(32.0 / 7.0), 1e-10);
}

TEST(WelfordAccumulator, IdenticalValues_zeroVariance) {
  WelfordAccumulator acc;
  acc.update(100);
  acc.update(100);
  acc.update(100);
  EXPECT_DOUBLE_EQ(acc.mean(), 100.0);
  EXPECT_DOUBLE_EQ(acc.stddev(), 0.0);
  EXPECT_DOUBLE_EQ(acc.populationVariance(), 0.0);
}

TEST(WelfordAccumulator, TwoValues_sampleVariance) {
  WelfordAccumulator acc;
  acc.update(10);
  acc.update(20);
  EXPECT_DOUBLE_EQ(acc.mean(), 15.0);
  EXPECT_DOUBLE_EQ(acc.sum(), 30.0);
  EXPECT_DOUBLE_EQ(acc.min(), 10.0);
  EXPECT_DOUBLE_EQ(acc.max(), 20.0);
  // Population variance = ((10-15)^2 + (20-15)^2) / 2 = 25
  EXPECT_DOUBLE_EQ(acc.populationVariance(), 25.0);
  // Sample variance = 50 / 1 = 50
  EXPECT_DOUBLE_EQ(acc.sampleVariance(), 50.0);
}
