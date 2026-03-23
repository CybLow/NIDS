#include "infra/flow/NativeFlowExtractor.h"

#include <gtest/gtest.h>

using nids::core::FlowKey;

// ── FlowKey tests ────────────────────────────────────────────────────

TEST(FlowKey, Equality) {
  FlowKey a{"10.0.0.1", "192.168.1.1", 12345, 443, 6};
  FlowKey b{"10.0.0.1", "192.168.1.1", 12345, 443, 6};
  FlowKey c{"10.0.0.2", "192.168.1.1", 12345, 443, 6};
  FlowKey d{"10.0.0.1", "192.168.1.2", 12345, 443, 6};

  EXPECT_EQ(a, b);
  EXPECT_NE(a, c);
  EXPECT_NE(a, d);
}

TEST(FlowKey, Equality_portDifference) {
  FlowKey a{"10.0.0.1", "10.0.0.2", 80, 443, 6};
  FlowKey b{"10.0.0.1", "10.0.0.2", 81, 443, 6};
  FlowKey c{"10.0.0.1", "10.0.0.2", 80, 444, 6};
  FlowKey d{"10.0.0.1", "10.0.0.2", 80, 443, 17};

  EXPECT_NE(a, b);
  EXPECT_NE(a, c);
  EXPECT_NE(a, d);
}

TEST(FlowKey, HashConsistency) {
  nids::core::FlowKeyHash hasher;
  FlowKey a{"10.0.0.1", "192.168.1.1", 12345, 443, 6};
  FlowKey b{"10.0.0.1", "192.168.1.1", 12345, 443, 6};
  FlowKey c{"10.0.0.2", "192.168.1.1", 12345, 443, 6};

  EXPECT_EQ(hasher(a), hasher(b));
  EXPECT_NE(hasher(a), hasher(c));
}

TEST(FlowKey, HashDiffersForProtocol) {
  nids::core::FlowKeyHash hasher;
  FlowKey tcp{"10.0.0.1", "10.0.0.2", 80, 443, 6};
  FlowKey udp{"10.0.0.1", "10.0.0.2", 80, 443, 17};
  EXPECT_NE(hasher(tcp), hasher(udp));
}
