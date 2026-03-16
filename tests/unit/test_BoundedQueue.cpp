#include "core/concurrent/BoundedQueue.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

using nids::core::BoundedQueue;

// ── Basic operations ────────────────────────────────────────────────

TEST(BoundedQueue, ConstructAndEmpty) {
  BoundedQueue<int> q(10);
  EXPECT_TRUE(q.empty());
  EXPECT_EQ(q.size(), 0u);
  EXPECT_FALSE(q.isClosed());
}

TEST(BoundedQueue, PushPopSingle) {
  BoundedQueue<int> q(4);
  EXPECT_TRUE(q.push(42));
  EXPECT_EQ(q.size(), 1u);

  auto val = q.pop();
  ASSERT_TRUE(val.has_value());
  EXPECT_EQ(*val, 42);
  EXPECT_TRUE(q.empty());
}

TEST(BoundedQueue, PushPopMultiple_fifoOrder) {
  BoundedQueue<int> q(8);
  for (int i = 0; i < 5; ++i) {
    EXPECT_TRUE(q.push(i));
  }
  EXPECT_EQ(q.size(), 5u);

  for (int i = 0; i < 5; ++i) {
    auto val = q.pop();
    ASSERT_TRUE(val.has_value());
    EXPECT_EQ(*val, i);
  }
  EXPECT_TRUE(q.empty());
}

TEST(BoundedQueue, TryPush_succeeds) {
  BoundedQueue<int> q(2);
  EXPECT_TRUE(q.tryPush(1));
  EXPECT_TRUE(q.tryPush(2));
  EXPECT_EQ(q.size(), 2u);
}

TEST(BoundedQueue, TryPush_failsWhenFull) {
  BoundedQueue<int> q(2);
  EXPECT_TRUE(q.tryPush(1));
  EXPECT_TRUE(q.tryPush(2));
  EXPECT_FALSE(q.tryPush(3)); // full
  EXPECT_EQ(q.size(), 2u);
}

// ── Close behavior ──────────────────────────────────────────────────

TEST(BoundedQueue, Close_popDrainsRemaining) {
  BoundedQueue<int> q(4);
  std::ignore = q.push(10);
  std::ignore = q.push(20);
  q.close();

  // Can still drain remaining elements after close
  auto v1 = q.pop();
  ASSERT_TRUE(v1.has_value());
  EXPECT_EQ(*v1, 10);

  auto v2 = q.pop();
  ASSERT_TRUE(v2.has_value());
  EXPECT_EQ(*v2, 20);

  // Now empty + closed → nullopt
  auto v3 = q.pop();
  EXPECT_FALSE(v3.has_value());
}

TEST(BoundedQueue, Close_pushReturnsFalse) {
  BoundedQueue<int> q(4);
  q.close();
  EXPECT_FALSE(q.push(42));
  EXPECT_FALSE(q.tryPush(42));
}

TEST(BoundedQueue, Close_idempotent) {
  BoundedQueue<int> q(4);
  q.close();
  q.close(); // no crash
  EXPECT_TRUE(q.isClosed());
}

// ── Move semantics ──────────────────────────────────────────────────

TEST(BoundedQueue, MoveOnlyType) {
  BoundedQueue<std::unique_ptr<int>> q(4);
  std::ignore = q.push(std::make_unique<int>(99));

  auto val = q.pop();
  ASSERT_TRUE(val.has_value());
  EXPECT_EQ(**val, 99);
}

// ── Concurrent producer-consumer ────────────────────────────────────

TEST(BoundedQueue, ConcurrentSingleProducerSingleConsumer) {
  constexpr int kCount = 10'000;
  BoundedQueue<int> q(64);

  std::jthread producer([&](std::stop_token) {
    for (int i = 0; i < kCount; ++i) {
      std::ignore = q.push(i);
    }
    q.close();
  });

  std::vector<int> consumed;
  consumed.reserve(kCount);
  while (auto val = q.pop()) {
    consumed.push_back(*val);
  }

  EXPECT_EQ(consumed.size(), static_cast<std::size_t>(kCount));
  // Verify FIFO order
  for (int i = 0; i < kCount; ++i) {
    EXPECT_EQ(consumed[static_cast<std::size_t>(i)], i);
  }
}

TEST(BoundedQueue, ConcurrentMultiProducerSingleConsumer) {
  constexpr int kPerProducer = 5'000;
  constexpr int kProducers = 4;
  BoundedQueue<int> q(32);

  std::atomic<int> producersDone{0};

  std::vector<std::jthread> producers;
  producers.reserve(kProducers);
  for (int p = 0; p < kProducers; ++p) {
    producers.emplace_back([&, p](std::stop_token) {
      for (int i = 0; i < kPerProducer; ++i) {
        std::ignore = q.push(p * kPerProducer + i);
      }
      if (++producersDone == kProducers) {
        q.close();
      }
    });
  }

  std::vector<int> consumed;
  consumed.reserve(kPerProducer * kProducers);
  while (auto val = q.pop()) {
    consumed.push_back(*val);
  }

  EXPECT_EQ(consumed.size(),
            static_cast<std::size_t>(kPerProducer * kProducers));
}

TEST(BoundedQueue, ConcurrentProducerConsumer_smallCapacity) {
  // Capacity=1 forces maximum contention between push and pop
  constexpr int kCount = 1'000;
  BoundedQueue<int> q(1);

  std::jthread producer([&](std::stop_token) {
    for (int i = 0; i < kCount; ++i) {
      std::ignore = q.push(i);
    }
    q.close();
  });

  int consumed = 0;
  while (q.pop().has_value()) {
    ++consumed;
  }

  EXPECT_EQ(consumed, kCount);
}

// ── Close wakes blocked consumers ───────────────────────────────────

TEST(BoundedQueue, Close_wakesBlockedConsumer) {
  BoundedQueue<int> q(4);

  std::atomic<bool> consumerFinished{false};
  std::jthread consumer([&](std::stop_token) {
    auto val = q.pop(); // blocks — queue is empty
    EXPECT_FALSE(val.has_value()); // closed + empty → nullopt
    consumerFinished = true;
  });

  // Give consumer time to block
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  EXPECT_FALSE(consumerFinished);

  q.close(); // wakes the blocked consumer
  consumer.join();
  EXPECT_TRUE(consumerFinished);
}

// ── Backpressure: push blocks when full ─────────────────────────────

TEST(BoundedQueue, Backpressure_pushBlocksWhenFull) {
  BoundedQueue<int> q(2);
  std::ignore = q.push(1);
  std::ignore = q.push(2);
  // Queue is now full

  std::atomic<bool> pushCompleted{false};
  std::jthread producer([&](std::stop_token) {
    std::ignore = q.push(3); // should block until consumer pops
    pushCompleted = true;
  });

  // Give producer time to block
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  EXPECT_FALSE(pushCompleted);

  // Pop one → unblocks the producer
  auto val = q.pop();
  ASSERT_TRUE(val.has_value());
  EXPECT_EQ(*val, 1);

  producer.join();
  EXPECT_TRUE(pushCompleted);
  EXPECT_EQ(q.size(), 2u); // 2 (original) + 3 (new) - 1 (popped) = 2
}
