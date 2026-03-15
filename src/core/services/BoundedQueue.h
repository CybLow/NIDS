#pragma once

/// Thread-safe bounded FIFO queue for producer-consumer patterns.
///
/// Provides blocking push/pop with backpressure: producers block when the queue
/// is full, consumers block when empty.  The queue can be closed to signal
/// end-of-stream — all blocked threads are woken and subsequent operations
/// return immediately.
///
/// Uses std::mutex + std::condition_variable (no lock-free tricks).  This is
/// correct, simple, and fast enough for the flow-level throughput expected in
/// NIDS (thousands of flows/sec, not millions of packets/sec).
///
/// Pure C++23, zero platform or framework dependencies.

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <optional>
#include <queue>
#include <vector>

namespace nids::core {

/**
 * Thread-safe bounded queue for single- or multi-producer/consumer use.
 *
 * @tparam T  Element type (must be movable).
 */
template <typename T>
class BoundedQueue {
public:
  /// Construct a queue with the given maximum capacity.
  /// @param capacity  Maximum number of elements before push blocks (must be >
  /// 0).
  explicit BoundedQueue(std::size_t capacity) : capacity_(capacity) {}

  // Non-copyable, non-movable (contains mutex/condvar).
  BoundedQueue(const BoundedQueue &) = delete;
  BoundedQueue &operator=(const BoundedQueue &) = delete;
  BoundedQueue(BoundedQueue &&) = delete;
  BoundedQueue &operator=(BoundedQueue &&) = delete;

  /**
   * Push an element, blocking until space is available or the queue is closed.
   *
   * @param value  Element to enqueue (moved in).
   * @return true if the element was enqueued, false if the queue was closed.
   */
  bool push(T value) {
    std::unique_lock lock(mutex_);
    notFull_.wait(lock, [this] { return queue_.size() < capacity_ || closed_; });
    if (closed_)
      return false;
    queue_.push(std::move(value));
    lock.unlock();
    notEmpty_.notify_one();
    return true;
  }

  /**
   * Try to push without blocking.
   *
   * @param value  Element to enqueue (moved in).
   * @return true if enqueued, false if the queue was full or closed.
   */
  bool tryPush(T value) {
    std::unique_lock lock(mutex_);
    if (closed_ || queue_.size() >= capacity_)
      return false;
    queue_.push(std::move(value));
    lock.unlock();
    notEmpty_.notify_one();
    return true;
  }

  /**
   * Pop an element, blocking until one is available or the queue is closed
   * and drained.
   *
   * @return The dequeued element, or std::nullopt if the queue is closed and
   *         empty (end-of-stream).
   */
  std::optional<T> pop() {
    std::unique_lock lock(mutex_);
    notEmpty_.wait(lock, [this] { return !queue_.empty() || closed_; });
    if (queue_.empty())
      return std::nullopt; // closed and drained
    T value = std::move(queue_.front());
    queue_.pop();
    lock.unlock();
    notFull_.notify_one();
    return value;
  }

  /**
   * Pop up to maxItems elements in one lock acquisition.
   *
   * Blocks until at least one element is available (or the queue is closed
   * and drained).  Then drains up to maxItems without releasing the lock,
   * minimizing lock contention for batched consumers.
   *
   * @param maxItems  Maximum number of elements to dequeue.
   * @return Vector of dequeued elements (empty = end-of-stream).
   */
  std::vector<T> popBatch(std::size_t maxItems) {
    std::vector<T> batch;
    batch.reserve(maxItems);
    std::unique_lock lock(mutex_);
    notEmpty_.wait(lock, [this] { return !queue_.empty() || closed_; });
    while (!queue_.empty() && batch.size() < maxItems) {
      batch.push_back(std::move(queue_.front()));
      queue_.pop();
    }
    lock.unlock();
    if (!batch.empty()) {
      notFull_.notify_all();
    }
    return batch;
  }

  /**
   * Close the queue.  Wakes all blocked producers and consumers.
   * After closing, push() returns false and pop() returns nullopt once drained.
   * Idempotent — safe to call multiple times.
   */
  void close() {
    {
      std::scoped_lock lock(mutex_);
      closed_ = true;
    }
    notFull_.notify_all();
    notEmpty_.notify_all();
  }

  /// Check if the queue has been closed.
  [[nodiscard]] bool isClosed() const {
    std::scoped_lock lock(mutex_);
    return closed_;
  }

  /// Return the current number of elements in the queue.
  [[nodiscard]] std::size_t size() const {
    std::scoped_lock lock(mutex_);
    return queue_.size();
  }

  /// Check whether the queue is empty.
  [[nodiscard]] bool empty() const {
    std::scoped_lock lock(mutex_);
    return queue_.empty();
  }

private:
  mutable std::mutex mutex_;
  std::condition_variable notFull_;
  std::condition_variable notEmpty_;
  std::queue<T> queue_;
  std::size_t capacity_;
  bool closed_ = false;
};

} // namespace nids::core
