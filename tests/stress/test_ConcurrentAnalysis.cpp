/**
 * Stress test: Concurrent analysis load.
 *
 * Tests HybridDetectionService and the analysis pipeline under concurrent
 * access from multiple threads submitting flows simultaneously.
 */

#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include "app/HybridDetectionService.h"
#include "core/model/DetectionResult.h"
#include "core/model/PredictionResult.h"
#include "stress/StressTestHelpers.h"

#include <atomic>
#include <format>
#include <mutex>
#include <thread>
#include <vector>

using nids::app::HybridDetectionService;
using nids::core::AttackType;
using nids::core::DetectionResult;
using nids::core::FlowInfo;
using nids::core::PredictionResult;
using nids::test::ScopedTimer;
using nids::test::StubAnalyzer;
using nids::test::StubRuleEngine;
using nids::test::StubThreatIntel;

namespace {

PredictionResult makePred(AttackType type, float confidence) {
  PredictionResult pred;
  pred.classification = type;
  pred.confidence = confidence;
  return pred;
}

FlowInfo makeFlowMeta(std::uint32_t flowId, double pps = 500.0) {
  FlowInfo meta;
  meta.srcIp = std::format("10.0.{}.{}", (flowId >> 8) & 0xff, flowId & 0xff);
  meta.dstIp = "10.1.0.1";
  meta.srcPort = static_cast<std::uint16_t>(40000 + flowId);
  meta.dstPort = 80;
  meta.protocol = 6;
  meta.totalFwdPackets = 100;
  meta.totalBwdPackets = 80;
  meta.flowDurationUs = 1'000'000.0;
  meta.fwdPacketsPerSecond = pps;
  meta.bwdPacketsPerSecond = pps * 0.8;
  return meta;
}

} // anonymous namespace

class ConcurrentAnalysisTest : public ::testing::Test {
protected: // NOSONAR
  StubThreatIntel ti_;
  StubRuleEngine rules_;
};

TEST_F(ConcurrentAnalysisTest, singleThread_10kEvaluations) {
  using enum nids::core::AttackType;
  HybridDetectionService service(&ti_, &rules_);
  constexpr std::size_t kFlows = 10'000;

  double elapsedMs = 0.0;
  std::size_t attackCount = 0;
  {
    ScopedTimer timer(elapsedMs);
    for (std::size_t i = 0; i < kFlows; ++i) {
      auto pred =
          (i % 3 == 0) ? makePred(DdosIcmp, 0.9f) : makePred(Benign, 0.95f);
      auto meta = makeFlowMeta(static_cast<std::uint32_t>(i));
      auto result = service.evaluate(pred, meta.srcIp, meta.dstIp, meta);
      if (result.finalVerdict != AttackType::Benign) {
        ++attackCount;
      }
    }
  }

  double epsec = static_cast<double>(kFlows) / (elapsedMs / 1000.0);
  spdlog::info(
      "Single-thread 10k evaluations: {:.1f} ms, {:.0f} eval/sec, {} attacks",
      elapsedMs, epsec, attackCount);

  EXPECT_GT(epsec, 50'000.0) << "Evaluation throughput too low";
  EXPECT_GT(attackCount, 0u);
}

TEST_F(ConcurrentAnalysisTest, multiThread_4threads_10kEach) {
  using enum nids::core::AttackType;
  HybridDetectionService service(&ti_, &rules_);
  constexpr std::size_t kFlowsPerThread = 10'000;
  constexpr unsigned kThreads = 4;

  std::atomic<std::size_t> totalAttacks{0};
  std::atomic<std::size_t> totalErrors{0};

  double elapsedMs = 0.0;
  {
    ScopedTimer timer(elapsedMs);

    std::vector<std::jthread> threads;
    threads.reserve(kThreads);

    for (unsigned t = 0; t < kThreads; ++t) {
      threads.emplace_back([&service, &totalAttacks, &totalErrors, t] {
        for (std::size_t i = 0; i < kFlowsPerThread; ++i) {
          auto flowId = static_cast<std::uint32_t>(t * kFlowsPerThread + i);
          auto pred = (i % 5 == 0) ? makePred(SynFlood, 0.88f)
                                   : makePred(Benign, 0.92f);
          auto meta = makeFlowMeta(flowId);

          try {
            auto result = service.evaluate(pred, meta.srcIp, meta.dstIp, meta);
            if (result.finalVerdict != Benign) {
              totalAttacks.fetch_add(1, std::memory_order_relaxed);
            }
          } catch (const std::exception & /* e */) { // NOSONAR
            totalErrors.fetch_add(1, std::memory_order_relaxed);
          }
        }
      });
    }
    // jthreads join automatically
  }

  std::size_t totalFlows = kFlowsPerThread * kThreads;
  double epsec = static_cast<double>(totalFlows) / (elapsedMs / 1000.0);
  spdlog::info("{} threads x {} flows: {:.1f} ms, {:.0f} eval/sec, {} attacks, "
               "{} errors",
               kThreads, kFlowsPerThread, elapsedMs, epsec, totalAttacks.load(),
               totalErrors.load());

  EXPECT_EQ(totalErrors.load(), 0u) << "Concurrent evaluation errors detected";
  EXPECT_GT(totalAttacks.load(), 0u);
  EXPECT_GT(epsec, 20'000.0) << "Concurrent throughput too low";
}

TEST_F(ConcurrentAnalysisTest, multiThread_8threads_highContention) {
  // Stress test with higher contention: 8 threads all evaluating flows
  // that share a small number of IPs (triggering TI lookups)
  std::vector<std::string> blacklist = {"10.0.0.1", "10.0.0.2", "10.0.0.3"};
  StubThreatIntel tiWithMatches(blacklist);
  HybridDetectionService service(&tiWithMatches, &rules_);

  constexpr std::size_t kFlowsPerThread = 5'000;
  constexpr unsigned kThreads = 8;

  std::atomic<std::size_t> tiMatches{0};
  std::atomic<std::size_t> totalErrors{0};

  double elapsedMs = 0.0;
  {
    ScopedTimer timer(elapsedMs);

    std::vector<std::jthread> threads;
    threads.reserve(kThreads);

    for (unsigned t = 0; t < kThreads; ++t) {
      threads.emplace_back([&service, &tiMatches, &totalErrors] {
        for (std::size_t i = 0; i < kFlowsPerThread; ++i) {
          // Cycle through IPs including blacklisted ones
          auto flowId = static_cast<std::uint32_t>(i % 10);
          auto pred = makePred(AttackType::Benign, 0.7f);
          auto meta = makeFlowMeta(flowId);
          // Override srcIp to cycle through blacklisted IPs
          meta.srcIp = std::format("10.0.0.{}", flowId);

          try {
            auto result = service.evaluate(pred, meta.srcIp, meta.dstIp, meta);
            if (result.hasThreatIntelMatch()) {
              tiMatches.fetch_add(1, std::memory_order_relaxed);
            }
          } catch (const std::exception & /* e */) { // NOSONAR
            totalErrors.fetch_add(1, std::memory_order_relaxed);
          }
        }
      });
    }
  }

  std::size_t totalFlows = kFlowsPerThread * kThreads;
  double epsec = static_cast<double>(totalFlows) / (elapsedMs / 1000.0);
  spdlog::info(
      "{} threads x {} flows (TI contention): {:.1f} ms, {:.0f} eval/sec, "
      "{} TI matches, {} errors",
      kThreads, kFlowsPerThread, elapsedMs, epsec, tiMatches.load(),
      totalErrors.load());

  EXPECT_EQ(totalErrors.load(), 0u);
  EXPECT_GT(tiMatches.load(), 0u) << "Expected some TI matches";
}

TEST_F(ConcurrentAnalysisTest, weightChangeUnderLoad) {
  // Change weights while threads are evaluating — must not crash
  HybridDetectionService service(&ti_, &rules_);
  constexpr std::size_t kFlowsPerThread = 5'000;
  constexpr unsigned kWorkerThreads = 4;

  std::atomic running{true};
  std::atomic<std::size_t> totalEvals{0};
  std::atomic<std::size_t> totalErrors{0};

  // Worker threads
  std::vector<std::jthread> workers;
  workers.reserve(kWorkerThreads);
  for (unsigned t = 0; t < kWorkerThreads; ++t) {
    workers.emplace_back([&service, &running, &totalEvals, &totalErrors] {
      std::size_t count = 0;
      while (running.load(std::memory_order_relaxed) ||
             count < kFlowsPerThread) {
        auto pred = makePred(AttackType::PortScanning, 0.75f);
        auto meta = makeFlowMeta(static_cast<std::uint32_t>(count));
        try {
          auto result = service.evaluate(pred, meta.srcIp, meta.dstIp, meta);
          static_cast<void>(result);
        } catch (const std::exception & /* e */) { // NOSONAR
          totalErrors.fetch_add(1, std::memory_order_relaxed);
        }
        ++count;
      }
      totalEvals.fetch_add(count, std::memory_order_relaxed);
    });
  }

  // Weight-changer thread — rapidly changes weights
  std::jthread weightChanger([&service, &running] {
    HybridDetectionService::Weights w;
    for (int i = 0; i < 100 && running.load(std::memory_order_relaxed); ++i) {
      w.ml = 0.3f + static_cast<float>(i % 5) * 0.1f;
      w.threatIntel = 0.2f + static_cast<float>(i % 3) * 0.1f;
      w.heuristic = 1.0f - w.ml - w.threatIntel;
      service.setWeights(w);
      std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    running.store(false, std::memory_order_relaxed);
  });

  weightChanger.join();
  for (auto &w : workers) {
    w.join();
  }

  spdlog::info("Weight change under load: {} total evaluations, {} errors",
               totalEvals.load(), totalErrors.load());

  EXPECT_EQ(totalErrors.load(), 0u)
      << "Errors during concurrent weight changes";
  EXPECT_GT(totalEvals.load(), 0u);
}
