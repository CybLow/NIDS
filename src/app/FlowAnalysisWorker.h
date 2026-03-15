#pragma once

/// Worker thread that consumes completed flows from a BoundedQueue
/// and runs the ML + hybrid detection pipeline.
///
/// Pure C++23 — no Qt dependency. Communicates results via a callback
/// that the UI layer can bridge to Qt signals using QMetaObject::invokeMethod.
///
/// Lives in the app/ layer: depends on core/ interfaces and app/ services.
/// Infrastructure implementations are injected via non-owning pointers.

#include "core/model/CaptureSession.h"
#include "core/model/DetectionResult.h"
#include "core/services/BoundedQueue.h"
#include "core/services/IFeatureNormalizer.h"
#include "core/services/IFlowExtractor.h"
#include "core/services/IPacketAnalyzer.h"

#include <atomic>
#include <cstddef>
#include <functional>
#include <thread>
#include <vector>

namespace nids::app {

class HybridDetectionService;

/// Work item pushed into the queue by the flow extractor callback.
struct FlowWorkItem {
    std::vector<float> features;
    nids::core::FlowInfo metadata;
};

/**
 * Consumes completed flows from a BoundedQueue on a dedicated std::jthread.
 *
 * Typical lifecycle:
 *   1. Construct with dependencies (queue, analyzer, normalizer, session).
 *   2. Optionally set a result callback and/or hybrid detection service.
 *   3. Call start() to launch the consumer thread.
 *   4. Producers push FlowWorkItems into the shared queue.
 *   5. Call stop() (or let the destructor run) to close the queue and join.
 *
 * The worker assigns sequential flow indices starting from 0. Each processed
 * flow's DetectionResult is stored in the CaptureSession and, if set, the
 * result callback is invoked with the index and result.
 */
class FlowAnalysisWorker {
public:
    /// Callback invoked on the worker thread for each processed flow.
    /// Parameters: (flow index, detection result, flow metadata).
    using ResultCallback =
        std::function<void(std::size_t, nids::core::DetectionResult,
                           nids::core::FlowInfo)>;

    /**
     * Construct the worker with its required dependencies.
     *
     * @param queue       Shared bounded queue (producer pushes, worker pops).
     * @param analyzer    ML inference engine (non-owning, must outlive worker).
     * @param normalizer  Feature normalizer (non-owning, must outlive worker).
     * @param session     Thread-safe result storage (non-owning, must outlive worker).
     */
    FlowAnalysisWorker(nids::core::BoundedQueue<FlowWorkItem>& queue,
                       nids::core::IPacketAnalyzer& analyzer,
                       nids::core::IFeatureNormalizer& normalizer,
                       nids::core::CaptureSession& session);

    ~FlowAnalysisWorker();

    // Non-copyable, non-movable (owns a thread).
    FlowAnalysisWorker(const FlowAnalysisWorker&) = delete;
    FlowAnalysisWorker& operator=(const FlowAnalysisWorker&) = delete;
    FlowAnalysisWorker(FlowAnalysisWorker&&) = delete;
    FlowAnalysisWorker& operator=(FlowAnalysisWorker&&) = delete;

    /// Set the hybrid detection service for multi-layer analysis.
    /// Pass nullptr to use ML-only mode. Must be called before start().
    void setHybridDetection(HybridDetectionService* service) noexcept;

    /// Set a callback invoked on the worker thread for each processed flow.
    /// Must be called before start().
    void setResultCallback(ResultCallback cb) noexcept;

    /// Launch the consumer thread.  No-op if already running.
    void start();

    /// Close the queue and join the worker thread.
    /// Blocks until all queued items are drained and processed.
    /// Safe to call multiple times.
    void stop();

    /// Number of flows processed so far (atomically read).
    [[nodiscard]] std::size_t processedCount() const noexcept;

    /// Check whether the worker thread is currently running.
    [[nodiscard]] bool isRunning() const noexcept;

private:
    /// Maximum number of flows per inference batch.
    static constexpr std::size_t kMaxBatchSize = 32;

    /// Consumer loop executed on the worker thread.
    void run();

    /// Process a batch of flow work items via batched inference.
    void processBatch(std::vector<FlowWorkItem>& items, std::size_t startIndex);

    /// Process a single flow work item (fallback for hybrid detection).
    void processItem(FlowWorkItem&& item, std::size_t index);

    nids::core::BoundedQueue<FlowWorkItem>& queue_;
    nids::core::IPacketAnalyzer& analyzer_;
    nids::core::IFeatureNormalizer& normalizer_;
    nids::core::CaptureSession& session_;
    HybridDetectionService* hybridService_ = nullptr;
    ResultCallback resultCallback_;

    std::jthread thread_;
    std::atomic<std::size_t> processedCount_{0};
    std::atomic<bool> running_{false};
};

} // namespace nids::app
