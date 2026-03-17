#pragma once

/// Orchestrates real-time flow detection during live packet capture.
///
/// Pure C++23 — no Qt dependency.  The pipeline feeds raw packets into a
/// flow extractor, pushes completed flows into a BoundedQueue, and a
/// FlowAnalysisWorker consumes them for ML + hybrid detection.
///
/// Thread model:
///   - feedPacket() is called on the PcapPlusPlus capture thread.
///   - The flow extractor runs on the capture thread (single-threaded).
///   - Completed flows are enqueued via tryPush() (non-blocking).
///   - The FlowAnalysisWorker runs on its own std::jthread.
///   - ResultCallback fires on the worker thread.
///
/// Lives in the app/ layer: depends on core/ interfaces.
/// Infrastructure implementations are injected.

#include "app/FlowAnalysisWorker.h"
#include "core/model/CaptureSession.h"
#include "core/model/DetectionResult.h"
#include "core/concurrent/BoundedQueue.h"
#include "core/services/IFeatureNormalizer.h"
#include "core/services/IFlowExtractor.h"
#include "core/services/IOutputSink.h"
#include "core/services/IPacketAnalyzer.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace nids::app {

class HybridDetectionService;

/**
 * Real-time flow detection pipeline for live packet capture.
 *
 * Typical lifecycle:
 *   1. Construct with injected dependencies.
 *   2. Optionally set a result callback and/or hybrid detection service.
 *   3. Call start() when capture begins.
 *   4. Feed raw packets via feedPacket() from the capture thread.
 *   5. Call stop() when capture ends — finalizes remaining flows.
 */
class LiveDetectionPipeline {
public:
    /// Callback invoked on the worker thread for each detected flow.
    /// Parameters: (flow index, detection result, flow metadata).
    using ResultCallback =
        std::function<void(std::size_t, core::DetectionResult,
                           core::FlowInfo)>;

    /**
     * Construct the pipeline with required dependencies.
     *
     * All references are non-owning and must outlive the pipeline.
     *
     * @param extractor   Flow feature extractor (used for processPacket).
     * @param analyzer    ML inference engine.
     * @param normalizer  Feature normalizer.
     * @param session     Thread-safe result storage.
     */
    LiveDetectionPipeline(core::IFlowExtractor& extractor,
                          core::IPacketAnalyzer& analyzer,
                          core::IFeatureNormalizer& normalizer,
                          core::CaptureSession& session);

    ~LiveDetectionPipeline();

    // Non-copyable, non-movable.
    LiveDetectionPipeline(const LiveDetectionPipeline&) = delete;
    LiveDetectionPipeline& operator=(const LiveDetectionPipeline&) = delete;
    LiveDetectionPipeline(LiveDetectionPipeline&&) = delete;
    LiveDetectionPipeline& operator=(LiveDetectionPipeline&&) = delete;

    /// Set the hybrid detection service.  Must be called before start().
    /// @pre !isRunning()
    void setHybridDetection(HybridDetectionService* service) noexcept;

    /// Set a callback invoked on the worker thread for each detected flow.
    /// Must be called before start().
    /// @pre !isRunning()
    void setResultCallback(ResultCallback cb) noexcept;

    /// Register an output sink.  Sinks receive every flow result
    /// (attack + benign) on the worker thread.  Must be called before start().
    /// The pipeline does NOT take ownership — the caller must keep the sink
    /// alive until after stop() returns.
    /// @pre !isRunning()
    void addOutputSink(core::IOutputSink* sink);

    /// Start the pipeline: resets the flow extractor, creates the queue
    /// and worker thread.  No-op if already running.
    void start();

    /// Feed a single raw packet into the flow extractor.
    ///
    /// Called from the PcapPlusPlus capture thread.  Must only be called
    /// while the pipeline is running (between start() and stop()).
    void feedPacket(const std::uint8_t* data, std::size_t length,
                    std::int64_t timestampUs);

    /// Finalize remaining active flows, drain the queue, and stop the
    /// worker thread.  Blocks until all queued flows are processed.
    /// Safe to call multiple times.
    void stop();

    /// Number of flows detected so far (atomically read).
    [[nodiscard]] std::size_t flowsDetected() const noexcept;

    /// Check whether the pipeline is currently running.
    [[nodiscard]] bool isRunning() const noexcept;

    /// Number of flows dropped due to queue backpressure (atomically read).
    [[nodiscard]] std::size_t droppedFlows() const noexcept;

private:
    /// Queue capacity for the live detection pipeline.
    static constexpr std::size_t kQueueCapacity = 512;

    core::IFlowExtractor& extractor_;
    core::IPacketAnalyzer& analyzer_;
    core::IFeatureNormalizer& normalizer_;
    core::CaptureSession& session_;
    HybridDetectionService* hybridService_ = nullptr;
    ResultCallback resultCallback_;

    std::vector<core::IOutputSink*> sinks_;
    std::unique_ptr<core::BoundedQueue<FlowWorkItem>> queue_;
    std::unique_ptr<FlowAnalysisWorker> worker_;
    std::atomic<bool> running_{false};
    std::atomic<std::size_t> droppedFlows_{0};
    std::atomic<std::size_t> feedPacketCount_{0}; ///< Total feedPacket() calls.
    std::atomic<std::size_t> queuePushCount_{0};  ///< Successful queue pushes.

    /// Configure the worker's result callback, wrapping with output sink
    /// dispatch if sinks are registered.
    void configureResultCallback();

    /// Log diagnostics summary at pipeline stop.
    void logDiagnostics() const;
};

} // namespace nids::app
