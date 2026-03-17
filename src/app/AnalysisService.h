#pragma once

#include "app/FlowAnalysisWorker.h"
#include "core/concurrent/BoundedQueue.h"
#include "core/model/CaptureSession.h"
#include "core/model/AttackType.h"
#include "core/services/IPacketAnalyzer.h"
#include "core/services/IFlowExtractor.h"
#include "core/services/IFeatureNormalizer.h"

#include <expected>
#include <functional>
#include <memory>
#include <string>

namespace nids::app {

class HybridDetectionService;

/** Service that orchestrates ML-based packet/flow analysis.
 *
 * Pure C++23 — no Qt dependency.  The UI layer can bridge callbacks
 * to its own event loop (e.g. via QMetaObject::invokeMethod).
 */
class AnalysisService {
public:
    // ── Callback types ─────────────────────────────────────────────
    using StartedCallback  = std::function<void()>;
    using ProgressCallback = std::function<void(int current, int total)>;
    using FinishedCallback = std::function<void()>;
    using ErrorCallback    = std::function<void(const std::string& message)>;

    /** Construct with injected analyzer, flow extractor, and feature normalizer. */
    explicit AnalysisService(std::unique_ptr<core::IPacketAnalyzer> analyzer,
                             std::unique_ptr<core::IFlowExtractor> extractor,
                             std::unique_ptr<core::IFeatureNormalizer> normalizer);

    /** Load the ONNX model from the given path. Returns error string on failure. */
    [[nodiscard]] std::expected<void, std::string> loadModel(const std::string& modelPath);

    /// Load normalization parameters from model metadata JSON.
    /// Must be called before analyzeCapture() for correct predictions.
    [[nodiscard]] std::expected<void, std::string> loadNormalization(
        const std::string& metadataPath);

    /// Set the hybrid detection service for multi-layer analysis.
    /// The caller retains ownership (non-owning pointer).
    /// If not set, analysis falls back to ML-only mode.
    void setHybridDetection(HybridDetectionService* service) noexcept;

    /**
     * Run ML analysis on a pcap file, populating the session with detection results.
     * @param pcapPath  Path to the pcap file to analyze.
     * @param session   Capture session to populate with results.
     */
    void analyzeCapture(const std::string& pcapPath,
                        core::CaptureSession& session);

    /// Returns per-flow metadata from the most recent analyzeCapture() call.
    /// Indexed in the same order as detection results in the CaptureSession.
    [[nodiscard]] const std::vector<core::FlowInfo>& lastFlowMetadata() const noexcept;

    // ── Callback setters ───────────────────────────────────────────
    void setStartedCallback(StartedCallback cb)   { onStarted_  = std::move(cb); }
    void setProgressCallback(ProgressCallback cb)  { onProgress_ = std::move(cb); }
    void setFinishedCallback(FinishedCallback cb)  { onFinished_ = std::move(cb); }
    void setErrorCallback(ErrorCallback cb)        { onError_    = std::move(cb); }

private:
    std::unique_ptr<core::IPacketAnalyzer> analyzer_;
    std::unique_ptr<core::IFlowExtractor> extractor_;
    std::unique_ptr<core::IFeatureNormalizer> normalizer_;
    HybridDetectionService* hybridService_ = nullptr;  // non-owning

    // Callbacks (fired on the calling thread — the consumer is responsible
    // for any thread marshaling).
    StartedCallback  onStarted_;
    ProgressCallback onProgress_;
    FinishedCallback onFinished_;
    ErrorCallback    onError_;

    /// Push batch results through the worker pipeline when the streaming
    /// callback was not invoked (e.g. mock extractors).
    void pushBatchFallback(FlowAnalysisWorker& worker,
                           core::BoundedQueue<FlowWorkItem>& queue,
                           std::vector<std::vector<float>>& allFeatures);

    /// Log results and fire final callbacks.
    void reportResults(const std::string& pcapPath,
                       std::size_t processedCount,
                       bool noFeatures);
};

} // namespace nids::app
