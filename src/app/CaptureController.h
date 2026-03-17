#pragma once

#include "core/model/DetectionResult.h"
#include "core/model/PacketInfo.h"
#include "core/model/CaptureSession.h"
#include "core/model/PacketFilter.h"
#include "core/services/IPacketCapture.h"
#include "core/services/IFlowExtractor.h"

#include <functional>
#include <memory>
#include <string>

namespace nids::app {

class LiveDetectionPipeline;

/** Controller that manages live packet capture via an IPacketCapture backend.
 *
 * Pure C++23 — no Qt dependency.  The UI layer bridges callbacks to its
 * own event loop (e.g. via QMetaObject::invokeMethod).
 *
 * When live detection is enabled (via enableLiveDetection()), captured
 * packets are simultaneously fed to a flow extractor for real-time ML
 * detection.  Detection results are delivered via the liveFlowDetected
 * callback.
 */
class CaptureController {
public:
    // ── Callback types ─────────────────────────────────────────────
    using PacketReceivedCallback = std::function<void(const core::PacketInfo&)>;
    using CaptureStartedCallback = std::function<void()>;
    using CaptureStoppedCallback = std::function<void()>;
    using CaptureErrorCallback   = std::function<void(const std::string& message)>;
    using LiveFlowCallback       = std::function<void(core::DetectionResult result,
                                                      core::FlowInfo metadata)>;

    /** Construct with an injected packet capture backend. */
    explicit CaptureController(std::unique_ptr<core::IPacketCapture> capture);
    ~CaptureController();

    CaptureController(const CaptureController&) = delete;
    CaptureController& operator=(const CaptureController&) = delete;
    CaptureController(CaptureController&&) = delete;
    CaptureController& operator=(CaptureController&&) = delete;

    /**
     * Enable real-time flow detection during live capture.
     *
     * The pipeline is started/stopped automatically with capture.
     * Must be called before startCapture().  The pipeline is non-owning —
     * the caller retains ownership and must ensure it outlives the controller.
     */
    void enableLiveDetection(LiveDetectionPipeline* pipeline) noexcept;

    /// Disable live detection.  The pipeline is stopped if currently running.
    void disableLiveDetection() noexcept;

    /**
     * Start capturing packets using the given filter.
     * @param filter    BPF filter to apply.
     * @param dumpFile  Optional path to write a pcap dump file.
     */
    void startCapture(const core::PacketFilter& filter,
                      const std::string& dumpFile = "");
    /** Stop the current capture session. */
    void stopCapture();

    /** Return true if a capture is currently running. */
    [[nodiscard]] bool isCapturing() const;
    /** Access the current capture session (mutable). */
    [[nodiscard]] core::CaptureSession& session();
    /** Access the current capture session (const). */
    [[nodiscard]] const core::CaptureSession& session() const;
    /** Query available network interfaces from the capture backend. */
    [[nodiscard]] std::vector<std::string> listInterfaces() const;

    /** Return true if live detection is enabled and currently running. */
    [[nodiscard]] bool isLiveDetectionActive() const noexcept;

    // ── Callback setters ───────────────────────────────────────────
    void setPacketReceivedCallback(PacketReceivedCallback cb) { onPacketReceived_ = std::move(cb); }
    void setCaptureStartedCallback(CaptureStartedCallback cb) { onCaptureStarted_ = std::move(cb); }
    void setCaptureStoppedCallback(CaptureStoppedCallback cb) { onCaptureStopped_ = std::move(cb); }
    void setCaptureErrorCallback(CaptureErrorCallback cb)     { onCaptureError_   = std::move(cb); }
    void setLiveFlowCallback(LiveFlowCallback cb)             { onLiveFlow_       = std::move(cb); }

private:
    std::unique_ptr<core::IPacketCapture> capture_;
    core::CaptureSession session_;
    LiveDetectionPipeline* pipeline_ = nullptr;  // non-owning

    // Callbacks (fired on the calling thread — the consumer is responsible
    // for any thread marshaling).
    PacketReceivedCallback onPacketReceived_;
    CaptureStartedCallback onCaptureStarted_;
    CaptureStoppedCallback onCaptureStopped_;
    CaptureErrorCallback   onCaptureError_;
    LiveFlowCallback       onLiveFlow_;
};

} // namespace nids::app
