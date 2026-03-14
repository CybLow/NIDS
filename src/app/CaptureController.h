#pragma once

#include "core/model/DetectionResult.h"
#include "core/model/PacketInfo.h"
#include "core/model/CaptureSession.h"
#include "core/services/PacketFilter.h"
#include "core/services/IPacketCapture.h"
#include "core/services/IFlowExtractor.h"

#include <QObject>

#include <memory>
#include <string>

namespace nids::app {

class LiveDetectionPipeline;

/** Controller that manages live packet capture via an IPacketCapture backend.
 *
 * When live detection is enabled (via enableLiveDetection()), captured
 * packets are simultaneously fed to a flow extractor for real-time ML
 * detection.  Detection results are emitted via liveFlowDetected().
 */
class CaptureController : public QObject {
    Q_OBJECT

public:
    /** Construct with an injected packet capture backend. */
    explicit CaptureController(std::unique_ptr<nids::core::IPacketCapture> capture,
                               QObject* parent = nullptr);
    ~CaptureController() override;

    /**
     * Enable real-time flow detection during live capture.
     *
     * The pipeline is started/stopped automatically with capture.
     * Must be called before startCapture().  The pipeline is non-owning —
     * the caller retains ownership and must ensure it outlives the controller.
     *
     * @param pipeline  Live detection pipeline (non-owning).
     */
    void enableLiveDetection(LiveDetectionPipeline* pipeline) noexcept;

    /// Disable live detection.  The pipeline is stopped if currently running.
    void disableLiveDetection() noexcept;

    /**
     * Start capturing packets using the given filter.
     * @param filter    BPF filter to apply.
     * @param dumpFile  Optional path to write a pcap dump file.
     */
    void startCapture(const nids::core::PacketFilter& filter,
                      const std::string& dumpFile = "");
    /** Stop the current capture session. */
    void stopCapture();

    /** Return true if a capture is currently running. */
    [[nodiscard]] bool isCapturing() const;
    /** Access the current capture session (mutable). */
    [[nodiscard]] nids::core::CaptureSession& session();
    /** Access the current capture session (const). */
    [[nodiscard]] const nids::core::CaptureSession& session() const;
    /** Query available network interfaces from the capture backend. */
    [[nodiscard]] std::vector<std::string> listInterfaces();

    /** Return true if live detection is enabled and currently running. */
    [[nodiscard]] bool isLiveDetectionActive() const noexcept;

signals:
    /** Emitted for each captured packet. */
    void packetReceived(const nids::core::PacketInfo& info);
    /** Emitted when capture begins. */
    void captureStarted();
    /** Emitted when capture ends. */
    void captureStopped();
    /** Emitted when a capture error occurs. */
    void captureError(const QString& message);

    /** Emitted on the main thread for each flow detected during live capture. */
    void liveFlowDetected(nids::core::DetectionResult result,
                          nids::core::FlowInfo metadata);

private:
    std::unique_ptr<nids::core::IPacketCapture> capture_;
    nids::core::CaptureSession session_;
    LiveDetectionPipeline* pipeline_ = nullptr;  // non-owning
};

} // namespace nids::app
