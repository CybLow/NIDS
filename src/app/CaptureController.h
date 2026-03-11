#pragma once

#include "core/model/PacketInfo.h"
#include "core/model/CaptureSession.h"
#include "core/services/PacketFilter.h"
#include "core/services/IPacketCapture.h"

#include <QObject>

#include <memory>
#include <string>

namespace nids::app {

/** Controller that manages live packet capture via an IPacketCapture backend. */
class CaptureController : public QObject {
    Q_OBJECT

public:
    /** Construct with an injected packet capture backend. */
    explicit CaptureController(std::unique_ptr<nids::core::IPacketCapture> capture,
                               QObject* parent = nullptr);
    ~CaptureController() override;

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

signals:
    /** Emitted for each captured packet. */
    void packetReceived(const nids::core::PacketInfo& info);
    /** Emitted when capture begins. */
    void captureStarted();
    /** Emitted when capture ends. */
    void captureStopped();
    /** Emitted when a capture error occurs. */
    void captureError(const QString& message);

private:
    std::unique_ptr<nids::core::IPacketCapture> capture_;
    nids::core::CaptureSession session_;
};

} // namespace nids::app
