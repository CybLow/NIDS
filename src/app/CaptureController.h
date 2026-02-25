#pragma once

#include "core/model/PacketInfo.h"
#include "core/model/CaptureSession.h"
#include "core/services/PacketFilter.h"
#include "core/services/IPacketCapture.h"

#include <QObject>

#include <memory>
#include <string>

namespace nids::app {

class CaptureController : public QObject {
    Q_OBJECT

public:
    explicit CaptureController(std::unique_ptr<nids::core::IPacketCapture> capture,
                               QObject* parent = nullptr);
    ~CaptureController() override;

    void startCapture(const nids::core::PacketFilter& filter,
                      const std::string& dumpFile = "");
    void stopCapture();

    [[nodiscard]] bool isCapturing() const;
    [[nodiscard]] nids::core::CaptureSession& session();
    [[nodiscard]] const nids::core::CaptureSession& session() const;
    [[nodiscard]] std::vector<std::string> listInterfaces();

signals:
    void packetReceived(const nids::core::PacketInfo& info);
    void captureStarted();
    void captureStopped();
    void captureError(const QString& message);

private:
    std::unique_ptr<nids::core::IPacketCapture> capture_;
    nids::core::CaptureSession session_;
};

} // namespace nids::app
