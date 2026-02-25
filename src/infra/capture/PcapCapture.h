#pragma once

#include "core/services/IPacketCapture.h"
#include "core/services/ServiceRegistry.h"
#include "infra/capture/PcapHandle.h"

#include <QObject>
#include <QThread>

#include <atomic>
#include <string>
#include <vector>
#include <mutex>

namespace nids::infra {

class PcapCaptureWorker : public QObject {
    Q_OBJECT

public:
    explicit PcapCaptureWorker(QObject* parent = nullptr);

    void configure(const std::string& interface, const std::string& bpfFilter,
                   const std::string& dumpFile);

public slots:
    void doCapture();
    void requestStop();

signals:
    void packetCaptured(const nids::core::PacketInfo& info);
    void captureFinished();
    void captureError(const QString& message);

private:
    static void packetCallback(unsigned char* userData,
                               const struct pcap_pkthdr* pkthdr,
                               const unsigned char* packet);
    void processPacket(const struct pcap_pkthdr* pkthdr,
                       const unsigned char* packet);

    std::string interface_;
    std::string bpfFilter_;
    std::string dumpFile_;
    PcapHandle handle_{nullptr};
    PcapDumperHandle dumper_{nullptr};
    std::atomic<bool> capturing_{false};

    nids::core::ServiceRegistry serviceRegistry_;
};

class PcapCapture : public QObject, public nids::core::IPacketCapture {
    Q_OBJECT

public:
    explicit PcapCapture(QObject* parent = nullptr);
    ~PcapCapture() override;

    [[nodiscard]] bool initialize(const std::string& interface,
                                  const std::string& bpfFilter) override;
    void startCapture(const std::string& dumpFile) override;
    void stopCapture() override;
    [[nodiscard]] bool isCapturing() const override;

    void setPacketCallback(PacketCallback callback) override;
    void setErrorCallback(ErrorCallback callback) override;
    [[nodiscard]] std::vector<std::string> listInterfaces() override;

signals:
    void packetReceived(const nids::core::PacketInfo& info);

private:
    QThread workerThread_;
    PcapCaptureWorker* worker_ = nullptr;
    PacketCallback callback_;
    ErrorCallback errorCallback_;
    std::string interface_;
    std::string bpfFilter_;
    std::atomic<bool> capturing_{false};
};

} // namespace nids::infra
