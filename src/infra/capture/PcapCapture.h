#pragma once

#include "core/services/IPacketCapture.h"
#include "core/services/ServiceRegistry.h"

#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/PcapLiveDevice.h>

#include <QObject>
#include <QThread>

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace pcpp {
class RawPacket;
} // namespace pcpp

namespace nids::infra {

/** Worker object that runs the pcap capture loop on a dedicated QThread. */
class PcapCaptureWorker : public QObject {
  Q_OBJECT

public:
  /** Construct a capture worker, optionally parented to @p parent. */
  explicit PcapCaptureWorker(QObject *parent = nullptr);

  /**
   * Configure the capture session parameters before starting.
   * @param iface     Network interface name to capture on.
   * @param bpfFilter BPF filter expression (may be empty).
   * @param dumpFile  Path to write captured packets (empty to skip dump).
   */
  void configure(std::string_view iface, std::string_view bpfFilter,
                 std::string_view dumpFile);

public slots:
  /** Start the capture loop. Blocks until requestStop() is called. */
  void doCapture();
  /** Signal the capture loop to stop. */
  void requestStop();

signals:
  /** Emitted for each captured packet with parsed metadata. */
  void packetCaptured(const nids::core::PacketInfo &info);
  /** Emitted when the capture loop exits normally. */
  void captureFinished();
  /** Emitted when a capture error occurs. */
  void captureError(const QString &message);

private:
  static void packetCallback(pcpp::RawPacket *rawPacket,
                             pcpp::PcapLiveDevice *dev, void *userData);
  void processPacket(pcpp::RawPacket *rawPacket);

  std::string interface_;
  std::string bpfFilter_;
  std::string dumpFile_;
  pcpp::PcapLiveDevice *device_ = nullptr;
  std::unique_ptr<pcpp::PcapFileWriterDevice> dumper_;
  std::atomic<bool> capturing_{false};
  std::mutex mutex_;
  std::condition_variable stopCv_;

  nids::core::ServiceRegistry serviceRegistry_;
};

/** Pcap-based packet capture implementing IPacketCapture via a worker thread.
 */
class PcapCapture : public QObject, public nids::core::IPacketCapture {
  Q_OBJECT

public:
  /** Construct the capture manager, optionally parented to @p parent. */
  explicit PcapCapture(QObject *parent = nullptr);
  ~PcapCapture() override;

  PcapCapture(const PcapCapture &) = delete;
  PcapCapture &operator=(const PcapCapture &) = delete;
  PcapCapture(PcapCapture &&) = delete;
  PcapCapture &operator=(PcapCapture &&) = delete;

  [[nodiscard]] bool initialize(const std::string &iface,
                                const std::string &bpfFilter) override;
  void startCapture(const std::string &dumpFile) override;
  void stopCapture() override;
  [[nodiscard]] bool isCapturing() const override;

  void setPacketCallback(PacketCallback callback) override;
  void setErrorCallback(ErrorCallback callback) override;
  [[nodiscard]] std::vector<std::string> listInterfaces() override;

signals:
  /** Emitted for each captured packet, forwarded from the worker thread. */
  void packetReceived(const nids::core::PacketInfo &info);

private:
  QThread workerThread_;
  PcapCaptureWorker *worker_ = nullptr;
  PacketCallback callback_;
  ErrorCallback errorCallback_;
  std::string interface_;
  std::string bpfFilter_;
  std::atomic<bool> capturing_{false};
};

} // namespace nids::infra
