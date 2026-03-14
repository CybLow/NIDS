#pragma once

#include "core/services/IPacketCapture.h"
#include "core/services/ServiceRegistry.h"

#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/PcapLiveDevice.h>

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace pcpp {
class RawPacket;
} // namespace pcpp

namespace nids::infra {

/** Worker that runs the pcap capture loop on a dedicated thread.
 *
 *  Pure C++23 — no Qt dependency.  Communicates results via
 *  std::function callbacks set before capture starts.
 */
class PcapCaptureWorker {
public:
  /** Callback types matching IPacketCapture conventions. */
  using PacketCallback = nids::core::IPacketCapture::PacketCallback;
  using ErrorCallback = nids::core::IPacketCapture::ErrorCallback;
  using RawPacketCallback = nids::core::IPacketCapture::RawPacketCallback;

  PcapCaptureWorker() = default;

  /**
   * Configure the capture session parameters before starting.
   * @param iface     Network interface name to capture on.
   * @param bpfFilter BPF filter expression (may be empty).
   * @param dumpFile  Path to write captured packets (empty to skip dump).
   */
  void configure(std::string_view iface, std::string_view bpfFilter,
                 std::string_view dumpFile);

  /** Set the callback invoked for each parsed packet (on the capture thread). */
  void setPacketCallback(PacketCallback cb);
  /** Set the callback invoked on capture errors (on the capture thread). */
  void setErrorCallback(ErrorCallback cb);
  /** Register a callback for raw packet data on the capture thread.
   *  Thread-safe: may be called from any thread before or during capture. */
  void setRawPacketCallback(RawPacketCallback cb);
  /** Set the callback invoked when capture finishes (on the capture thread). */
  void setFinishedCallback(std::function<void()> cb);

  /** Start the capture loop. Blocks until requestStop() is called. */
  void doCapture();
  /** Signal the capture loop to stop. Thread-safe. */
  void requestStop();

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

  PacketCallback packetCallback_;
  ErrorCallback errorCallback_;
  std::function<void()> finishedCallback_;
  RawPacketCallback rawPacketCallback_;
  std::mutex rawCallbackMutex_; ///< Protects rawPacketCallback_ for thread-safe set/read.
  nids::core::ServiceRegistry serviceRegistry_;
};

/** Pcap-based packet capture implementing IPacketCapture via a worker thread.
 *
 *  Pure C++23 — no Qt dependency.  Uses std::jthread for the capture thread.
 */
class PcapCapture : public nids::core::IPacketCapture {
public:
  PcapCapture() = default;
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
  void setRawPacketCallback(RawPacketCallback callback) override;
  [[nodiscard]] std::vector<std::string> listInterfaces() override;

private:
  std::unique_ptr<PcapCaptureWorker> worker_;
  std::jthread captureThread_;
  PacketCallback callback_;
  ErrorCallback errorCallback_;
  RawPacketCallback rawCallback_;
  std::string interface_;
  std::string bpfFilter_;
  std::atomic<bool> capturing_{false};
};

} // namespace nids::infra
