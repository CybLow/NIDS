#pragma once

#include "core/services/IPacketCapture.h"

#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/PcapLiveDevice.h>

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

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
};

} // namespace nids::infra
