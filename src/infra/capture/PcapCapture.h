#pragma once

#include "infra/capture/PcapCaptureWorker.h"
#include "core/services/IPacketCapture.h"

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace nids::infra {

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

  [[nodiscard]] std::expected<void, std::string> initialize(
      const std::string &iface, const std::string &bpfFilter) override;
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
