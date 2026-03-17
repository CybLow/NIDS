#include "infra/capture/PcapCapture.h"
#include "infra/capture/PcapCaptureWorker.h"

#include <pcapplusplus/PcapLiveDeviceList.h>

#include <expected>
#include <iterator>
#include <ranges>
#include <string>

namespace nids::infra {

PcapCapture::PcapCapture() = default;

PcapCapture::~PcapCapture() {
  PcapCapture::stopCapture();
}

std::expected<void, std::string> PcapCapture::initialize(
    const std::string &iface, const std::string &bpfFilter) {
  interface_ = iface;
  bpfFilter_ = bpfFilter;
  return {};
}

void PcapCapture::startCapture(const std::string &dumpFile) {
  if (capturing_.load())
    return;
  capturing_.store(true);

  // Create a fresh worker for each capture session.
  worker_ = std::make_unique<PcapCaptureWorker>();
  worker_->configure(interface_, bpfFilter_, dumpFile);
  worker_->setPacketCallback(callback_);
  worker_->setErrorCallback(errorCallback_);
  worker_->setRawPacketCallback(rawCallback_);
  worker_->setFinishedCallback([this]() { capturing_.store(false); });

  captureThread_ = std::jthread([w = worker_.get()](std::stop_token /*st*/) {
    w->doCapture();
  });
}

void PcapCapture::stopCapture() {
  if (!capturing_.load() && !worker_)
    return;

  if (worker_) {
    worker_->requestStop();
  }

  if (captureThread_.joinable()) {
    captureThread_.join();
  }

  worker_.reset();
}

bool PcapCapture::isCapturing() const { return capturing_.load(); }

void PcapCapture::setPacketCallback(PacketCallback callback) {
  callback_ = std::move(callback);
}

void PcapCapture::setErrorCallback(ErrorCallback callback) {
  errorCallback_ = std::move(callback);
}

void PcapCapture::setRawPacketCallback(RawPacketCallback callback) {
  rawCallback_ = std::move(callback);
  if (worker_) {
    worker_->setRawPacketCallback(rawCallback_);
  }
}

std::vector<std::string> PcapCapture::listInterfaces() const {
  const auto &devList =
      pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
  std::vector<std::string> result;
  result.reserve(devList.size());
  std::ranges::transform(devList, std::back_inserter(result),
                         [](const auto *dev) { return dev->getName(); });
  return result;
}

} // namespace nids::infra
