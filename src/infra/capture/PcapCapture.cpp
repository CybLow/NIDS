#include "infra/capture/PcapCapture.h"

#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IcmpLayer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>

#include <expected>
#include <iterator>
#include <ranges>
#include <string>

namespace nids::infra {

// --- PcapCaptureWorker ---

void PcapCaptureWorker::configure(std::string_view iface,
                                  std::string_view bpfFilter,
                                  std::string_view dumpFile) {
  interface_ = iface;
  bpfFilter_ = bpfFilter;
  dumpFile_ = dumpFile;
}

void PcapCaptureWorker::setPacketCallback(PacketCallback cb) {
  packetCallback_ = std::move(cb);
}

void PcapCaptureWorker::setErrorCallback(ErrorCallback cb) {
  errorCallback_ = std::move(cb);
}

void PcapCaptureWorker::setFinishedCallback(std::function<void()> cb) {
  finishedCallback_ = std::move(cb);
}

void PcapCaptureWorker::setRawPacketCallback(RawPacketCallback cb) {
  std::scoped_lock lock(rawCallbackMutex_);
  rawPacketCallback_ = std::move(cb);
}

void PcapCaptureWorker::doCapture() {
  device_ = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(interface_);
  if (!device_) {
    if (errorCallback_) {
      errorCallback_("Failed to find interface: " + interface_);
    }
    if (finishedCallback_) {
      finishedCallback_();
    }
    return;
  }

  if (!device_->open()) {
    if (errorCallback_) {
      errorCallback_("Failed to open interface: " + interface_);
    }
    if (finishedCallback_) {
      finishedCallback_();
    }
    return;
  }

  if (!bpfFilter_.empty() && !device_->setFilter(bpfFilter_)) {
    if (errorCallback_) {
      errorCallback_("Could not apply filter: " + bpfFilter_);
    }
  }

  if (!dumpFile_.empty()) {
    dumper_ = std::make_unique<pcpp::PcapFileWriterDevice>(dumpFile_);
    if (!dumper_->open()) {
      if (errorCallback_) {
        errorCallback_("Error opening dump file: " + dumpFile_);
      }
      dumper_.reset();
    }
  }

  capturing_.store(true);
  device_->startCapture(packetCallback, this);

  // PcapPlusPlus startCapture() is non-blocking, so block here until stop is
  // requested.
  std::unique_lock lock(mutex_);
  stopCv_.wait(lock, [this] { return !capturing_.load(); });

  device_->stopCapture();
  device_->close();
  dumper_.reset();
  device_ = nullptr;

  if (finishedCallback_) {
    finishedCallback_();
  }
}

void PcapCaptureWorker::requestStop() {
  if (capturing_.load()) {
    capturing_.store(false);
    std::scoped_lock lock(mutex_);
    stopCv_.notify_one();
  }
}

void PcapCaptureWorker::packetCallback(pcpp::RawPacket *rawPacket,
                                       pcpp::PcapLiveDevice * /*dev*/,
                                       void *userData) {
  auto *self = static_cast<PcapCaptureWorker *>(userData);
  self->processPacket(rawPacket);
}

void PcapCaptureWorker::processPacket(pcpp::RawPacket *rawPacket) {
  // Fire raw packet callback first (on the capture thread) before parsing
  // for PacketInfo.  This lets live flow extraction run with minimal latency.
  {
    std::scoped_lock lock(rawCallbackMutex_);
    if (rawPacketCallback_) {
      auto ts = rawPacket->getPacketTimeStamp();
      auto tsUs = std::int64_t{ts.tv_sec} * 1'000'000 +
                  std::int64_t{ts.tv_nsec} / 1'000;
      rawPacketCallback_(rawPacket->getRawData(),
                         static_cast<std::size_t>(rawPacket->getRawDataLen()),
                         tsUs);
    }
  }

  if (dumper_) {
    dumper_->writePacket(*rawPacket);
  }

  pcpp::Packet parsedPacket(rawPacket);

  // Skip non-IPv4 packets (ARP, IPv6, STP, etc.) -- they have no meaningful
  // IP/port fields and would display as blank rows in the Packets tab.
  const auto *ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
  if (!ipLayer) {
    return;
  }

  nids::core::PacketInfo info;
  info.ipSource = ipLayer->getSrcIPv4Address().toString();
  info.ipDestination = ipLayer->getDstIPv4Address().toString();

  if (const auto *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>()) {
    info.protocol = "TCP";
    info.portSource = std::to_string(tcpLayer->getSrcPort());
    info.portDestination = std::to_string(tcpLayer->getDstPort());
    info.application =
        serviceRegistry_.resolveApplication("", "", info.portDestination);
  } else if (const auto *udpLayer =
                 parsedPacket.getLayerOfType<pcpp::UdpLayer>()) {
    info.protocol = "UDP";
    info.portSource = std::to_string(udpLayer->getSrcPort());
    info.portDestination = std::to_string(udpLayer->getDstPort());
    info.application =
        serviceRegistry_.resolveApplication("", "", info.portDestination);
  } else if (parsedPacket.getLayerOfType<pcpp::IcmpLayer>()) {
    info.protocol = "ICMP";
    info.portSource = "-";
    info.portDestination = "-";
  } else {
    info.protocol = "Other";
    info.portSource = "-";
    info.portDestination = "-";
  }

  info.rawData.assign(rawPacket->getRawData(),
                      rawPacket->getRawData() + rawPacket->getRawDataLen());

  if (packetCallback_) {
    packetCallback_(info);
  }
}

// --- PcapCapture ---

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

std::vector<std::string> PcapCapture::listInterfaces() {
  const auto &devList =
      pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
  std::vector<std::string> result;
  result.reserve(devList.size());
  std::ranges::transform(devList, std::back_inserter(result),
                         [](const auto *dev) { return dev->getName(); });
  return result;
}

} // namespace nids::infra
