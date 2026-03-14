#include "infra/capture/PcapCapture.h"

#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IcmpLayer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>

#include <iterator>
#include <ranges>
#include <string>

namespace nids::infra {

// --- PcapCaptureWorker ---

PcapCaptureWorker::PcapCaptureWorker(QObject *parent) : QObject(parent) {}

void PcapCaptureWorker::configure(std::string_view iface,
                                  std::string_view bpfFilter,
                                  std::string_view dumpFile) {
  interface_ = iface;
  bpfFilter_ = bpfFilter;
  dumpFile_ = dumpFile;
}

void PcapCaptureWorker::doCapture() {
  device_ = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(interface_);
  if (!device_) {
    emit captureError(
        QString("Failed to find interface: %1").arg(interface_.c_str()));
    emit captureFinished();
    return;
  }

  if (!device_->open()) {
    emit captureError(
        QString("Failed to open interface: %1").arg(interface_.c_str()));
    emit captureFinished();
    return;
  }

  if (!bpfFilter_.empty() && !device_->setFilter(bpfFilter_)) {
    emit captureError(
        QString("Could not apply filter: %1").arg(bpfFilter_.c_str()));
  }

  if (!dumpFile_.empty()) {
    dumper_ = std::make_unique<pcpp::PcapFileWriterDevice>(dumpFile_);
    if (!dumper_->open()) {
      emit captureError(
          QString("Error opening dump file: %1").arg(dumpFile_.c_str()));
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
  emit captureFinished();
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

void PcapCaptureWorker::setRawPacketCallback(
    nids::core::IPacketCapture::RawPacketCallback cb) {
  std::scoped_lock lock(rawCallbackMutex_);
  rawPacketCallback_ = std::move(cb);
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

  pcpp::Packet parsedPacket(rawPacket);
  nids::core::PacketInfo info;

  if (const auto *ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()) {
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
    } else {
      info.protocol = "Unknown";
    }
  }

  info.rawData.assign(rawPacket->getRawData(),
                      rawPacket->getRawData() + rawPacket->getRawDataLen());

  if (dumper_) {
    dumper_->writePacket(*rawPacket);
  }

  emit packetCaptured(info);
}

// --- PcapCapture ---

PcapCapture::PcapCapture(QObject *parent) : QObject(parent) {
  auto workerPtr = std::make_unique<PcapCaptureWorker>();
  worker_ = workerPtr.release(); // Qt takes ownership via deleteLater
  worker_->moveToThread(&workerThread_);

  connect(&workerThread_, &QThread::finished, worker_, &QObject::deleteLater);
  connect(
      worker_, &PcapCaptureWorker::packetCaptured, this,
      [this](const nids::core::PacketInfo &info) {
        if (callback_)
          callback_(info);
        emit packetReceived(info);
      },
      Qt::QueuedConnection);
  connect(
      worker_, &PcapCaptureWorker::captureFinished, this,
      [this]() { capturing_.store(false); }, Qt::QueuedConnection);
  connect(
      worker_, &PcapCaptureWorker::captureError, this,
      [this](const QString &message) {
        if (errorCallback_)
          errorCallback_(message.toStdString());
      },
      Qt::QueuedConnection);

  workerThread_.start();
}

PcapCapture::~PcapCapture() {
  // Call the final override directly to avoid virtual dispatch in destructor.
  // cppcheck-suppress virtualCallInConstructor
  PcapCapture::stopCapture();
  workerThread_.quit();
  workerThread_.wait();
}

bool PcapCapture::initialize(const std::string &iface,
                             const std::string &bpfFilter) {
  interface_ = iface;
  bpfFilter_ = bpfFilter;
  return true;
}

void PcapCapture::startCapture(const std::string &dumpFile) {
  if (capturing_.load())
    return;
  capturing_.store(true);
  worker_->configure(interface_, bpfFilter_, dumpFile);
  QMetaObject::invokeMethod(worker_, "doCapture", Qt::QueuedConnection);
}

void PcapCapture::stopCapture() {
  if (!capturing_.load())
    return;
  QMetaObject::invokeMethod(worker_, "requestStop", Qt::QueuedConnection);
}

bool PcapCapture::isCapturing() const { return capturing_.load(); }

void PcapCapture::setPacketCallback(PacketCallback callback) {
  callback_ = std::move(callback);
}

void PcapCapture::setErrorCallback(ErrorCallback callback) {
  errorCallback_ = std::move(callback);
}

void PcapCapture::setRawPacketCallback(RawPacketCallback callback) {
  worker_->setRawPacketCallback(std::move(callback));
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
