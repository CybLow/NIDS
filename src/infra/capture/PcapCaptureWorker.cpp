#include "infra/capture/PcapCaptureWorker.h"
#include "core/model/ProtocolConstants.h"
#include "infra/parsing/PacketParser.h"

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/RawPacket.h>

namespace nids::infra {

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

  if (!bpfFilter_.empty() && !device_->setFilter(bpfFilter_) &&
      errorCallback_) {
    errorCallback_("Could not apply filter: " + bpfFilter_);
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

  // Use the shared PacketParser to parse headers (DRY — same parser as
  // NativeFlowExtractor).  Skip non-IPv4 packets.
  pcpp::Packet parsedPacket(rawPacket);
  ParsedFields fields;
  if (!parsePacketHeaders(parsedPacket, fields)) {
    return;
  }

  core::PacketInfo info;
  info.ipSource = fields.srcIp;
  info.ipDestination = fields.dstIp;

  info.protocol = fields.protocol;
  if (fields.protocol == core::kIpProtoTcp ||
      fields.protocol == core::kIpProtoUdp) {
    info.portSource = fields.srcPort;
    info.portDestination = fields.dstPort;
  }
  // ICMP and other protocols: portSource/portDestination default to 0.
  // Note: application/service resolution is NOT done here — that's the
  // UI layer's responsibility (ServiceRegistry is a UI/display concern).

  info.rawData.assign(rawPacket->getRawData(),
                      rawPacket->getRawData() + rawPacket->getRawDataLen());

  if (packetCallback_) {
    packetCallback_(info);
  }
}

} // namespace nids::infra
