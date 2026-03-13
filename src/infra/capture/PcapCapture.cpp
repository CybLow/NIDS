#include "infra/capture/PcapCapture.h"
#include "infra/platform/NetworkHeaders.h"

#include <cstring>
#include <pcap.h>

namespace nids::infra {

// --- PcapCaptureWorker ---

PcapCaptureWorker::PcapCaptureWorker(QObject *parent) : QObject(parent) {}

void PcapCaptureWorker::configure(std::string_view interface,
                                  std::string_view bpfFilter,
                                  std::string_view dumpFile) {
  interface_ = interface;
  bpfFilter_ = bpfFilter;
  dumpFile_ = dumpFile;
}

void PcapCaptureWorker::doCapture() {
  char errbuf[PCAP_ERRBUF_SIZE];
  auto *rawHandle = pcap_open_live(interface_.c_str(), BUFSIZ, 1, 1000, errbuf);
  if (!rawHandle) {
    emit captureError(QString("Failed to open interface: %1").arg(errbuf));
    emit captureFinished();
    return;
  }
  handle_ = makePcapHandle(rawHandle);

  if (!bpfFilter_.empty()) {
    struct bpf_program fp{};
    if (pcap_compile(handle_.get(), &fp, bpfFilter_.c_str(), 0,
                     PCAP_NETMASK_UNKNOWN) != -1) {
      if (pcap_setfilter(handle_.get(), &fp) == -1) {
        emit captureError(QString("Could not install filter: %1")
                              .arg(pcap_geterr(handle_.get())));
      }
      pcap_freecode(&fp);
    } else {
      emit captureError(QString("Could not compile filter: %1")
                            .arg(pcap_geterr(handle_.get())));
    }
  }

  if (!dumpFile_.empty()) {
    auto *rawDumper = pcap_dump_open(handle_.get(), dumpFile_.c_str());
    if (rawDumper) {
      dumper_ = makePcapDumperHandle(rawDumper);
    } else {
      emit captureError(QString("Error opening dump file: %1")
                            .arg(pcap_geterr(handle_.get())));
    }
  }

  capturing_.store(true);
  pcap_loop(handle_.get(), 0, packetCallback,
            reinterpret_cast<unsigned char *>(this));

  dumper_.reset();
  handle_.reset();
  capturing_.store(false);
  emit captureFinished();
}

void PcapCaptureWorker::requestStop() {
  if (capturing_.load() && handle_) {
    capturing_.store(false);
    pcap_breakloop(handle_.get());
  }
}

void PcapCaptureWorker::packetCallback(unsigned char *userData,
                                       const struct pcap_pkthdr *pkthdr,
                                       const unsigned char *packet) {
  auto *self = reinterpret_cast<PcapCaptureWorker *>(userData);
  self->processPacket(pkthdr, packet);
}

void PcapCaptureWorker::processPacket(const struct pcap_pkthdr *pkthdr,
                                      const unsigned char *packet) {
  using namespace nids::platform;

  nids::core::PacketInfo info;

  auto *ethHeader = reinterpret_cast<const EthernetHeader *>(packet);
  if (getEtherType(ethHeader) == kEtherTypeIPv4) {
    auto *ipHeader = reinterpret_cast<const IPv4Header *>(
        packet + kEthernetHeaderSize); // NOSONAR
    info.ipSource = getIpSrcStr(ipHeader);
    info.ipDestination = getIpDstStr(ipHeader);

    auto proto = getIpProtocol(ipHeader);
    auto ipHeaderLen = getIpIhl(ipHeader);

    // Validate IP header length (minimum 20 bytes, must fit in captured packet)
    if (ipHeaderLen < 20 ||
        (kEthernetHeaderSize + ipHeaderLen) > pkthdr->caplen) {
      info.protocol = "Malformed";
    } else if (proto == kIpProtoTcp) {
      auto *tcpHeader = reinterpret_cast<const TcpHeader *>( // NOSONAR
          reinterpret_cast<const std::uint8_t *>(ipHeader) +
          ipHeaderLen); // NOSONAR
      info.protocol = "TCP";
      info.portSource = std::to_string(getTcpSrcPort(tcpHeader));
      info.portDestination = std::to_string(getTcpDstPort(tcpHeader));
      info.application =
          serviceRegistry_.resolveApplication("", "", info.portDestination);
    } else if (proto == kIpProtoUdp) {
      auto *udpHeader = reinterpret_cast<const UdpHeader *>( // NOSONAR
          reinterpret_cast<const std::uint8_t *>(ipHeader) +
          ipHeaderLen); // NOSONAR
      info.protocol = "UDP";
      info.portSource = std::to_string(getUdpSrcPort(udpHeader));
      info.portDestination = std::to_string(getUdpDstPort(udpHeader));
      info.application =
          serviceRegistry_.resolveApplication("", "", info.portDestination);
    } else if (proto == kIpProtoIcmp) {
      info.protocol = "ICMP";
    } else {
      info.protocol = "Unknown";
    }
  }

  info.rawData.assign(packet, packet + pkthdr->len);

  if (dumper_) {
    pcap_dump(reinterpret_cast<unsigned char *>(dumper_.get()), pkthdr,
              packet); // NOSONAR
  }

  emit packetCaptured(info);
}

// --- PcapCapture ---

PcapCapture::PcapCapture(QObject *parent)
    : QObject(parent), worker_(new PcapCaptureWorker()) {
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

bool PcapCapture::initialize(const std::string &interface,
                             const std::string &bpfFilter) {
  interface_ = interface;
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

std::vector<std::string> PcapCapture::listInterfaces() {
  std::vector<std::string> result;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *interfaces = nullptr;

  if (pcap_findalldevs(&interfaces, errbuf) == -1) {
    return result;
  }

  for (auto *iface = interfaces; iface; iface = iface->next) {
    result.emplace_back(iface->name);
  }

  pcap_freealldevs(interfaces);
  return result;
}

} // namespace nids::infra
