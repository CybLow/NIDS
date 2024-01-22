#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <QThread>
#include <pcap.h>
#include <string>
#include <atomic>
#include <functional>
#include "PacketInfo.h"
#include "PacketCaptureNotifier.h"

class PacketCapture : public QThread {
Q_OBJECT

public:
    explicit PacketCapture(const std::string& interface, QObject *parent = nullptr);
    ~PacketCapture() override;

    bool Initialize();
    void StopCapture();
    void startPcapDump(const std::string& filename);
    void dumpPacket(const struct pcap_pkthdr* header, const u_char* packet);
    void stopPcapDump();
    using PacketInfoCallback = std::function<void(const PacketInfo&)>;
    PacketCaptureNotifier notifier_;

protected:
    void run() override;

private:
    static void PacketCallback(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void ProcessPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);

    std::string interface_;
    pcap_dumper_t* dumper_; // Pcap dumper
    std::string dumpFile_; // Path to the dump file
    pcap_t* handle_;
    std::atomic<bool> capturing;

    PacketInfoCallback packetInfoCallback_;
};

#endif // PACKET_CAPTURE_H
