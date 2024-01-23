#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <QThread>
#include <pcap.h>
#include <string>
#include <atomic>
#include <functional>

#include "PacketFilter.h"
#include "PacketInfo.h"
#include "PacketCaptureNotifier.h"

using namespace std;

class PacketCapture : public QThread {
Q_OBJECT

public:
    explicit PacketCapture(const string& interface, const string& filterStr, QObject *parent = nullptr);
    ~PacketCapture() override;

    bool Initialize();
    void StopCapture();
    void startPcapDump(const string& filename);
    void dumpPacket(const struct pcap_pkthdr* header, const u_char* packet);
    void stopPcapDump();
    using PacketInfoCallback = function<void(const PacketInfo&)>;
    PacketCaptureNotifier notifier_;

    void setPcapFilter();

protected:
    void run() override;

private:
    static void PacketCallback(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void ProcessPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);

    string interface_;
    pcap_dumper_t* dumper_; // Pcap dumper
    string dumpFile_; // Path to the dump file
    pcap_t* handle_;
    atomic<bool> capturing;

    PacketInfoCallback packetInfoCallback_;
    PacketFilter filterData;

    string filterString_;

    string getApplicationNameByPort(PacketInfo &packetInfo);
};

#endif // PACKET_CAPTURE_H
