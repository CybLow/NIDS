#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include "../../src/packet/PacketSignalEmitter.cpp"
#include "PacketInfo.h"
#include "PacketCaptureNotifier.h"

#include <pcap.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <iostream>
#include <functional>


using namespace std;

class PacketCapture {
public:
    explicit PacketCapture(string interface);
    bool Initialize();
    void StartCapture();
    void StopCapture();
    ~PacketCapture();

    using PacketInfoCallback = std::function<void(const PacketInfo&)>;
    void setPacketInfoCallback(const PacketInfoCallback& callback);

    PacketCaptureNotifier notifier_;

private:
    static void PacketCallback(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void ProcessPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);
    string interface_;
    pcap_t* handle_;

    thread captureThread;
    atomic<bool> capturing;

    vector<PacketInfo> packetBuffer_;
    PacketInfoCallback packetInfoCallback_;
};

#endif // PACKET_CAPTURE_H
