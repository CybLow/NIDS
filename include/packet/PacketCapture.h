#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include "PacketInfo.h"
#include <pcap.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
//#include <ndpi/ndpi_api.h>

using namespace std;

class PacketCapture {
public:
    explicit PacketCapture(string  interface);
    bool Initialize();
    void StartCapture();
    void StopCapture();
    ~PacketCapture();

private:
    static void PacketCallback(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void ProcessPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);
    string interface_;
    pcap_t* handle_;

    thread captureThread;
    atomic<bool> capturing;

    vector<PacketInfo> packetBuffer_;
};

#endif // PACKET_CAPTURE_H
