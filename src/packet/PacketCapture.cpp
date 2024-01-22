#include "../../include/packet/PacketCapture.h"
#include "../../include/packet/PacketProcessor.h"

#include <iostream>
#include <qobjectdefs.h>
#include <utility>


PacketCapture::PacketCapture(string  interface)
        : interface_(move(interface)), handle_(nullptr), capturing(false) {}


PacketCapture::~PacketCapture() {
    StopCapture();
}


bool PacketCapture::Initialize() {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live(interface_.c_str(), BUFSIZ, 1, 1000, errbuf);
    return handle_ != nullptr;
}


void PacketCapture::StartCapture() {
    if (!handle_) {
        std::cerr << "Capture handle not initialized." << std::endl;
        return;
    }

    capturing.store(true, std::memory_order_relaxed);
    captureThread = std::thread([this] {
        std::cout << "Starting packet capture on " << interface_ << "..." << std::endl;
        pcap_loop(handle_, 0, PacketCallback, reinterpret_cast<u_char*>(this));
        std::cout << "Capture thread ending." << std::endl;
    });

}


void PacketCapture::StopCapture() {
    capturing.store(false, std::memory_order_relaxed);
    pcap_breakloop(handle_); // Interrompre pcap_loop

    if (captureThread.joinable()) {
        captureThread.join();
    }
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
    std::cout << "Capture stopped." << std::endl;
}


void PacketCapture::PacketCallback(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketCapture* capture = reinterpret_cast<PacketCapture*>(userData);
    capture->ProcessPacket(pkthdr, packet);
}

void PacketCapture::ProcessPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet) {


    PacketProcessor processor;
    PacketInfo packetInfo;
    cout << "Capture.." << endl;
    // Ici, vous traiteriez le paquet
    //processor.ProcessPacket(&packet); // Mettez à jour selon votre logique de traitement de paquet
    //packetBuffer_.push_back();
}
