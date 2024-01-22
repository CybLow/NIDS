#include "../../include/packet/PacketCapture.h"
#include <iostream>
#include <netinet/ip.h>        // For IP header
#include <netinet/tcp.h>       // For TCP header
#include <netinet/udp.h>       // For UDP header
#include <arpa/inet.h>         // For inet_ntoa
#include <netinet/if_ether.h>  // For ether_header and ETHERTYPE_IP

PacketCapture::PacketCapture(const std::string& interface, QObject *parent)
        : QThread(parent), interface_(interface), handle_(nullptr), capturing(false) {}

PacketCapture::~PacketCapture() {
    StopCapture();
}

bool PacketCapture::Initialize() {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live(interface_.c_str(), BUFSIZ, 1, 1000, errbuf);
    return handle_ != nullptr;
}

void PacketCapture::run() {
    if (!Initialize()) {
        std::cerr << "Failed to initialize packet capture." << std::endl;
        return;
    }

    capturing.store(true);
    std::cout << "Starting packet capture on " << interface_ << "..." << std::endl;
    startPcapDump("dump.pcap");
    pcap_loop(handle_, 0, PacketCallback, reinterpret_cast<u_char*>(this));

}

void PacketCapture::StopCapture() {
    if (!capturing.load()) return;

    capturing.store(false);
    pcap_breakloop(handle_);

    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
    stopPcapDump();
    std::cout << "Capture stopped." << std::endl;
}

void PacketCapture::PacketCallback(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketCapture* capture = reinterpret_cast<PacketCapture*>(userData);
    capture->ProcessPacket(pkthdr, packet);
}

void PacketCapture::ProcessPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketInfo packetInfo;

    // Parse Ethernet header
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    const struct udphdr* udpHeader;

    // Assuming Ethernet + IPv4 packets
    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        packetInfo.ipSource = inet_ntoa(ipHeader->ip_src);
        packetInfo.ipDestination = inet_ntoa(ipHeader->ip_dst);

        // Check protocol and parse accordingly
        if (ipHeader->ip_p == IPPROTO_TCP) {
            tcpHeader = (tcphdr*)((u_char*)ipHeader + sizeof(struct ip));
            packetInfo.protocol = "TCP";
            packetInfo.portSource = std::to_string(ntohs(tcpHeader->th_sport));
            packetInfo.portDestination = std::to_string(ntohs(tcpHeader->th_dport));

            // Determine application based on port or other criteria
        } else if (ipHeader->ip_p == IPPROTO_UDP) {
            udpHeader = (udphdr*)((u_char*)ipHeader + sizeof(struct ip));
            packetInfo.protocol = "UDP";
            packetInfo.portSource = std::to_string(ntohs(udpHeader->uh_sport));
            packetInfo.portDestination = std::to_string(ntohs(udpHeader->uh_dport));

            // Determine application based on port or other criteria
        } else if (ipHeader->ip_p == IPPROTO_ICMP) {
            packetInfo.protocol = "ICMP";
            // ICMP doesn't have ports
        } else {
            packetInfo.protocol = "Unknown";
            // Other protocols such as IGMP and others
        }
        // Additional protocol parsing as necessary
    }

    // Process packetInfo further as needed
    cout << "Capture: " << packetInfo.protocol << " from " << packetInfo.ipSource << ":" << packetInfo.portDestination <<
    " to " << packetInfo.ipDestination << ":" << packetInfo.portDestination << endl;
    dumpPacket(pkthdr,packet);
    notifier_.emitPacketReceived(packetInfo);
}

// Start dumping packets to a file
void PacketCapture::startPcapDump(const std::string& filename) {
    dumpFile_ = filename;
    dumper_ = pcap_dump_open(handle_, dumpFile_.c_str());

    if (dumper_ == nullptr) {
        std::cerr << "Error opening dump file: " << pcap_geterr(handle_) << std::endl;
        return;
    }

    // Other initializations if necessary
}

// This function should be called every time a packet is captured
void PacketCapture::dumpPacket(const struct pcap_pkthdr* header, const u_char* packet) {
    if (dumper_ != nullptr) {
        pcap_dump((unsigned char*)dumper_, header, packet);
    }
}

// Stop dumping packets and close the file
void PacketCapture::stopPcapDump() {
    if (dumper_ != nullptr) {
        pcap_dump_close(dumper_);
        dumper_ = nullptr;
    }
}

#include "../../include/packet/PacketCapture.moc"