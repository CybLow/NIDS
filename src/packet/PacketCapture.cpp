#include "../../include/packet/PacketCapture.h"

#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

PacketCapture::PacketCapture(const string& interface, const string& filterStr, QObject *parent)
        : QThread(parent), interface_(interface), filterString_(filterStr), handle_(nullptr), capturing(false) {}


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
        cerr << "Failed to initialize packet capture." << endl;
        return;
    }

    capturing.store(true);
    cout << "Starting packet capture on " << interface_ << "..." << endl;

    setPcapFilter();

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
    cout << "Capture stopped." << endl;
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
            packetInfo.portSource = to_string(ntohs(tcpHeader->th_sport));
            packetInfo.portDestination = to_string(ntohs(tcpHeader->th_dport));
            packetInfo.application = getApplicationNameByPort(packetInfo);

            // Determine application based on port or other criteria
        } else if (ipHeader->ip_p == IPPROTO_UDP) {
            udpHeader = (udphdr*)((u_char*)ipHeader + sizeof(struct ip));
            packetInfo.protocol = "UDP";
            packetInfo.portSource = to_string(ntohs(udpHeader->uh_sport));
            packetInfo.portDestination = to_string(ntohs(udpHeader->uh_dport));
            packetInfo.application = getApplicationNameByPort(packetInfo);

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

    packetInfo.rawData.assign(packet, packet + pkthdr->len);

    cout << "Capture: " << packetInfo.protocol << " from " << packetInfo.ipSource << ":" << packetInfo.portDestination <<
    " to " << packetInfo.ipDestination << ":" << packetInfo.portDestination << endl;
    dumpPacket(pkthdr,packet);
    notifier_.emitPacketReceived(packetInfo);
}

string PacketCapture::getApplicationNameByPort(PacketInfo& packetInfo) {
    string applicationName;

    if (!filterData.destinationPort.empty()) {
        applicationName = getServiceNameByPort(stoi(filterData.destinationPort));
    } else if (!filterData.sourcePort.empty()) {
        applicationName = getServiceNameByPort(stoi(filterData.sourcePort));
    } else {
        // If both are defined, prioritize destination port
        applicationName = getServiceNameByPort(stoi(packetInfo.portDestination));
    }
    return applicationName;
}

void PacketCapture::setPcapFilter() {

    struct bpf_program fp;
    if (!filterString_.empty() && pcap_compile(handle_, &fp, filterString_.c_str(), 0, PCAP_NETMASK_UNKNOWN) != -1) {
        if (pcap_setfilter(handle_, &fp) != -1) {
            cout << "Filter set: " << filterString_ << endl; // Use member variable filterString_
        } else {
            cerr << "Could not install filter: " << pcap_geterr(handle_) << endl;
        }
        pcap_freecode(&fp);
    } else {
        cerr << "Could not parse filter: " << pcap_geterr(handle_) << endl;
    }
}

// Start dumping packets to a file
void PacketCapture::startPcapDump(const string& filename) {
    dumpFile_ = filename;
    dumper_ = pcap_dump_open(handle_, dumpFile_.c_str());

    if (dumper_ == nullptr) {
        cerr << "Error opening dump file: " << pcap_geterr(handle_) << endl;
        return;
    }

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