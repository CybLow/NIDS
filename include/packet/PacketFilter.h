//
// Created by sku on 22/01/2024.
//

#ifndef NIDS_PACKETFILTER_H
#define NIDS_PACKETFILTER_H

#include <string>

using namespace std;

struct PacketFilter {
    string networkCard;
    string protocol;
    string application;
    string sourceIP;
    string destinationIP;
    string sourcePort;
    string destinationPort;

    PacketFilter() = default;

    PacketFilter(const string& netCard, const string& proto, const string& app,
               const string& srcIP, const string& destIP,
               const string& srcPort, const string& destPort)
            : networkCard(netCard), protocol(proto), application(app),
              sourceIP(srcIP), destinationIP(destIP),
              sourcePort(srcPort), destinationPort(destPort) {}
};


#endif //NIDS_PACKETFILTER_H
