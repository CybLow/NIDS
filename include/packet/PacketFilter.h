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

    string generatePcapFilterString() const;
};


#endif //NIDS_PACKETFILTER_H
