//
// Created by sku on 22/01/2024.
//

#include "include/packet/PacketFilter.h"

string PacketFilter::generatePcapFilterString() const {
    string filterStr;
    if (!customBPFFilter.empty()) {
        filterStr = customBPFFilter;
    } else {
        if (!protocol.empty() && protocol != "ALL" && protocol != "Unknown") {
            filterStr += "proto " + protocol;
        }
        if (!sourceIP.empty()) {
            if (!filterStr.empty()) filterStr += " and ";
            filterStr += "src host " + sourceIP;
        }
        if (!destinationIP.empty()) {
            if (!filterStr.empty()) filterStr += " and ";
            filterStr += "dst host " + destinationIP;
        }
        if (!sourcePort.empty()) {
            if (!filterStr.empty()) filterStr += " and ";
            filterStr += "src port " + sourcePort;
        }
        if (!destinationPort.empty()) {
            if (!filterStr.empty()) filterStr += " and ";
            filterStr += "dst port " + destinationPort;
        }
    }

    return filterStr;
}
