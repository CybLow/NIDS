//
// Created by sim on 21/01/24.
//
#include <pcap.h>
#include <iostream>
#include <string>
#include "../../include/utils/ListNetworkInterfaces.h"

std::vector<std::string> ListNetworkInterfaces::listInterfaces() {
    std::vector<std::string> interfacesList;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *temp;
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        std::cerr << "Error finding interfaces: " << errbuf << std::endl;
        return interfacesList;
    }

    for (temp = interfaces; temp; temp = temp->next) {
        interfacesList.push_back(temp->name);
    }

    pcap_freealldevs(interfaces);
    return interfacesList;
}