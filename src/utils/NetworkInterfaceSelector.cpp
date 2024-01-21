#include "../../include/utils/NetworkInterfaceSelector.h"
#include <iostream>
#include <pcap.h>
#include <cstring>

// Stock the list of interfaces in enum for the GUI

string NetworkInterfaceSelector::SelectInterface() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* interfaces;
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        throw runtime_error("Error finding network interfaces: " + string(errbuf));
    }

    int index = 0;
    for (pcap_if_t* iface = interfaces; iface != nullptr; iface = iface->next) {
        // Exclure certaines interfaces spécifiques
        if (strstr(iface->name, "bluetooth") == nullptr &&
            //strstr(iface->name, "lo") == nullptr &&
            //strstr(iface->name, "nflog") == nullptr &&
            strstr(iface->name, "nfqueue") == nullptr &&
            strstr(iface->name, "dbus") == nullptr) {
            cout << index << ": " << iface->name;
            if (iface->description) {
                cout << " (" << iface->description << ")";
            }
            cout << endl;
            index++;
        }
    }

    int selected;
    cout << "Enter the index of the interface to use for capture: ";
    cin >> selected;

    pcap_if_t* selectedInterface = interfaces;
    for (int i = 0; i < selected; selectedInterface = selectedInterface->next) {
        if (strstr(selectedInterface->name, "bluetooth") == nullptr &&
            //strstr(selectedInterface->name, "lo") == nullptr &&
            //strstr(selectedInterface->name, "nflog") == nullptr &&
            strstr(selectedInterface->name, "nfqueue") == nullptr &&
            strstr(selectedInterface->name, "dbus") == nullptr) {
            if (i++ == selected) break;
        }
    }

    if (!selectedInterface) {
        throw runtime_error("Selected interface not found.");
    }

    string interfaceName = selectedInterface->name;
    pcap_freealldevs(interfaces);
    return interfaceName;
}
