#include <pcap.h>
#include <iostream>

//fhzuyhgfzeui
void packetHandler(unsigned char* userData, const struct pcap_pkthdr* pkthdr, const unsigned char* packetData) {
    // Traitez ici les données de la trame
    std::cout << "Capture d'une trame de taille : " << pkthdr->len << " octets" << std::endl;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Ouvrir une interface de capture
    pcap_t* handle = pcap_open_live("your_network_interface", 65536, 1, 1000, errbuf);

    if (handle == nullptr) {
        std::cerr << "Erreur lors de l'ouverture de l'interface: " << errbuf << std::endl;
        return -1;
    }

    // Capturer les paquets en utilisant le callback packetHandler
    pcap_loop(handle, 0, packetHandler, nullptr);

    // Fermer l'interface de capture
    pcap_close(handle);

    return 0;
}
