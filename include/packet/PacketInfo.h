#ifndef PACKET_INFO_H
#define PACKET_INFO_H

#include <netinet/ip.h>
#include <string>

struct PacketInfo {
    struct ip* ipHeader;
    const u_char* payload;
    int payloadLength;
    int protocol;
    std::string sourceApp; // Nom de l'application source (SSH, Apache, etc.)
};


#endif // PACKET_INFO_H
