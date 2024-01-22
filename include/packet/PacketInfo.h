#ifndef PACKET_INFO_H
#define PACKET_INFO_H

#include <netinet/ip.h>
#include <string>
#include <QString>

using namespace std;


struct PacketInfo {
    string protocol;
    string application;
    string ipSource;
    string portSource;
    string ipDestination;
    string portDestination;
};

#endif // PACKET_INFO_H
