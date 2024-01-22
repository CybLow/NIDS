#ifndef PACKET_INFO_H
#define PACKET_INFO_H

#include <netinet/ip.h>
#include <string>
#include <QString>
#include <map>
#include <set>

using namespace std;

extern const map<int, string> portToServiceMap;

set<string> getUniqueServices();

string getServiceNameByPort(int port);

struct PacketInfo {
    string protocol;
    string application;
    string ipSource;
    string portSource;
    string ipDestination;
    string portDestination;
};

//
//entre un port de filtre choisi automatiquement l'appli
//si le port est inconnu noté Unknow

#endif // PACKET_INFO_H
