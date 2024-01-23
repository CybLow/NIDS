#ifndef PACKET_INFO_H
#define PACKET_INFO_H

#include <netinet/ip.h>
#include <string>
#include <QString>
#include <map>
#include <set>
#include <vector>

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

    vector<u_char> rawData;
};

//
// BUG : IF APPLICATION ARE CHOOSED IN APPLICATION LIST
// THE FILTER WILL TAKE IN COUNT THIS
// NOW : ONLY WORK WITH SOURCE AND DESTINATION PORT (FOR APPLICATION)

#endif // PACKET_INFO_H
