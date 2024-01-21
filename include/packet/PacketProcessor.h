#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include "PacketInfo.h"

class PacketProcessor {
public:
    void ProcessPacket(PacketInfo& packet);
};

#endif // PACKET_PROCESSOR_H
