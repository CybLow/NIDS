#include <qobjectdefs.h>
#include <QObject>
#include "../../include/packet/PacketInfo.h"
#include "../../include/packet/PacketSignalEmitter.h"

//
// Created by sim on 21/01/24.
//
class PacketSignalEmitter : public QObject {
    Q_OBJECT
public:
    void emitPacketCaptured(const PacketInfo& info)(
        emit packetCaptured(info)
        );

signals:
    void packetCaptured(const PacketInfo& info);

};

#include "PacketSignalEmitter.moc"