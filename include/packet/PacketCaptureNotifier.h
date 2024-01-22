// PacketCaptureNotifier.h
#ifndef PACKETCAPTURENOTIFIER_H
#define PACKETCAPTURENOTIFIER_H

#include <QObject>
#include <QDebug>
#include "PacketInfo.h" // Include your PacketInfo definition

class PacketCaptureNotifier : public QObject {
Q_OBJECT

public:
    void emitPacketReceived(const PacketInfo& packetInfo) {
        qDebug() << "Emitting packet signal with info:" << packetInfo.ipSource.c_str();
        emit packetReceived(packetInfo);
    }

signals:
    void packetReceived(const PacketInfo& packetInfo);
};

#endif // PACKETCAPTURENOTIFIER_H
