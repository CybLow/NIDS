//
// Created by sim on 21/01/24.
//

#ifndef PACKET_CAPTURE_UI_H
#define PACKET_CAPTURE_UI_H

#include <QMainWindow>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QHeaderView>
#include <QComboBox>
#include <QTableWidget>
#include <QMessageBox>
#include <QFrame>
#include <QMenuBar>
#include <QInputDialog>
#include <QRegularExpressionValidator>
#include <vector>
#include <string>

#include "../packet/PacketCapture.h"
#include "../packet/PacketInfo.h"

class PacketCaptureUI : public QMainWindow {
Q_OBJECT

public:
    explicit PacketCaptureUI(QWidget *parent = nullptr);
    ~PacketCaptureUI();

private:
    void setupUi();
    void connectSignalsSlots();
    void populateNetworkCardComboBox();
    void configureValidators();

    // UI Components
    QLineEdit *sourceNetworkEdit, *sourcePortEdit, *destinationNetworkEdit, *destinationPortEdit, *messageTextEdit;
    QPushButton *startStopButton;
    QLabel *networkCardLabel, *protocolLabel, *applicationLabel, *sourceNetworkLabel, *sourcePortLabel, *destinationNetworkLabel, *destinationPortLabel, *messageTextLabel;

    QComboBox *networkCardComboBox, *protocolComboBox, *applicationComboBox;
    QTableWidget *packetTable;
    QAction *securityAction, *notificationAction;

    // Validators
    QRegularExpressionValidator *ipValidator, *portValidator;

    // Additional members
    std::vector<std::string> networkInterfaces;
    bool emailNotificationEnabled;
    bool windowsNotificationEnabled;
    bool securityEnabled;

    PacketCapture* packetCaptureInstance;
    QRegularExpression ipRegex;
    QRegularExpression portRegex;

    /*struct PacketInfo {
        QString networkCard;
        QString protocol;
        QString application;
        QString ipSource;
        QString portSource;
        QString ipDestination;
        QString portDestination;
    };*/

public slots:
    void updatePacketTable(const PacketInfo &info);

private slots:
    void toggleCapture();
    //void updatePacketTable(const PacketInfo& info);
    void securitySettings();
    void notificationSettings();
    void sendEmailPrompt();
    void populateProtocolComboBox();
    void populateApplicationComboBox();
    void validateInputs();
    //void onTestButtonClicked();
    void setupPacketCapture();

    //void updatePacketTable(const PacketInfo &info);
};



#endif // PACKET_CAPTURE_UI_H
