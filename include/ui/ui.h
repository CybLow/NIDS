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
#include <QSystemTrayIcon>
#include <QApplication>
#include <QRegularExpressionValidator>
#include <vector>
#include <string>
#include <QScrollArea>

#include "../packet/PacketCapture.h"
#include "../packet/PacketInfo.h"
#include "../packet/PacketFilter.h"
#include "HexAsciiDisplay.h"

using namespace std;

class PacketCaptureUI : public QMainWindow {
Q_OBJECT

public:
    explicit PacketCaptureUI(QWidget *parent = nullptr);
    ~PacketCaptureUI();

private:
    void setupUi();
    void connectSignalsSlots();
    void populateNetworkCardComboBox();

    QScrollArea* scrollArea;  // Member variable for the scroll area
    HexAsciiDisplay* hexAsciiDisplay;

    // UI Components
    QLineEdit *sourceNetworkEdit, *sourcePortEdit, *destinationNetworkEdit, *destinationPortEdit, *filterTextEdit;
    QPushButton *startStopButton;
    QLabel *networkCardLabel, *protocolLabel, *applicationLabel, *sourceNetworkLabel, *sourcePortLabel, *destinationNetworkLabel, *destinationPortLabel, *filterTextLabel;

    QComboBox *networkCardComboBox, *protocolComboBox, *applicationComboBox;
    QTableWidget *packetTable;
    QAction *securityAction, *notificationAction;

    // Validators
    QRegularExpressionValidator *ipValidator, *portValidator;

    // Additional members
    vector<string> networkInterfaces;
    bool emailNotificationEnabled;
    bool notificationEnabled;
    bool securityEnabled;

    PacketCapture* packetCaptureInstance;
    QRegularExpression ipRegex;
    QRegularExpression portRegex;

    QString lastCustomService;
    QString lastAddedService;

    PacketFilter currentPacketData;

    QSystemTrayIcon *systemTrayIcon;
    vector<PacketInfo> packetInfoList;

public slots:
    void updatePacketTable(const PacketInfo &info);

private slots:
    void toggleCapture();
    void securitySettings();
    void notificationSettings();
    void sendEmailPrompt();
    void populateProtocolComboBox();
    void populateApplicationComboBox();
    void validateInputs();
    void setupPacketCapture();
    void onApplicationComboBoxChanged(int index);

    void updateApplicationComboBoxBasedOnPort();

    PacketFilter gatherPacketData();

    void generateReport();

    void displaySelectedPacketRawData();

    void addPacketToTable(const PacketInfo &packetInfo);

    void ensureScrollAreaVisibility();
};



#endif // PACKET_CAPTURE_UI_H
