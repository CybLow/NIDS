//
// Created by sim on 21/01/24.
//
/*
#ifndef UI_H
#define UI_H
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


class PacketCaptureUI : public QMainWindow {
    Q_OBJECT  // Essential for Qt's meta-object system

public:
    explicit PacketCaptureUI(QWidget *parent = nullptr) : QMainWindow(parent) {}
    // Member function to populate the network card combo box
    void populateNetworkCardComboBox();

    // Add other public member functions and properties as needed

private:
    QLineEdit* lineEdit;          // Example of a line edit
    QPushButton* pushButton;      // Example of a push button
    QLabel* label;                // Example of a label
    QVBoxLayout* vBoxLayout;      // Example of a vertical box layout
    QHeaderView* headerView;      // Example of a header view
    QComboBox* comboBox;          // Example of a combo box
    QTableWidget* tableWidget;    // Example of a table widget
    QMessageBox* messageBox;      // Example of a message box
    QFrame* frame;                // Example of a frame
    QMenuBar* menuBar;            // Example of a menu bar
    QInputDialog* inputDialog;    // Example of an input dialog

    std::vector<std::string> networkInterfaces; // Stores network interfaces

    // Add other private member functions, variables, and helper functions as needed
};

#endif //UI_H
*/

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

private slots:
    void toggleCapture();
    void updatePacketTable(double info);
    void securitySettings();
    void notificationSettings();
    void sendEmailPrompt();
    void populateProtocolComboBox();
    void populateApplicationComboBox();
    void validateInputs();
};


#endif // PACKET_CAPTURE_UI_H
