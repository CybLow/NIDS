#include "../../include/utils/ListNetworkInterfaces.h"
#include "../../include/packet/PacketCapture.h"
#include "include/ui/ui.h"

#include <QRegularExpression>
#include <QGridLayout>
#include <QAction>
#include <QMenu>
#include <QApplication>
#include <QMainWindow>
#include <QLineEdit>
#include <QDebug>
#include <iostream>


PacketCaptureUI::PacketCaptureUI(QWidget *parent)
        : QMainWindow(parent),
          emailNotificationEnabled(false),
          windowsNotificationEnabled(false),
          securityEnabled(false) {
    setupUi();
    connectSignalsSlots();
    packetCaptureInstance = nullptr;

    QString selectedInterface = networkCardComboBox->currentText();
    packetCaptureInstance = new PacketCapture(string (selectedInterface.toStdString()));
    connect(&(packetCaptureInstance->notifier_), &PacketCaptureNotifier::packetReceived,
            this, &PacketCaptureUI::updatePacketTable, Qt::DirectConnection);

}

PacketCaptureUI::~PacketCaptureUI() {
    // Cleanup if necessary
    if (packetCaptureInstance) {
        packetCaptureInstance->StopCapture(); // Ensure capture is stopped
        delete packetCaptureInstance; // Delete the instance
    }
}

void PacketCaptureUI::setupUi() {
    // Labels
    networkCardLabel = new QLabel("Network Card", this);
    protocolLabel = new QLabel("Protocol", this);
    applicationLabel = new QLabel("Application", this);
    sourceNetworkLabel = new QLabel("IP Source", this);
    sourcePortLabel = new QLabel("Port Source", this);
    destinationNetworkLabel = new QLabel("IP Destination", this);
    destinationPortLabel = new QLabel("Port Destination", this);
    messageTextLabel = new QLabel("Custom Filter", this);

    // Edit lines
    sourceNetworkEdit = new QLineEdit(this);
    sourcePortEdit = new QLineEdit(this);
    destinationNetworkEdit = new QLineEdit(this);
    destinationPortEdit = new QLineEdit(this);
    messageTextEdit = new QLineEdit(this);

    // Combo boxes
    networkCardComboBox = new QComboBox(this);
    protocolComboBox = new QComboBox(this);
    applicationComboBox = new QComboBox(this);

    // Buttons
    startStopButton = new QPushButton("Start", this);
    startStopButton->setEnabled(false);


    // Table
    packetTable = new QTableWidget(this);
    packetTable->setColumnCount(8);
    QStringList tableHeader{"Number", "Network Card", "Protocol", "Application", "IP Source", "Port Source", "IP Destination", "Port Destination"};
    packetTable->setHorizontalHeaderLabels(tableHeader);
    packetTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    packetTable->verticalHeader()->setVisible(false);
    packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetTable->setSelectionMode(QAbstractItemView::SingleSelection);

    // Validators
    ipRegex = QRegularExpression("^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$");
    ipValidator = new QRegularExpressionValidator(ipRegex, this);
    portRegex = QRegularExpression("^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$");
    portValidator = new QRegularExpressionValidator(portRegex, this);

    sourceNetworkEdit->setFocusPolicy(Qt::StrongFocus);
    sourcePortEdit->setFocusPolicy(Qt::StrongFocus);
    destinationNetworkEdit->setFocusPolicy(Qt::StrongFocus);
    destinationPortEdit->setFocusPolicy(Qt::StrongFocus);

    sourceNetworkEdit->setMinimumSize(QSize(100, 20));
    sourcePortEdit->setMinimumSize(QSize(100, 20));
    destinationNetworkEdit->setMinimumSize(QSize(100, 20));
    destinationPortEdit->setMinimumSize(QSize(100, 20));

    // BUG : CETTE FONCTION EST SPAMMER DEUX FOIS A CHAQUE FOIS QU'ON CHANGE LE TEXTE
    validateInputs();


    // Actions
    securityAction = new QAction("Security", this);
    notificationAction = new QAction("Notification", this);
    menuBar()->addAction(securityAction);
    menuBar()->addAction(notificationAction);

    // Layout
    auto *gridLayout = new QGridLayout();
    gridLayout->addWidget(networkCardLabel, 0, 0);
    gridLayout->addWidget(networkCardComboBox, 1, 0);
    gridLayout->addWidget(protocolLabel, 0, 1);
    gridLayout->addWidget(protocolComboBox, 1, 1);
    gridLayout->addWidget(applicationLabel, 0, 2);
    gridLayout->addWidget(applicationComboBox, 1, 2);
    gridLayout->addWidget(sourceNetworkLabel, 0, 3);
    gridLayout->addWidget(sourceNetworkEdit, 1, 3);
    gridLayout->addWidget(sourcePortLabel, 0, 4);
    gridLayout->addWidget(sourcePortEdit, 1, 4);
    gridLayout->addWidget(destinationNetworkLabel, 0, 5);
    gridLayout->addWidget(destinationNetworkEdit, 1, 5);
    gridLayout->addWidget(destinationPortLabel, 0, 6);
    gridLayout->addWidget(destinationPortEdit, 1, 6);
    gridLayout->addWidget(messageTextLabel, 2, 0);
    gridLayout->addWidget(messageTextEdit, 2, 1, 1, 6);
    gridLayout->addWidget(startStopButton, 2, 7);
    gridLayout->addWidget(packetTable, 3, 0, 1, 8);

    auto *centralWidget = new QWidget(this);
    centralWidget->setLayout(gridLayout);
    setCentralWidget(centralWidget);

    // Set Protocol and Application ComboBoxes
    populateProtocolComboBox();
    populateApplicationComboBox();

    // Set Window Properties
    setWindowTitle("Packet Capture Interface");
    resize(1500, 400);

    // Populate Network Card ComboBox
    populateNetworkCardComboBox();
    setupPacketCapture();
}

void PacketCaptureUI::connectSignalsSlots() {
    // Connections between signals and slots
    connect(securityAction, &QAction::triggered, this, &PacketCaptureUI::securitySettings);
    connect(notificationAction, &QAction::triggered, this, &PacketCaptureUI::notificationSettings);

    if (this == nullptr) {
        qDebug() << "PacketCaptureUI instance is nullptr";
    }

    connect(startStopButton, &QPushButton::clicked, this, &PacketCaptureUI::toggleCapture);

    connect(sourceNetworkEdit, &QLineEdit::textChanged, this, &PacketCaptureUI::validateInputs);
    connect(sourcePortEdit, &QLineEdit::textChanged, this, &PacketCaptureUI::validateInputs);
    connect(destinationNetworkEdit, &QLineEdit::textChanged, this, &PacketCaptureUI::validateInputs);
    connect(destinationPortEdit, &QLineEdit::textChanged, this, &PacketCaptureUI::validateInputs);

    //connect(startStopButton, &QPushButton::clicked, this, &PacketCaptureUI::onTestButtonClicked);
    //connect(packetTable, &QTableWidget::itemSelectionChanged, this, &PacketCaptureUI::onTableSelectionChanged);
}

void PacketCaptureUI::populateNetworkCardComboBox() {
    networkInterfaces = ListNetworkInterfaces::listInterfaces();
    for (const std::string& interface : networkInterfaces) {
        networkCardComboBox->addItem(QString::fromStdString(interface));
    }
}

void PacketCaptureUI::toggleCapture() {
    if (!packetCaptureInstance) {
        // Start capturing
        packetCaptureInstance = new PacketCapture(networkCardComboBox->currentText().toStdString());
        // NEED TO PUT THIS VALUE IN THE PACKETINFO NETWORKCARD
        startStopButton->setText("Stop");
        packetCaptureInstance->Initialize();
        packetCaptureInstance->StartCapture();


        // Disable input fields
        sourceNetworkEdit->setReadOnly(true);
        sourcePortEdit->setReadOnly(true);
        // Similarly for destination fields
    } else {
        // Stop capturing
        packetCaptureInstance->StopCapture();
        startStopButton->setText("Start");

        // Re-enable input fields
        sourceNetworkEdit->setReadOnly(false);
        sourcePortEdit->setReadOnly(false);


        int ret = QMessageBox::question(this, "Filtering Report",
                                        "Do you need a filtering report?",
                                        QMessageBox::Yes | QMessageBox::No);
        if (ret == QMessageBox::Yes) {
            // Implement the logic to generate the report here
            //generateReport(); // Hypothetical function
        }

        //packetCaptureInstance->deleteLater(); // Schedule the object for deletion
        packetCaptureInstance = nullptr;
    }
}



void PacketCaptureUI::updatePacketTable(const PacketInfo& info) {
    QTableWidget *tableWidget = findChild<QTableWidget *>();
    int row = tableWidget->rowCount();
    tableWidget->insertRow(row);

    // Example of creating a non-editable QTableWidgetItem
    auto createNonEditableItem = [](QString text) {
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    };

    qDebug() << "updatePacketTable called with packet info:" << info.ipSource.c_str();

    tableWidget->setItem(row, 0, createNonEditableItem(QString::number(row + 1)));
    tableWidget->setItem(row, 1, createNonEditableItem("eth"));//info.networkCard));
    tableWidget->setItem(row, 2, createNonEditableItem(QString::fromStdString(info.protocol)));
    tableWidget->setItem(row, 3, createNonEditableItem(QString::fromStdString(info.application)));
    tableWidget->setItem(row, 4, createNonEditableItem(QString::fromStdString(info.ipSource)));
    tableWidget->setItem(row, 5, createNonEditableItem(QString::fromStdString(info.portSource))); // Assuming portSource is int
    tableWidget->setItem(row, 6, createNonEditableItem(QString::fromStdString(info.ipDestination)));
    tableWidget->setItem(row, 7, createNonEditableItem(QString::fromStdString(info.portDestination))); // Assuming portDestination is int
}


void PacketCaptureUI::securitySettings() {
    QMenu securityMenu(this);
    QAction *enableAction = new QAction("Enable", this);
    QAction *disableAction = new QAction("Disable", this);

    enableAction->setCheckable(true);
    disableAction->setCheckable(true);

    enableAction->setChecked(securityEnabled);
    disableAction->setChecked(!securityEnabled);

    connect(enableAction, &QAction::triggered, [this]() {
        securityEnabled = true;
        // Additional logic to enable security
    });
    connect(disableAction, &QAction::triggered, [this]() {
        securityEnabled = false;
        // Additional logic to disable security
    });

    securityMenu.addAction(enableAction);
    securityMenu.addAction(disableAction);
    securityMenu.exec(QCursor::pos());
}

void PacketCaptureUI::notificationSettings() {
    QMenu *notificationMenu = new QMenu(this);

    QAction *sendEmailAction = new QAction("Send Email", this);
    QAction *windowsNotificationAction = new QAction("Windows Notification", this);

    windowsNotificationAction->setCheckable(true);
    sendEmailAction->setCheckable(true);

    sendEmailAction->setChecked(emailNotificationEnabled);
    windowsNotificationAction->setChecked(windowsNotificationEnabled);

    connect(windowsNotificationAction, &QAction::toggled, this, [this](bool checked) {
        windowsNotificationEnabled = checked;
        // Handle the change in notification settings
    });

    connect(sendEmailAction, &QAction::toggled, this, [this](bool checked) {
        emailNotificationEnabled = checked;
        // You may want to save this setting or change the behavior of the program
    });// Additional connections for notifications

    connect(sendEmailAction, &QAction::triggered, this, &PacketCaptureUI::sendEmailPrompt);

    notificationMenu->addAction(sendEmailAction);
    notificationMenu->addAction(windowsNotificationAction);
    notificationMenu->popup(QCursor::pos());
}

void PacketCaptureUI::sendEmailPrompt() {
    bool ok;
    QString email = QInputDialog::getText(this, tr("Enter Email Address"), tr("Email:"), QLineEdit::Normal, "", &ok);
    if (ok && !email.isEmpty()) {
        // Logic to handle the email
    }
}

void PacketCaptureUI::populateProtocolComboBox() {
    protocolComboBox->addItem("TCP");
    protocolComboBox->addItem("UDP");
    protocolComboBox->addItem("ICMP");
    protocolComboBox->addItem("Unknown");
    // Add other protocols as needed
}

void PacketCaptureUI::populateApplicationComboBox() {
    applicationComboBox->addItem("HTTP");
    applicationComboBox->addItem("FTP");
    applicationComboBox->addItem("SSH");
    // Add other applications as needed
}

void PacketCaptureUI::validateInputs() {
    bool isSIPValid = !sourceNetworkEdit->text().isEmpty() && ipRegex.match(sourceNetworkEdit->text()).hasMatch();
    bool isSPortValid = !sourcePortEdit->text().isEmpty() && portRegex.match(sourcePortEdit->text()).hasMatch();
    bool isDIPValid = !destinationNetworkEdit->text().isEmpty() && ipRegex.match(destinationNetworkEdit->text()).hasMatch();
    bool isDPortValid = !destinationPortEdit->text().isEmpty() && portRegex.match(destinationPortEdit->text()).hasMatch();

    bool isSIPEmpty = sourceNetworkEdit->text().isEmpty();
    bool isSPortEmpty = sourcePortEdit->text().isEmpty();
    bool isDIPEmpty = destinationNetworkEdit->text().isEmpty();
    bool isDPortEmpty = destinationPortEdit->text().isEmpty();

    // Add similar checks for destination IP and port if necessary

    // Enable the Start button only if all conditions are met
    startStopButton->setEnabled(isSIPValid && isSPortValid && isDIPValid && isDPortValid ||
    isSIPEmpty && isSPortEmpty && isDIPEmpty && isDPortEmpty);

}

void PacketCaptureUI::setupPacketCapture() {
    qDebug() << "Setting up packet capture";
    QString selectedInterface = networkCardComboBox->currentText();
    packetCaptureInstance = new PacketCapture(selectedInterface.toStdString());
    bool isConnected = connect(&(packetCaptureInstance->notifier_), &PacketCaptureNotifier::packetReceived,
                               this, &PacketCaptureUI::updatePacketTable);
    qDebug() << "Connection status:" << isConnected;


    connect(&(packetCaptureInstance->notifier_), &PacketCaptureNotifier::packetReceived,
            this, &PacketCaptureUI::updatePacketTable, Qt::DirectConnection);





}

/*
void PacketCaptureUI::onTestButtonClicked() {
    PacketInfo testInfo;
    //testInfo.networkCard = "eth0";
    testInfo.protocol = "TCP";
    testInfo.application = "HTTP";
    testInfo.ipSource = "192.168.1.1";
    testInfo.portSource = "80";
    testInfo.ipDestination = "192.168.1.100";
    testInfo.portDestination = "8080";

    for (int i = 0; i < 1000; i++){
        updatePacketTable(testInfo);
    }
    //updatePacketTable(testInfo);
}*/


// Other necessary implementations...

#include "../../include/ui/ui.moc"
