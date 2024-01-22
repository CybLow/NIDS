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


PacketCaptureUI::PacketCaptureUI(QWidget *parent): QMainWindow(parent),
    emailNotificationEnabled(false),
    windowsNotificationEnabled(false),
    securityEnabled(false) {
        setupUi();
        connectSignalsSlots();
        packetCaptureInstance = nullptr;
}

PacketCaptureUI::~PacketCaptureUI() {
    // Cleanup if necessary
    if (packetCaptureInstance) {
        packetCaptureInstance->StopCapture(); // Ensure capture is stopped
        packetCaptureInstance->wait();        // Wait for thread to finish
        delete packetCaptureInstance;         // Delete the instance
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
}

void PacketCaptureUI::populateNetworkCardComboBox() {
    networkInterfaces = ListNetworkInterfaces::listInterfaces();
    for (const std::string& interface : networkInterfaces) {
        networkCardComboBox->addItem(QString::fromStdString(interface));
    }

    // Automatically set up packet capture when a network card is selected
    connect(networkCardComboBox, &QComboBox::currentTextChanged, this, &PacketCaptureUI::setupPacketCapture);
}

void PacketCaptureUI::toggleCapture() {
    if (packetCaptureInstance && packetCaptureInstance->isRunning()) {
        // Stop capturing
        packetCaptureInstance->StopCapture();
        packetCaptureInstance->wait(); // Wait for the thread to finish
        startStopButton->setText("Start");

        // Re-enable input fields and other relevant UI components
        sourceNetworkEdit->setReadOnly(false);
        sourcePortEdit->setReadOnly(false);
        destinationNetworkEdit->setReadOnly(false);
        destinationPortEdit->setReadOnly(false);

        // Additional logic if needed after stopping capture
        int ret = QMessageBox::question(this, "Filtering Report",
                                        "Do you need a filtering report?",
                                        QMessageBox::Yes | QMessageBox::No);
        if (ret == QMessageBox::Yes) {
            // Implement the logic to generate the report here
            // generateReport(); // Hypothetical function
        }
    } else {
        // Start capturing
        if (!packetCaptureInstance) {
            QString selectedInterface = networkCardComboBox->currentText();
            packetCaptureInstance = new PacketCapture(selectedInterface.toStdString(), this);
            connect(&(packetCaptureInstance->notifier_), &PacketCaptureNotifier::packetReceived,
                    this, &PacketCaptureUI::updatePacketTable, Qt::QueuedConnection);
        }
        packetCaptureInstance->start(); // Start the thread
        startStopButton->setText("Stop");

        // Disable input fields and other relevant UI components
        sourceNetworkEdit->setReadOnly(true);
        sourcePortEdit->setReadOnly(true);
        destinationNetworkEdit->setReadOnly(true);
        destinationPortEdit->setReadOnly(true);
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

    tableWidget->setItem(row, 0, createNonEditableItem(QString::number(row + 1)));
    // FAIRE EN SORTE DE METTRE LA CARTE RESEAU UTILISEE
    tableWidget->setItem(row, 1, createNonEditableItem("eth0"));//info.networkCard));
    tableWidget->setItem(row, 2, createNonEditableItem(QString::fromStdString(info.protocol)));
    tableWidget->setItem(row, 3, createNonEditableItem(QString::fromStdString(info.application)));
    tableWidget->setItem(row, 4, createNonEditableItem(QString::fromStdString(info.ipSource)));
    tableWidget->setItem(row, 5, createNonEditableItem(QString::fromStdString(info.portSource))); // Assuming portSource is int
    tableWidget->setItem(row, 6, createNonEditableItem(QString::fromStdString(info.ipDestination)));
    tableWidget->setItem(row, 7, createNonEditableItem(QString::fromStdString(info.portDestination))); // Assuming portDestination is int
}


// SERA PEUT ETRE A RETIRER
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
        // TODO : IMPLEMENTER L'ENVOI DE NOTIFICATION WINDOWS
    });

    connect(sendEmailAction, &QAction::toggled, this, [this](bool checked) {
        emailNotificationEnabled = checked;

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
        // TODO : IMPLEMENTER L'ENVOI D'EMAIL
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
    // https://www.stationx.net/common-ports-cheat-sheet/
    // AJOUTER CETTE LISTE D'APP AVEC LES PORTS COMMUN
    // CELA PERMET D'EVITER DE FAIRE DE LA DPI (DEEP PACKET INSPECTION) AVEC LIBNDPI
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
    if (packetCaptureInstance) {
        // If an instance already exists, make sure it's stopped and deleted
        if (packetCaptureInstance->isRunning()) {
            packetCaptureInstance->StopCapture();
            packetCaptureInstance->wait(); // Wait for the thread to finish
        }
        delete packetCaptureInstance;
    }

    QString selectedInterface = networkCardComboBox->currentText();
    packetCaptureInstance = new PacketCapture(selectedInterface.toStdString(), this);
    connect(&(packetCaptureInstance->notifier_), &PacketCaptureNotifier::packetReceived,
            this, &PacketCaptureUI::updatePacketTable, Qt::QueuedConnection);
}

// Other necessary implementations...

#include "../../include/ui/ui.moc"
