#include "../../include/utils/ListNetworkInterfaces.h"
#include "../../include/packet/PacketCapture.h"
#include "include/ui/ui.h"
#include "include/ui/FullListDialog.h"

#include <QRegularExpression>
#include <QGridLayout>
#include <QAction>
#include <QMenu>
#include <QApplication>
#include <QMainWindow>
#include <QLineEdit>
#include <QDir>
#include <iostream>
#include <QScrollArea>


PacketCaptureUI::PacketCaptureUI(QWidget *parent): QMainWindow(parent),
    emailNotificationEnabled(false),
    notificationEnabled(true),
    securityEnabled(false)
    {
        setupUi();
        connectSignalsSlots();
        packetCaptureInstance = nullptr;

        systemTrayIcon = new QSystemTrayIcon(this);
        systemTrayIcon->setIcon(QIcon("logo.png")); // Set an icon here
        systemTrayIcon->setVisible(true);
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
    filterTextLabel = new QLabel("Custom Filter", this);

    // Edit lines
    sourceNetworkEdit = new QLineEdit(this);
    sourcePortEdit = new QLineEdit(this);
    destinationNetworkEdit = new QLineEdit(this);
    destinationPortEdit = new QLineEdit(this);
    filterTextEdit = new QLineEdit(this);

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
    gridLayout->addWidget(filterTextLabel, 2, 0);
    gridLayout->addWidget(filterTextEdit, 2, 1, 1, 6);
    gridLayout->addWidget(startStopButton, 2, 7);
    gridLayout->addWidget(packetTable, 3, 0, 1, 8);

    // Hex display
    hexAsciiDisplay = new HexAsciiDisplay(this);
    hexAsciiDisplay->setMinimumSize(QSize(200, 100)); // Set a minimum size for the display

    // Initialize the scroll area
    scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true); // Allow the scroll area to resize with its content
    scrollArea->setWidget(hexAsciiDisplay); // Add the HexAsciiDisplay as the scroll area's widget

    // Add the scroll area to the grid layout instead of the hex display directly
    gridLayout->addWidget(scrollArea, 4, 0, 1, 8);
    auto *centralWidget = new QWidget(this);
    centralWidget->setLayout(gridLayout);
    setCentralWidget(centralWidget);


    // Set Protocol and Application ComboBoxes
    populateProtocolComboBox();
    populateApplicationComboBox();

    // Set Window Properties
    setWindowTitle("Packet Capture Interface");
    resize(1500, 400);

    validateInputs();
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

    connect(applicationComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(onApplicationComboBoxChanged(int)));
    connect(sourcePortEdit, &QLineEdit::textChanged, this, &PacketCaptureUI::updateApplicationComboBoxBasedOnPort);
    connect(destinationPortEdit, &QLineEdit::textChanged, this, &PacketCaptureUI::updateApplicationComboBoxBasedOnPort);

    connect(packetTable, &QTableWidget::itemSelectionChanged, this, &PacketCaptureUI::displaySelectedPacketRawData);
}

void PacketCaptureUI::populateNetworkCardComboBox() {
    networkInterfaces = ListNetworkInterfaces::listInterfaces();
    for (const string& interface : networkInterfaces) {
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
            generateReport();
        }

        // Clear the table
        packetTable->setRowCount(0);
    } else {
        if (packetCaptureInstance) {
            packetCaptureInstance->StopCapture();
            packetCaptureInstance->wait(); // Wait for the thread to finish
            delete packetCaptureInstance;
            packetCaptureInstance = nullptr;
        }
        // Start capturing
        if (!packetCaptureInstance) {
            PacketFilter filter = gatherPacketData();
            string filterString = filter.generatePcapFilterString();
            cout << "Generated pcap filter string: " << filterString << endl;

            QString selectedInterface = networkCardComboBox->currentText();
            packetCaptureInstance = new PacketCapture(selectedInterface.toStdString(), filterString, this);
            connect(&(packetCaptureInstance->notifier_), &PacketCaptureNotifier::packetReceived,
                    this, &PacketCaptureUI::updatePacketTable, Qt::QueuedConnection);
        }
        cout << "PacketFilter: "<< currentPacketData.networkCard << " with " << currentPacketData.protocol << " using "
             << currentPacketData.application << " from " << currentPacketData.sourceIP << ":" << currentPacketData.sourcePort
             << " to " << currentPacketData.destinationIP << ":" << currentPacketData.destinationPort << endl;

        packetCaptureInstance->start(); // Start the thread
        startStopButton->setText("Stop");

        // Disable input fields
        sourceNetworkEdit->setReadOnly(true);
        sourcePortEdit->setReadOnly(true);
        destinationNetworkEdit->setReadOnly(true);
        destinationPortEdit->setReadOnly(true);
    }
}

void PacketCaptureUI::updatePacketTable(const PacketInfo& info) {
    addPacketToTable(info);  // Delegate to addPacketToTable method
}

void PacketCaptureUI::addPacketToTable(const PacketInfo& packetInfo) {
    int row = packetTable->rowCount();
    packetTable->insertRow(row);

    auto createNonEditableItem = [](const QString& text) {
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    };

    // Add data to the table
    packetTable->setItem(row, 0, createNonEditableItem(QString::number(row + 1)));
    QString selectedInterface = networkCardComboBox->currentText();
    packetTable->setItem(row, 1, createNonEditableItem(selectedInterface));
    packetTable->setItem(row, 2, createNonEditableItem(QString::fromStdString(packetInfo.protocol)));
    packetTable->setItem(row, 3, createNonEditableItem(QString::fromStdString(packetInfo.application)));
    packetTable->setItem(row, 4, createNonEditableItem(QString::fromStdString(packetInfo.ipSource)));
    packetTable->setItem(row, 5, createNonEditableItem(QString::fromStdString(packetInfo.portSource)));
    packetTable->setItem(row, 6, createNonEditableItem(QString::fromStdString(packetInfo.ipDestination)));
    packetTable->setItem(row, 7, createNonEditableItem(QString::fromStdString(packetInfo.portDestination)));

    // Store the PacketInfo object in the list
    packetInfoList.push_back(packetInfo);
}


void PacketCaptureUI::displaySelectedPacketRawData() {
    int selectedRow = packetTable->currentRow();
    if (selectedRow >= 0 && selectedRow < packetInfoList.size()) {
        const PacketInfo& info = packetInfoList[selectedRow];
        QByteArray rawData = QByteArray::fromRawData(reinterpret_cast<const char*>(info.rawData.data()), info.rawData.size());
        hexAsciiDisplay->setData(rawData);

        QSize currentSize = this->size();
        this->resize(currentSize.width(), currentSize.height() + 1);
        this->resize(currentSize);

        ensureScrollAreaVisibility();
    }
}

void PacketCaptureUI::ensureScrollAreaVisibility() {
    hexAsciiDisplay->ensureCursorVisible();

    // Update the scroll area
    scrollArea->updateGeometry();
    scrollArea->ensureWidgetVisible(hexAsciiDisplay);
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
    QAction *notificationAction = new QAction("Desktop Notification", this);

    notificationAction->setCheckable(true);
    sendEmailAction->setCheckable(true);

    sendEmailAction->setChecked(emailNotificationEnabled);
    notificationAction->setChecked(notificationEnabled);

    connect(notificationAction, &QAction::toggled, this, [this](bool checked) {
        notificationEnabled = checked;
    });

    connect(sendEmailAction, &QAction::toggled, this, [this](bool checked) {
        emailNotificationEnabled = checked;

    });// Additional connections for notifications

    connect(sendEmailAction, &QAction::triggered, this, &PacketCaptureUI::sendEmailPrompt);

    notificationMenu->addAction(sendEmailAction);
    notificationMenu->addAction(notificationAction);
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
    protocolComboBox->addItem("ALL");
    protocolComboBox->addItem("TCP");
    protocolComboBox->addItem("UDP");
    protocolComboBox->addItem("ICMP");
    protocolComboBox->addItem("Unknown");
}

void PacketCaptureUI::populateApplicationComboBox() {
    applicationComboBox->blockSignals(true); // Prevent triggering onApplicationComboBoxChanged
    applicationComboBox->clear();
    QStringList mainApplications = {"ALL", "HTTP", "FTP", "SSH", "HTTPS", "SMTP", "DNS", "Telnet", "Unknown"};

    for (const QString& app : mainApplications) {
        applicationComboBox->addItem(app);
    }

    applicationComboBox->addItem("Other...");
    applicationComboBox->blockSignals(false); // Re-enable signals
}

void PacketCaptureUI::onApplicationComboBoxChanged(int index) {
    if (index == -1) return;

    QString selectedItem = applicationComboBox->itemText(index);

    if (selectedItem == "Other...") {
        FullListDialog dialog(getUniqueServices(), this);
        if (dialog.exec() == QDialog::Accepted) {
            QString selectedService = dialog.getSelectedService();
            if (!selectedService.isEmpty()) {
                // Update the combo box with the new service
                int existingIndex = applicationComboBox->findText(lastCustomService);
                if (existingIndex != -1) {
                    applicationComboBox->removeItem(existingIndex); // Remove the old custom item
                }

                applicationComboBox->blockSignals(true);
                applicationComboBox->addItem(selectedService);
                applicationComboBox->setCurrentIndex(applicationComboBox->findText(selectedService));
                applicationComboBox->blockSignals(false);

                lastCustomService = selectedService; // Update the last custom service
            }
        }
    } else if (selectedItem == "Show Main Applications") {
        populateApplicationComboBox();
    }
}

void PacketCaptureUI::updateApplicationComboBoxBasedOnPort() {
    QStringList majorApps = {"ALL", "HTTP", "FTP", "SSH", "HTTPS", "SMTP", "DNS", "Telnet", "Unknown"};

    // Get port numbers from both fields
    bool sourceOk, destOk;
    int sourcePort = sourcePortEdit->text().toInt(&sourceOk);
    int destPort = destinationPortEdit->text().toInt(&destOk);

    auto updateComboBox = [&](int port) {
        string serviceName = getServiceNameByPort(port);
        if (majorApps.contains(QString::fromStdString(serviceName))) {
            populateApplicationComboBox();
            applicationComboBox->setCurrentIndex(applicationComboBox->findText(QString::fromStdString(serviceName)));
        } else {
            int existingIndex = applicationComboBox->findText(lastAddedService);
            if (existingIndex != -1) {
                applicationComboBox->removeItem(existingIndex);
            }
            applicationComboBox->addItem(QString::fromStdString(serviceName));
            applicationComboBox->setCurrentIndex(applicationComboBox->count() - 1);
            lastAddedService = QString::fromStdString(serviceName);
        }
    };

    // Prioritize destination port; if not valid, check source port
    if (destOk) {
        updateComboBox(destPort);
    } else if (sourceOk) {
        updateComboBox(sourcePort);
    }
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

    // Enable the Start button only if all conditions are met
    startStopButton->setEnabled(
            isSIPValid && isSPortValid && isDIPValid && isDPortValid ||
            isSIPEmpty && isSPortEmpty && isDIPEmpty && isDPortEmpty ||

            isSIPValid && isSPortEmpty && isDIPEmpty && isDPortEmpty ||
            isSIPValid && isSPortValid && isDIPEmpty && isDPortEmpty ||
            isSIPValid && isSPortValid && isDIPValid && isDPortEmpty ||

            isSIPEmpty && isSPortValid && isDIPEmpty && isDPortEmpty ||
            isSIPEmpty && isSPortValid && isDIPValid && isDPortEmpty ||
            isSIPEmpty && isSPortValid && isDIPValid && isDPortValid ||

            isSIPEmpty && isSPortEmpty && isDIPValid && isDPortEmpty ||
            isSIPEmpty && isSPortEmpty && isDIPValid && isDPortValid ||

            isSIPValid && isSPortEmpty && isDIPValid && isDPortValid ||
            isSIPValid && isSPortEmpty && isDIPValid && isDPortEmpty ||
            isSIPValid && isSPortEmpty && isDIPEmpty && isDPortValid ||

            isSIPEmpty && isSPortValid && isDIPEmpty && isDPortValid ||
            isSIPEmpty && isSPortEmpty && isDIPEmpty && isDPortValid );

}

void PacketCaptureUI::setupPacketCapture() {
    if (packetCaptureInstance) {
        // If an instance already exists, make sure it's stopped and deleted
        if (packetCaptureInstance->isRunning()) {
            packetCaptureInstance->StopCapture();
            packetCaptureInstance->wait(); // Wait for the thread to finish
        }
        delete packetCaptureInstance;
        packetCaptureInstance = nullptr;
    }

    QString selectedInterface = networkCardComboBox->currentText();

    PacketFilter filter = gatherPacketData();

    string filterString = filter.generatePcapFilterString();

    packetCaptureInstance = new PacketCapture(selectedInterface.toStdString(), filterString, this);
    connect(&(packetCaptureInstance->notifier_), &PacketCaptureNotifier::packetReceived,
            this, &PacketCaptureUI::updatePacketTable, Qt::QueuedConnection);
}

void PacketCaptureUI::generateReport() {
    QString filePath = "report.txt";
    QFile reportFile(filePath);

    QElapsedTimer timer;
    timer.start();

    if (reportFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&reportFile);

        // HERE PUT THE CONTENT FOR REPORT GENERATION
        out << "Test Rapport\n";

        reportFile.close();

        // Time elastped to generate the report
        qint64 timeElapsed = timer.elapsed();

        // Convertion of elapsed time
        int hours = timeElapsed / 3600000;
        int minutes = (timeElapsed % 3600000) / 60000;
        int seconds = (timeElapsed % 60000) / 1000;

        QString timeString = QString::number(hours) + "h "
                             + QString::number(minutes) + "min "
                             + QString::number(seconds) + "s ";

        /*QMessageBox::information(this, "Report",
                                 "Le rapport a été généré avec succès à l'emplacement suivant : "
                                 + filePath + "\nTemps de génération : "
                                 + timeString);*/

        QString notificationMessage = "Le rapport a été généré avec succès à l'emplacement suivant : "
                                      + filePath + "\nTemps de génération : "
                                      + timeString;

        if (notificationEnabled) { // Check if notifications are enabled
            systemTrayIcon->showMessage("Report Generation", notificationMessage, QSystemTrayIcon::Information);
        } else {
            QMessageBox::information(this, "Report", notificationMessage);
        }
    } else {
        QMessageBox::critical(this, "Error", "Impossible de créer le rapport");
    }
}

PacketFilter PacketCaptureUI::gatherPacketData() {
    PacketFilter data;
    data.networkCard = networkCardComboBox->currentText().toStdString();
    data.protocol = protocolComboBox->currentText().toStdString();
    data.application = applicationComboBox->currentText().toStdString();
    data.sourceIP = sourceNetworkEdit->text().toStdString();
    data.destinationIP = destinationNetworkEdit->text().toStdString();
    data.sourcePort = sourcePortEdit->text().toStdString();
    data.destinationPort = destinationPortEdit->text().toStdString();

    data.customBPFFilter = filterTextEdit->text().toStdString();
    return data;
}

#include "../../include/ui/ui.moc"
