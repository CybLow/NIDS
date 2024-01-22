/*#include <iostream>
#include <QApplication>
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
#include <string>

#include "../../include/utils/ListNetworkInterfaces.h"
#include "../../include/packet/PacketCapture.h"

class PacketCaptureUI : public QMainWindow {
    Q_OBJECT
    // Populate networkCardComboBox with network interfaces
    std::vector<std::string> interfaces = ListNetworkInterfaces::listInterfaces();
    QComboBox *networkCardComboBox;

    bool emailNotificationEnabled; // Déclarez ces membres dans la portée de la classe
    bool windowsNotificationEnabled;
    bool securityEnabled;
public:
    PacketCaptureUI(QWidget *parent = nullptr) : QMainWindow(parent) {
        QMenuBar *menuBar = new QMenuBar(this);
        setMenuBar(menuBar);
        auto *networkCardLabel = new QLabel("Network Card", this);
        auto *networkCardComboBox = new QComboBox(this);
        auto *protocolLabel = new QLabel("Protocol", this);
        auto *protocolComboBox = new QComboBox(this);
        auto *applicationLabel = new QLabel("Application", this);
        auto *applicationComboBox = new QComboBox(this);
        auto *sourceNetworkLabel = new QLabel("IP Source", this);
        auto *sourceNetworkEdit = new QLineEdit(this);
        auto *sourcePortLabel = new QLabel("Port Source", this);
        auto *sourcePortEdit = new QLineEdit(this);
        auto *destinationNetworkLabel = new QLabel("IP Destination", this);
        auto *destinationNetworkEdit = new QLineEdit(this);
        auto *destinationPortLabel = new QLabel("Port Destination", this);
        auto *destinationPortEdit = new QLineEdit(this);
        auto *horizontalLine = new QFrame(this);
        horizontalLine->setFrameShape(QFrame::HLine);
        horizontalLine->setFrameShadow(QFrame::Sunken);
        horizontalLine->setLineWidth(1);
        auto *messageTextLabel = new QLabel("Custom Filter", this);
        auto *messageTextEdit = new QLineEdit(this);
        auto *startStopButton = new QPushButton("Start", this);

        QRegularExpression ipSourceRegex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
        QRegularExpressionValidator *ipSourceValidator = new QRegularExpressionValidator(ipSourceRegex, this);
        sourceNetworkEdit->setValidator(ipSourceValidator);
        sourcePortEdit->setValidator(ipSourceValidator); // Assurez-vous que le validateur de port source est correctement affecté au champ de port source

        QRegularExpression portSourceRegex("^(?:0|[1-9]\\d{0,4})$");
        QRegularExpressionValidator *portSourceValidator = new QRegularExpressionValidator(portSourceRegex, this);
        sourcePortEdit->setValidator(portSourceValidator);

        QRegularExpression ipDestinationRegex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
        QRegularExpressionValidator *ipDestinationValidator = new QRegularExpressionValidator(ipDestinationRegex, this);
        destinationNetworkEdit->setValidator(ipDestinationValidator); // Assurez-vous que le validateur de destination IP est correctement affecté au champ de destination IP

        QRegularExpression portDestinationRegex("^(?:0|[1-9]\\d{0,4})$");
        QRegularExpressionValidator *portDestinationValidator = new QRegularExpressionValidator(portDestinationRegex, this);
        destinationPortEdit->setValidator(portDestinationValidator); // Assurez-vous que le validateur de port destination est correctement affecté au champ de port destination


        QAction *securityAction = new QAction("Security", this);
        QAction *notificationAction = new QAction("Notification", this);

        menuBar->addAction(securityAction);
        menuBar->addAction(notificationAction);

        connect(securityAction, &QAction::triggered, this, &PacketCaptureUI::securityClicked);
        connect(notificationAction, &QAction::triggered, this, &PacketCaptureUI::notificationClicked);
        connect(notificationAction, &QAction::triggered, this, &PacketCaptureUI::notificationClicked);

        connect(startStopButton, &QPushButton::clicked, this, &PacketCaptureUI::toggleButton);

        PacketCapture* packetCaptureInstance;

        for(const std::string& interface : interfaces) {
            networkCardComboBox->addItem(QString::fromStdString(interface));
        }

        protocolComboBox->addItem("TCP");
        protocolComboBox->addItem("UDP");
        protocolComboBox->addItem("ICMP");

        applicationComboBox->addItem("HTTP");
        applicationComboBox->addItem("FTP");
        applicationComboBox->addItem("SSH");

        auto *gridLayout = new QGridLayout();

        gridLayout->addWidget(networkCardLabel, 0, 0);
        gridLayout->addWidget(protocolLabel, 0, 1);
        gridLayout->addWidget(applicationLabel, 0, 2);
        gridLayout->addWidget(sourceNetworkLabel, 0, 3);
        gridLayout->addWidget(sourcePortLabel, 0, 4);
        gridLayout->addWidget(destinationNetworkLabel, 0, 5);
        gridLayout->addWidget(destinationPortLabel, 0, 6);

        gridLayout->addWidget(networkCardComboBox, 1, 0);
        gridLayout->addWidget(protocolComboBox, 1, 1);
        gridLayout->addWidget(applicationComboBox, 1, 2);
        gridLayout->addWidget(sourceNetworkEdit, 1, 3);
        gridLayout->addWidget(sourcePortEdit, 1, 4);
        gridLayout->addWidget(destinationNetworkEdit, 1, 5);
        gridLayout->addWidget(destinationPortEdit, 1, 6);

        gridLayout->addWidget(horizontalLine, 2, 0, 1, 7);

        gridLayout->addWidget(messageTextLabel, 3, 0);
        gridLayout->addWidget(messageTextEdit, 3, 1, 1, 5);
        gridLayout->addWidget(startStopButton, 3, 6);

        auto *tableWidget = new QTableWidget(this);
        tableWidget->setColumnCount(8); // Nombre de colonnes
        QStringList tableHeader{"Numero", "Network Card", "Protocol", "Application", "IP Source",
                                "Port Source", "IP Destination", "Port Destination"};
        tableWidget->setHorizontalHeaderLabels(tableHeader);
        tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch); // Pour étirer les colonnes sur toute la largeur disponible
        tableWidget->verticalHeader()->setVisible(false); // Cacher l'entête vertical

        gridLayout->addWidget(tableWidget, 4, 0, 1, -1); // Ajout à la cinquième ligne, s'étendant sur toutes les colonnes

        auto *centralWidget = new QWidget(this);
        centralWidget->setLayout(gridLayout);
        setCentralWidget(centralWidget);

        setWindowTitle("Packet Capture Interface");
        resize(1500, 400); // Taille ajustée pour afficher correctement le tableau

        bool emailNotificationEnabled = false;
        bool windowsNotificationEnabled = false;

    }



private slots:
    void toggleButton() {
        QPushButton *button = qobject_cast<QPushButton *>(sender());
        if (button) {
            PacketCapture capture("eth0");
            if (button->text() == "Start") {
                //std::string selected_interface = networkCardComboBox->currentText().toStdString();
                button->setText("Stop");
                capture.Initialize();
                capture.StartCapture();
                cin.get();
            } else {
                button->setText("Start");
                capture.StopCapture();
                int ret = QMessageBox::question(this, "Rapport de filtrage",
                                                "Avez-vous besoin d'un rapport sur le filtrage?",
                                                QMessageBox::Yes | QMessageBox::No);
                if (ret == QMessageBox::Yes) {
                    // L'utilisateur a demandé un rapport
                    // Implémentez la logique pour générer le rapport ici
                }
            }
        }
    }

    void onPacketCaptured(const PacketInfo& info) {
        // Ajoutez le paquet au tableau
        QTableWidget *tableWidget = findChild<QTableWidget *>();
        int row = tableWidget->rowCount();
        tableWidget->insertRow(row);
        tableWidget->setItem(row, 0, new QTableWidgetItem(QString::number(row + 1)));
        //tableWidget->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(info.networkCard)));
        tableWidget->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(std::to_string(info.protocol))));
        //tableWidget->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(info.application)));
        //tableWidget->setItem(row, 4, new QTableWidgetItem(QString::fromStdString(info.ipSource)));
        //tableWidget->setItem(row, 5, new QTableWidgetItem(QString::fromStdString(info.portSource)));
        //tableWidget->setItem(row, 6, new QTableWidgetItem(QString::fromStdString(info.ipDestination)));
        //tableWidget->setItem(row, 7, new QTableWidgetItem(QString::fromStdString(info.portDestination)));
    }

    void securityClicked() {
        QMenu securityMenu(this);
        QAction *enableAction = new QAction("Activer", this);
        QAction *disableAction = new QAction("Désactiver", this);

        enableAction->setCheckable(true);
        disableAction->setCheckable(true);

        // Supposons que vous ayez une variable membre `securityEnabled` pour suivre l'état de la sécurité
        enableAction->setChecked(securityEnabled);
        disableAction->setChecked(!securityEnabled);

        connect(enableAction, &QAction::triggered, [this]() {
            securityEnabled = true;
            // TODO: Ajoutez ici la logique pour activer la sécurité
        });
        connect(disableAction, &QAction::triggered, [this]() {
            securityEnabled = false;
            // TODO: Ajoutez ici la logique pour désactiver la sécurité
        });

        securityMenu.addAction(enableAction);
        securityMenu.addAction(disableAction);
        securityMenu.exec(QCursor::pos());
    }

    void notificationClicked() {
        // Créez un pointeur de menu à l'échelle de la classe pour le garder en vie plus longtemps que la méthode.
        QMenu *notificationMenu = new QMenu(this);
        QAction *sendEmailAction = new QAction("Send email", this);
        QAction *windowsNotificationAction = new QAction("Notification windows", this);

        sendEmailAction->setCheckable(true);
        windowsNotificationAction->setCheckable(true);

        sendEmailAction->setChecked(emailNotificationEnabled);
        windowsNotificationAction->setChecked(windowsNotificationEnabled);

        connect(sendEmailAction, &QAction::triggered, this, &PacketCaptureUI::promptForEmailAddress);


        // Ajoutez les actions au menu
        notificationMenu->addAction(sendEmailAction);
        notificationMenu->addAction(windowsNotificationAction);

        // Affichez le menu contextuel à la position actuelle du curseur
        notificationMenu->popup(QCursor::pos()); // Utilisez popup() au lieu de exec() si vous voulez que le menu soit non-modal.
    }

void promptForEmailAddress() {
    bool ok;
    QString email = QInputDialog::getText(this, tr("Enter Email Address"),
                                          tr("Email:"), QLineEdit::Normal,
                                          "", &ok);
    if (ok && !email.isEmpty()) {
        // TODO: Logique pour envoyer un email à l'adresse `email`
        QMessageBox::information(this, tr("Email Address"), tr("You entered: %1").arg(email));
    }
}

    void sendTestEmail(const QString &email) {
        // TODO: Implémentez la logique pour envoyer un email de test à `email`
        // Vous devrez utiliser une bibliothèque externe ou une API de messagerie
        QMessageBox::information(this, tr("Email Test"), tr("Email sent to: %1").arg(email));
    }


};*/

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
}

PacketCaptureUI::~PacketCaptureUI() {
    // Cleanup if necessary
    if (packetCaptureInstance) {
        packetCaptureInstance->StopCapture(); // Ensure capture is stopped
        delete packetCaptureInstance; // Delete the instance
    }
}

void PacketCaptureUI::setupUi() {
    // Create and position all UI elements
    //QMenuBar *menuBar = new QMenuBar(this);

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

    // Validators
    /*QRegularExpression ipRegex("^\\d{1,3}(\\.\\d{1,3}){3}$");
    QRegularExpression portRegex("^(?:0|[1-9]\\d{0,4})$");

    ipValidator = new QRegularExpressionValidator(ipRegex, this);
    portValidator = new QRegularExpressionValidator(portRegex, this);*/

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
}

void PacketCaptureUI::toggleCapture() {
    if (!packetCaptureInstance) {
        // Start capturing
        packetCaptureInstance = new PacketCapture(networkCardComboBox->currentText().toStdString());
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



void PacketCaptureUI::updatePacketTable(double info) {
    // Implement the logic to update the packet table
    // Ajoutez le paquet au tableau
    QTableWidget *tableWidget = findChild<QTableWidget *>();
    int row = tableWidget->rowCount();
    tableWidget->insertRow(row);
    tableWidget->setItem(row, 0, new QTableWidgetItem(QString::number(row + 1)));
    //tableWidget->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(info.networkCard)));
    tableWidget->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(std::to_string(info))));
    //tableWidget->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(info.application)));
    //tableWidget->setItem(row, 4, new QTableWidgetItem(QString::fromStdString(info.ipSource)));
    //tableWidget->setItem(row, 5, new QTableWidgetItem(QString::fromStdString(info.portSource)));
    //tableWidget->setItem(row, 6, new QTableWidgetItem(QString::fromStdString(info.ipDestination)));
    //tableWidget->setItem(row, 7, new QTableWidgetItem(QString::fromStdString(info.portDestination)));
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



// Other necessary implementations...


int main(int argc, char *argv[]) {
    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication app(argc, argv);


    PacketCaptureUI window;
    window.show();
    return app.exec();
}

#include "../../include/ui/ui.moc"
