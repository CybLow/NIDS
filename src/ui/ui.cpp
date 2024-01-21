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
            PacketCapture capture("wlo1");
            if (button->text() == "Start") {
                //std::string selected_interface = networkCardComboBox->currentText().toStdString();

                capture.Initialize();
                capture.StartCapture();
                button->setText("Stop");
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


};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    PacketCaptureUI window;
    window.show();
    return app.exec();
}

#include "ui.moc"
