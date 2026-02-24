#include "ui/FilterPanel.h"
#include "ui/dialogs/ServiceDialog.h"

#include <QGridLayout>

namespace nids::ui {

FilterPanel::FilterPanel(const nids::core::ServiceRegistry& registry, QWidget* parent)
    : QWidget(parent)
    , serviceRegistry_(registry) {
    setupLayout();
    populateProtocols();
    populateApplications();
    validateInputs();
}

void FilterPanel::setupLayout() {
    auto* layout = new QGridLayout(this);

    auto makeLabel = [this](const QString& text) { return new QLabel(text, this); };

    layout->addWidget(makeLabel("Network Card"), 0, 0);
    networkCardCombo_ = new QComboBox(this);
    layout->addWidget(networkCardCombo_, 1, 0);

    layout->addWidget(makeLabel("Protocol"), 0, 1);
    protocolCombo_ = new QComboBox(this);
    layout->addWidget(protocolCombo_, 1, 1);

    layout->addWidget(makeLabel("Application"), 0, 2);
    applicationCombo_ = new QComboBox(this);
    layout->addWidget(applicationCombo_, 1, 2);

    layout->addWidget(makeLabel("IP Source"), 0, 3);
    sourceIpEdit_ = new QLineEdit(this);
    sourceIpEdit_->setMinimumSize(100, 20);
    layout->addWidget(sourceIpEdit_, 1, 3);

    layout->addWidget(makeLabel("Port Source"), 0, 4);
    sourcePortEdit_ = new QLineEdit(this);
    sourcePortEdit_->setMinimumSize(100, 20);
    layout->addWidget(sourcePortEdit_, 1, 4);

    layout->addWidget(makeLabel("IP Destination"), 0, 5);
    destIpEdit_ = new QLineEdit(this);
    destIpEdit_->setMinimumSize(100, 20);
    layout->addWidget(destIpEdit_, 1, 5);

    layout->addWidget(makeLabel("Port Destination"), 0, 6);
    destPortEdit_ = new QLineEdit(this);
    destPortEdit_->setMinimumSize(100, 20);
    layout->addWidget(destPortEdit_, 1, 6);

    layout->addWidget(makeLabel("Custom Filter"), 2, 0);
    customFilterEdit_ = new QLineEdit(this);
    layout->addWidget(customFilterEdit_, 2, 1, 1, 6);

    startStopButton_ = new QPushButton("Start", this);
    startStopButton_->setEnabled(false);
    layout->addWidget(startStopButton_, 2, 7);

    ipRegex_ = QRegularExpression(
        R"(^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$)");
    portRegex_ = QRegularExpression(
        R"(^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$)");
    ipValidator_ = new QRegularExpressionValidator(ipRegex_, this);
    portValidator_ = new QRegularExpressionValidator(portRegex_, this);

    connect(startStopButton_, &QPushButton::clicked, this, &FilterPanel::startStopClicked);
    connect(networkCardCombo_, &QComboBox::currentTextChanged, this, &FilterPanel::interfaceChanged);
    connect(sourceIpEdit_, &QLineEdit::textChanged, this, &FilterPanel::validateInputs);
    connect(sourcePortEdit_, &QLineEdit::textChanged, this, &FilterPanel::validateInputs);
    connect(destIpEdit_, &QLineEdit::textChanged, this, &FilterPanel::validateInputs);
    connect(destPortEdit_, &QLineEdit::textChanged, this, &FilterPanel::validateInputs);
    connect(applicationCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &FilterPanel::onApplicationChanged);
    connect(sourcePortEdit_, &QLineEdit::textChanged, this, &FilterPanel::updateApplicationFromPort);
    connect(destPortEdit_, &QLineEdit::textChanged, this, &FilterPanel::updateApplicationFromPort);
}

void FilterPanel::populateProtocols() {
    protocolCombo_->addItems({"ALL", "TCP", "UDP", "ICMP", "Unknown"});
}

void FilterPanel::populateApplications() {
    applicationCombo_->blockSignals(true);
    applicationCombo_->clear();
    applicationCombo_->addItems(
        {"ALL", "HTTP", "FTP", "SSH", "HTTPS", "SMTP", "DNS", "Telnet", "Unknown", "Other..."});
    applicationCombo_->blockSignals(false);
}

void FilterPanel::setInterfaces(const std::vector<std::string>& interfaces) {
    networkCardCombo_->clear();
    for (const auto& iface : interfaces) {
        networkCardCombo_->addItem(QString::fromStdString(iface));
    }
}

nids::core::PacketFilter FilterPanel::gatherFilter() const {
    nids::core::PacketFilter filter;
    filter.networkCard = networkCardCombo_->currentText().toStdString();
    filter.protocol = protocolCombo_->currentText().toStdString();
    filter.application = applicationCombo_->currentText().toStdString();
    filter.sourceIP = sourceIpEdit_->text().toStdString();
    filter.destinationIP = destIpEdit_->text().toStdString();
    filter.sourcePort = sourcePortEdit_->text().toStdString();
    filter.destinationPort = destPortEdit_->text().toStdString();
    filter.customBPFFilter = customFilterEdit_->text().toStdString();
    return filter;
}

std::string FilterPanel::selectedInterface() const {
    return networkCardCombo_->currentText().toStdString();
}

void FilterPanel::setInputsReadOnly(bool readOnly) {
    sourceIpEdit_->setReadOnly(readOnly);
    sourcePortEdit_->setReadOnly(readOnly);
    destIpEdit_->setReadOnly(readOnly);
    destPortEdit_->setReadOnly(readOnly);
}

void FilterPanel::setButtonText(const QString& text) {
    startStopButton_->setText(text);
}

void FilterPanel::validateInputs() {
    auto isValid = [](const QRegularExpression& re, const QLineEdit* edit) {
        return !edit->text().isEmpty() && re.match(edit->text()).hasMatch();
    };
    auto isEmpty = [](const QLineEdit* edit) { return edit->text().isEmpty(); };

    bool sipValid = isValid(ipRegex_, sourceIpEdit_);
    bool spValid = isValid(portRegex_, sourcePortEdit_);
    bool dipValid = isValid(ipRegex_, destIpEdit_);
    bool dpValid = isValid(portRegex_, destPortEdit_);
    bool sipEmpty = isEmpty(sourceIpEdit_);
    bool spEmpty = isEmpty(sourcePortEdit_);
    bool dipEmpty = isEmpty(destIpEdit_);
    bool dpEmpty = isEmpty(destPortEdit_);

    // Enable if: all valid, all empty, or any valid subset with remaining empty
    bool allValid = sipValid && spValid && dipValid && dpValid;
    bool allEmpty = sipEmpty && spEmpty && dipEmpty && dpEmpty;

    auto fieldOk = [](bool valid, bool empty) { return valid || empty; };
    bool eachOk = fieldOk(sipValid, sipEmpty) && fieldOk(spValid, spEmpty)
                  && fieldOk(dipValid, dipEmpty) && fieldOk(dpValid, dpEmpty);

    startStopButton_->setEnabled(allValid || allEmpty || eachOk);
}

void FilterPanel::onApplicationChanged(int index) {
    if (index == -1) return;

    QString selected = applicationCombo_->itemText(index);
    if (selected == "Other...") {
        ServiceDialog dialog(serviceRegistry_.getUniqueServices(), this);
        if (dialog.exec() == QDialog::Accepted) {
            QString service = dialog.getSelectedService();
            if (!service.isEmpty()) {
                int existing = applicationCombo_->findText(lastCustomService_);
                if (existing != -1) {
                    applicationCombo_->removeItem(existing);
                }
                applicationCombo_->blockSignals(true);
                applicationCombo_->addItem(service);
                applicationCombo_->setCurrentIndex(applicationCombo_->findText(service));
                applicationCombo_->blockSignals(false);
                lastCustomService_ = service;
            }
        }
    }
}

void FilterPanel::updateApplicationFromPort() {
    QStringList majorApps = {"ALL", "HTTP", "FTP", "SSH", "HTTPS", "SMTP", "DNS", "Telnet", "Unknown"};

    bool srcOk = false, dstOk = false;
    int srcPort = sourcePortEdit_->text().toInt(&srcOk);
    int dstPort = destPortEdit_->text().toInt(&dstOk);

    auto update = [&](int port) {
        auto name = QString::fromStdString(serviceRegistry_.getServiceByPort(port));
        if (majorApps.contains(name)) {
            populateApplications();
            applicationCombo_->setCurrentIndex(applicationCombo_->findText(name));
        } else {
            int existing = applicationCombo_->findText(lastAddedService_);
            if (existing != -1) applicationCombo_->removeItem(existing);
            applicationCombo_->addItem(name);
            applicationCombo_->setCurrentIndex(applicationCombo_->count() - 1);
            lastAddedService_ = name;
        }
    };

    if (dstOk) update(dstPort);
    else if (srcOk) update(srcPort);
}

} // namespace nids::ui
