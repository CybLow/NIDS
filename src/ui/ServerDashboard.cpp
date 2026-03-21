#include "ui/ServerDashboard.h"

#include "client/NidsClient.h"

#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>

namespace nids::ui {

ServerDashboard::ServerDashboard(QWidget* parent)
    : QWidget(parent) {
    setupUi();
}

ServerDashboard::~ServerDashboard() = default;

// ── UI setup ────────────────────────────────────────────────────────

void ServerDashboard::setupUi() {
    auto* mainLayout = new QVBoxLayout(this);

    // Connection bar.
    auto* connLayout = new QHBoxLayout;
    connLayout->addWidget(new QLabel("Server:"));
    serverAddress_ = new QLineEdit("localhost:50051");
    serverAddress_->setMaximumWidth(250);
    connLayout->addWidget(serverAddress_);

    connectBtn_ = new QPushButton("Connect");
    disconnectBtn_ = new QPushButton("Disconnect");
    disconnectBtn_->setEnabled(false);
    connLayout->addWidget(connectBtn_);
    connLayout->addWidget(disconnectBtn_);

    connectionStatus_ = new QLabel("Disconnected");
    connectionStatus_->setStyleSheet("color: red; font-weight: bold;");
    connLayout->addWidget(connectionStatus_);
    connLayout->addStretch();

    mainLayout->addLayout(connLayout);

    // Tabs.
    tabs_ = new QTabWidget;

    // ── Health tab ──────────────────────────────────────────────
    auto* healthTab = new QWidget;
    auto* healthLayout = new QFormLayout(healthTab);
    healthStatus_ = new QLabel("--");
    versionLabel_ = new QLabel("--");
    uptimeLabel_ = new QLabel("--");
    totalFlowsLabel_ = new QLabel("--");
    totalAlertsLabel_ = new QLabel("--");
    healthLayout->addRow("Status:", healthStatus_);
    healthLayout->addRow("Version:", versionLabel_);
    healthLayout->addRow("Uptime:", uptimeLabel_);
    healthLayout->addRow("Total flows:", totalFlowsLabel_);
    healthLayout->addRow("Total alerts:", totalAlertsLabel_);
    tabs_->addTab(healthTab, "Health");

    // ── Server Status tab ──────────────────────────────────────
    auto* statusTab = new QWidget;
    auto* statusLayout = new QFormLayout(statusTab);
    capturingLabel_ = new QLabel("--");
    interfaceLabel_ = new QLabel("--");
    sessionLabel_ = new QLabel("--");
    packetsLabel_ = new QLabel("--");
    flowsLabel_ = new QLabel("--");
    flaggedLabel_ = new QLabel("--");
    statusLayout->addRow("Capturing:", capturingLabel_);
    statusLayout->addRow("Interface:", interfaceLabel_);
    statusLayout->addRow("Session:", sessionLabel_);
    statusLayout->addRow("Packets:", packetsLabel_);
    statusLayout->addRow("Flows:", flowsLabel_);
    statusLayout->addRow("Flagged:", flaggedLabel_);
    tabs_->addTab(statusTab, "Capture Status");

    // ── Hunt tab ───────────────────────────────────────────────
    auto* huntTab = new QWidget;
    auto* huntLayout = new QVBoxLayout(huntTab);

    // Flow search.
    auto* searchGroup = new QGroupBox("Flow Search");
    auto* searchLayout = new QHBoxLayout(searchGroup);
    searchIpInput_ = new QLineEdit;
    searchIpInput_->setPlaceholderText("IP address");
    searchBtn_ = new QPushButton("Search");
    searchLayout->addWidget(new QLabel("IP:"));
    searchLayout->addWidget(searchIpInput_);
    searchLayout->addWidget(searchBtn_);
    huntLayout->addWidget(searchGroup);

    searchResults_ = new QTableWidget(0, 6);
    searchResults_->setHorizontalHeaderLabels(
        {"Source", "Destination", "Port", "Verdict", "Score", "Flagged"});
    searchResults_->horizontalHeader()->setStretchLastSection(true);
    searchResults_->setEditTriggers(QTableWidget::NoEditTriggers);
    huntLayout->addWidget(searchResults_);

    // IOC search.
    auto* iocGroup = new QGroupBox("IOC Search");
    auto* iocLayout = new QHBoxLayout(iocGroup);
    iocInput_ = new QLineEdit;
    iocInput_->setPlaceholderText("IPs (comma-separated)");
    iocBtn_ = new QPushButton("Search IOCs");
    iocLayout->addWidget(new QLabel("IOCs:"));
    iocLayout->addWidget(iocInput_);
    iocLayout->addWidget(iocBtn_);
    huntLayout->addWidget(iocGroup);

    iocResults_ = new QTableWidget(0, 5);
    iocResults_->setHorizontalHeaderLabels(
        {"Source", "Destination", "Port", "Verdict", "Flagged"});
    iocResults_->horizontalHeader()->setStretchLastSection(true);
    iocResults_->setEditTriggers(QTableWidget::NoEditTriggers);
    huntLayout->addWidget(iocResults_);

    tabs_->addTab(huntTab, "Threat Hunting");

    // ── Rules tab ──────────────────────────────────────────────
    auto* rulesTab = new QWidget;
    auto* rulesLayout = new QVBoxLayout(rulesTab);

    auto* loadGroup = new QGroupBox("Load Rules");
    auto* loadLayout = new QHBoxLayout(loadGroup);
    rulesPathInput_ = new QLineEdit;
    rulesPathInput_->setPlaceholderText("/path/to/rules/");
    loadRulesBtn_ = new QPushButton("Load");
    loadLayout->addWidget(rulesPathInput_);
    loadLayout->addWidget(loadRulesBtn_);
    rulesLayout->addWidget(loadGroup);

    auto* statsGroup = new QGroupBox("Rule Statistics");
    auto* statsLayout = new QFormLayout(statsGroup);
    snortRulesLabel_ = new QLabel("--");
    yaraRulesLabel_ = new QLabel("--");
    statsLayout->addRow("Snort rules:", snortRulesLabel_);
    statsLayout->addRow("YARA rules:", yaraRulesLabel_);
    rulesLayout->addWidget(statsGroup);
    rulesLayout->addStretch();

    tabs_->addTab(rulesTab, "Signatures");

    mainLayout->addWidget(tabs_);

    // Signals.
    connect(connectBtn_, &QPushButton::clicked, this, &ServerDashboard::onConnect);
    connect(disconnectBtn_, &QPushButton::clicked, this, &ServerDashboard::onDisconnect);
    connect(searchBtn_, &QPushButton::clicked, this, &ServerDashboard::onSearchFlows);
    connect(iocBtn_, &QPushButton::clicked, this, &ServerDashboard::onIocSearch);
    connect(loadRulesBtn_, &QPushButton::clicked, this, &ServerDashboard::onLoadRules);

    // Auto-refresh timer (2 seconds).
    refreshTimer_ = new QTimer(this);
    connect(refreshTimer_, &QTimer::timeout, this, &ServerDashboard::onRefresh);
}

// ── Connection management ───────────────────────────────────────────

void ServerDashboard::onConnect() {
    client::ClientConfig config;
    config.serverAddress = serverAddress_->text().toStdString();
    config.connectTimeoutSec = 3;
    config.rpcTimeoutSec = 10;

    client_ = std::make_unique<client::NidsClient>(config);
    if (client_->connect()) {
        connected_ = true;
        connectionStatus_->setText("Connected");
        connectionStatus_->setStyleSheet("color: green; font-weight: bold;");
        connectBtn_->setEnabled(false);
        disconnectBtn_->setEnabled(true);
        refreshTimer_->start(2000);
        onRefresh();
    } else {
        QMessageBox::warning(this, "Connection Failed",
            "Cannot connect to " + serverAddress_->text());
        client_.reset();
    }
}

void ServerDashboard::onDisconnect() {
    refreshTimer_->stop();
    if (client_) {
        client_->disconnect();
        client_.reset();
    }
    connected_ = false;
    connectionStatus_->setText("Disconnected");
    connectionStatus_->setStyleSheet("color: red; font-weight: bold;");
    connectBtn_->setEnabled(true);
    disconnectBtn_->setEnabled(false);
}

void ServerDashboard::onRefresh() {
    if (!connected_ || !client_) return;
    updateHealthPanel();
    updateStatusPanel();
    updateRuleStatsPanel();
}

// ── Panel updates ───────────────────────────────────────────────────

void ServerDashboard::updateHealthPanel() {
    auto info = client_->healthCheck();
    healthStatus_->setText(info.healthy ? "Healthy" : "Unhealthy");
    healthStatus_->setStyleSheet(info.healthy
        ? "color: green; font-weight: bold;"
        : "color: red; font-weight: bold;");
    versionLabel_->setText(QString::fromStdString(info.version));
    uptimeLabel_->setText(QString::number(info.uptimeSeconds) + "s");
    totalFlowsLabel_->setText(QString::number(info.totalFlows));
    totalAlertsLabel_->setText(QString::number(info.totalAlerts));
}

void ServerDashboard::updateStatusPanel() {
    auto info = client_->getStatus();
    capturingLabel_->setText(info.capturing ? "Yes" : "No");
    interfaceLabel_->setText(info.currentInterface.empty()
        ? "(none)" : QString::fromStdString(info.currentInterface));
    sessionLabel_->setText(info.sessionId.empty()
        ? "(none)" : QString::fromStdString(info.sessionId));
    packetsLabel_->setText(QString::number(info.packetsCaptured));
    flowsLabel_->setText(QString::number(info.flowsDetected));
    flaggedLabel_->setText(QString::number(info.flowsFlagged));
}

void ServerDashboard::updateRuleStatsPanel() {
    auto stats = client_->getRuleStats();
    snortRulesLabel_->setText(
        QString::number(stats.total_rules()) + " (" +
        QString::number(stats.rule_files()) + " files)");
    yaraRulesLabel_->setText(
        QString::number(stats.yara_rules()) + " (" +
        QString::number(stats.yara_files()) + " files)");
}

// ── Hunt operations ─────────────────────────────────────────────────

void ServerDashboard::onSearchFlows() {
    if (!connected_ || !client_) return;

    SearchFlowsRequest request;
    auto ip = searchIpInput_->text().toStdString();
    if (!ip.empty()) request.set_any_ip(ip);
    request.set_limit(100);

    auto response = client_->searchFlows(request);

    searchResults_->setRowCount(0);
    for (int i = 0; i < response.flows_size(); ++i) {
        const auto& f = response.flows(i);
        int row = searchResults_->rowCount();
        searchResults_->insertRow(row);
        searchResults_->setItem(row, 0,
            new QTableWidgetItem(QString::fromStdString(f.src_ip())));
        searchResults_->setItem(row, 1,
            new QTableWidgetItem(QString::fromStdString(f.dst_ip())));
        searchResults_->setItem(row, 2,
            new QTableWidgetItem(QString::number(f.dst_port())));
        searchResults_->setItem(row, 3,
            new QTableWidgetItem(QString::fromStdString(f.verdict())));
        searchResults_->setItem(row, 4,
            new QTableWidgetItem(QString::number(f.combined_score(), 'f', 2)));
        searchResults_->setItem(row, 5,
            new QTableWidgetItem(f.is_flagged() ? "YES" : ""));
    }
}

void ServerDashboard::onIocSearch() {
    if (!connected_ || !client_) return;

    IocSearchRequest request;
    auto ips = iocInput_->text().split(',', Qt::SkipEmptyParts);
    for (const auto& ip : ips) {
        request.add_ips(ip.trimmed().toStdString());
    }

    auto response = client_->iocSearch(request);

    iocResults_->setRowCount(0);
    for (int i = 0; i < response.matched_flows_size(); ++i) {
        const auto& f = response.matched_flows(i);
        int row = iocResults_->rowCount();
        iocResults_->insertRow(row);
        iocResults_->setItem(row, 0,
            new QTableWidgetItem(QString::fromStdString(f.src_ip())));
        iocResults_->setItem(row, 1,
            new QTableWidgetItem(QString::fromStdString(f.dst_ip())));
        iocResults_->setItem(row, 2,
            new QTableWidgetItem(QString::number(f.dst_port())));
        iocResults_->setItem(row, 3,
            new QTableWidgetItem(QString::fromStdString(f.verdict())));
        iocResults_->setItem(row, 4,
            new QTableWidgetItem(f.is_flagged() ? "YES" : ""));
    }
}

void ServerDashboard::onLoadRules() {
    if (!connected_ || !client_) return;

    auto path = rulesPathInput_->text().toStdString();
    if (path.empty()) return;

    auto response = client_->loadRules(path);

    QString msg = response.success()
        ? QString("Loaded %1 rules").arg(response.rules_loaded())
        : QString("Failed: %1").arg(QString::fromStdString(response.message()));

    QMessageBox::information(this, "Load Rules", msg);
    updateRuleStatsPanel();
}

} // namespace nids::ui
