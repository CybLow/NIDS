#include "ui/ServerDashboard.h"

#include "client/NidsClient.h"

#include <QComboBox>
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

ServerDashboard::ServerDashboard(QWidget* parent) : QWidget(parent) {
    setupUi();
}

ServerDashboard::~ServerDashboard() {
    streaming_.store(false);
}

// ── UI Construction ─────────────────────────────────────────────────

void ServerDashboard::setupUi() {
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->addWidget(createConnectionBar());

    tabs_ = new QTabWidget;
    tabs_->addTab(createHealthTab(), "Health");
    tabs_->addTab(createCaptureTab(), "Capture");
    tabs_->addTab(createStreamingTab(), "Live Stream");
    tabs_->addTab(createHuntTab(), "Threat Hunting");
    tabs_->addTab(createRulesTab(), "Signatures");
    tabs_->setEnabled(false);
    mainLayout->addWidget(tabs_);

    refreshTimer_ = new QTimer(this);
    connect(refreshTimer_, &QTimer::timeout, this, &ServerDashboard::onRefresh);
}

QWidget* ServerDashboard::createConnectionBar() {
    auto* bar = new QWidget;
    auto* layout = new QHBoxLayout(bar);
    layout->setContentsMargins(0, 0, 0, 0);

    layout->addWidget(new QLabel("Server:"));
    serverAddress_ = new QLineEdit("localhost:50051");
    serverAddress_->setMaximumWidth(250);
    layout->addWidget(serverAddress_);

    connectBtn_ = new QPushButton("Connect");
    disconnectBtn_ = new QPushButton("Disconnect");
    disconnectBtn_->setEnabled(false);
    layout->addWidget(connectBtn_);
    layout->addWidget(disconnectBtn_);

    connectionStatus_ = new QLabel("Disconnected");
    connectionStatus_->setStyleSheet("color: red; font-weight: bold;");
    layout->addWidget(connectionStatus_);
    layout->addStretch();

    connect(connectBtn_, &QPushButton::clicked, this, &ServerDashboard::onConnect);
    connect(disconnectBtn_, &QPushButton::clicked, this, &ServerDashboard::onDisconnect);

    return bar;
}

QWidget* ServerDashboard::createHealthTab() {
    auto* tab = new QWidget;
    auto* layout = new QFormLayout(tab);
    healthStatus_ = new QLabel("--");
    versionLabel_ = new QLabel("--");
    uptimeLabel_ = new QLabel("--");
    totalFlowsLabel_ = new QLabel("--");
    totalAlertsLabel_ = new QLabel("--");
    layout->addRow("Status:", healthStatus_);
    layout->addRow("Version:", versionLabel_);
    layout->addRow("Uptime:", uptimeLabel_);
    layout->addRow("Total flows:", totalFlowsLabel_);
    layout->addRow("Total alerts:", totalAlertsLabel_);
    return tab;
}

QWidget* ServerDashboard::createCaptureTab() {
    auto* tab = new QWidget;
    auto* layout = new QVBoxLayout(tab);

    // Capture controls.
    auto* ctrlGroup = new QGroupBox("Capture Control");
    auto* ctrlLayout = new QHBoxLayout(ctrlGroup);

    interfaceCombo_ = new QComboBox;
    interfaceCombo_->setMinimumWidth(150);
    refreshIfacesBtn_ = new QPushButton("Refresh");
    startCaptureBtn_ = new QPushButton("Start Capture");
    stopCaptureBtn_ = new QPushButton("Stop Capture");
    stopCaptureBtn_->setEnabled(false);

    ctrlLayout->addWidget(new QLabel("Interface:"));
    ctrlLayout->addWidget(interfaceCombo_);
    ctrlLayout->addWidget(refreshIfacesBtn_);
    ctrlLayout->addWidget(startCaptureBtn_);
    ctrlLayout->addWidget(stopCaptureBtn_);
    ctrlLayout->addStretch();
    layout->addWidget(ctrlGroup);

    // Live stats.
    auto* statsGroup = new QGroupBox("Session Statistics");
    auto* statsLayout = new QFormLayout(statsGroup);
    capturingLabel_ = new QLabel("No");
    sessionLabel_ = new QLabel("--");
    packetsLabel_ = new QLabel("0");
    flowsLabel_ = new QLabel("0");
    flaggedLabel_ = new QLabel("0");
    statsLayout->addRow("Capturing:", capturingLabel_);
    statsLayout->addRow("Session ID:", sessionLabel_);
    statsLayout->addRow("Packets:", packetsLabel_);
    statsLayout->addRow("Flows:", flowsLabel_);
    statsLayout->addRow("Flagged:", flaggedLabel_);
    layout->addWidget(statsGroup);
    layout->addStretch();

    connect(refreshIfacesBtn_, &QPushButton::clicked,
            this, &ServerDashboard::onRefreshInterfaces);
    connect(startCaptureBtn_, &QPushButton::clicked,
            this, &ServerDashboard::onStartCapture);
    connect(stopCaptureBtn_, &QPushButton::clicked,
            this, &ServerDashboard::onStopCapture);

    return tab;
}

QWidget* ServerDashboard::createStreamingTab() {
    auto* tab = new QWidget;
    auto* layout = new QVBoxLayout(tab);

    auto* btnLayout = new QHBoxLayout;
    startStreamBtn_ = new QPushButton("Start Streaming");
    stopStreamBtn_ = new QPushButton("Stop");
    stopStreamBtn_->setEnabled(false);
    btnLayout->addWidget(startStreamBtn_);
    btnLayout->addWidget(stopStreamBtn_);
    btnLayout->addStretch();
    layout->addLayout(btnLayout);

    streamTable_ = new QTableWidget(0, 7);
    streamTable_->setHorizontalHeaderLabels(
        {"Flow", "Verdict", "Source", "Destination", "Protocol",
         "Classification", "Score"});
    streamTable_->horizontalHeader()->setStretchLastSection(true);
    streamTable_->setEditTriggers(QTableWidget::NoEditTriggers);
    layout->addWidget(streamTable_);

    connect(startStreamBtn_, &QPushButton::clicked,
            this, &ServerDashboard::onStartStreaming);
    connect(stopStreamBtn_, &QPushButton::clicked,
            this, &ServerDashboard::onStopStreaming);

    return tab;
}

QWidget* ServerDashboard::createHuntTab() {
    auto* tab = new QWidget;
    auto* layout = new QVBoxLayout(tab);

    // Flow search.
    auto* searchGroup = new QGroupBox("Flow Search");
    auto* searchLayout = new QHBoxLayout(searchGroup);
    searchIpInput_ = new QLineEdit;
    searchIpInput_->setPlaceholderText("IP address");
    searchBtn_ = new QPushButton("Search");
    searchLayout->addWidget(new QLabel("IP:"));
    searchLayout->addWidget(searchIpInput_);
    searchLayout->addWidget(searchBtn_);
    layout->addWidget(searchGroup);

    searchResults_ = new QTableWidget(0, 6);
    searchResults_->setHorizontalHeaderLabels(
        {"Source", "Destination", "Port", "Verdict", "Score", "Flagged"});
    searchResults_->horizontalHeader()->setStretchLastSection(true);
    searchResults_->setEditTriggers(QTableWidget::NoEditTriggers);
    layout->addWidget(searchResults_);

    // IOC search.
    auto* iocGroup = new QGroupBox("IOC Indicator Search");
    auto* iocLayout = new QHBoxLayout(iocGroup);
    iocInput_ = new QLineEdit;
    iocInput_->setPlaceholderText("IPs (comma-separated)");
    iocBtn_ = new QPushButton("Search IOCs");
    iocLayout->addWidget(new QLabel("IOCs:"));
    iocLayout->addWidget(iocInput_);
    iocLayout->addWidget(iocBtn_);
    layout->addWidget(iocGroup);

    iocResults_ = new QTableWidget(0, 5);
    iocResults_->setHorizontalHeaderLabels(
        {"Source", "Destination", "Port", "Verdict", "Flagged"});
    iocResults_->horizontalHeader()->setStretchLastSection(true);
    iocResults_->setEditTriggers(QTableWidget::NoEditTriggers);
    layout->addWidget(iocResults_);

    connect(searchBtn_, &QPushButton::clicked,
            this, &ServerDashboard::onSearchFlows);
    connect(iocBtn_, &QPushButton::clicked,
            this, &ServerDashboard::onIocSearch);

    return tab;
}

QWidget* ServerDashboard::createRulesTab() {
    auto* tab = new QWidget;
    auto* layout = new QVBoxLayout(tab);

    auto* loadGroup = new QGroupBox("Load Rules");
    auto* loadLayout = new QHBoxLayout(loadGroup);
    rulesPathInput_ = new QLineEdit;
    rulesPathInput_->setPlaceholderText("/path/to/rules/");
    loadRulesBtn_ = new QPushButton("Load");
    loadLayout->addWidget(rulesPathInput_);
    loadLayout->addWidget(loadRulesBtn_);
    layout->addWidget(loadGroup);

    auto* statsGroup = new QGroupBox("Rule Statistics");
    auto* statsLayout = new QFormLayout(statsGroup);
    snortRulesLabel_ = new QLabel("--");
    yaraRulesLabel_ = new QLabel("--");
    statsLayout->addRow("Snort rules:", snortRulesLabel_);
    statsLayout->addRow("YARA rules:", yaraRulesLabel_);
    layout->addWidget(statsGroup);
    layout->addStretch();

    connect(loadRulesBtn_, &QPushButton::clicked,
            this, &ServerDashboard::onLoadRules);

    return tab;
}

// ── Connection ──────────────────────────────────────────────────────

void ServerDashboard::onConnect() {
    client::ClientConfig config;
    config.serverAddress = serverAddress_->text().toStdString();
    config.connectTimeoutSec = 3;
    config.rpcTimeoutSec = 10;

    client_ = std::make_unique<client::NidsClient>(config);
    if (client_->connect()) {
        setConnectedState(true);
        onRefreshInterfaces();
        onRefresh();
        refreshTimer_->start(2000);
    } else {
        QMessageBox::warning(this, "Connection Failed",
            "Cannot connect to " + serverAddress_->text());
        client_.reset();
    }
}

void ServerDashboard::onDisconnect() {
    streaming_.store(false);
    refreshTimer_->stop();
    if (client_) {
        client_->disconnect();
        client_.reset();
    }
    setConnectedState(false);
}

void ServerDashboard::setConnectedState(bool conn) {
    connected_ = conn;
    tabs_->setEnabled(conn);
    connectBtn_->setEnabled(!conn);
    disconnectBtn_->setEnabled(conn);
    serverAddress_->setEnabled(!conn);
    connectionStatus_->setText(conn ? "Connected" : "Disconnected");
    connectionStatus_->setStyleSheet(
        conn ? "color: green; font-weight: bold;"
             : "color: red; font-weight: bold;");
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
    capturingLabel_->setStyleSheet(info.capturing
        ? "color: green; font-weight: bold;" : "");
    sessionLabel_->setText(info.sessionId.empty()
        ? "--" : QString::fromStdString(info.sessionId));
    packetsLabel_->setText(QString::number(info.packetsCaptured));
    flowsLabel_->setText(QString::number(info.flowsDetected));
    flaggedLabel_->setText(QString::number(info.flowsFlagged));

    startCaptureBtn_->setEnabled(!info.capturing);
    stopCaptureBtn_->setEnabled(info.capturing);
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

// ── Capture control ─────────────────────────────────────────────────

void ServerDashboard::onRefreshInterfaces() {
    if (!connected_ || !client_) return;

    auto ifaces = client_->listInterfaces();
    interfaceCombo_->clear();
    for (const auto& iface : ifaces) {
        interfaceCombo_->addItem(QString::fromStdString(iface));
    }
}

void ServerDashboard::onStartCapture() {
    if (!connected_ || !client_) return;

    auto iface = interfaceCombo_->currentText().toStdString();
    if (iface.empty()) {
        QMessageBox::warning(this, "Error", "Select an interface first");
        return;
    }

    auto sessionId = client_->startCapture(iface);
    if (sessionId.empty()) {
        QMessageBox::warning(this, "Error", "Failed to start capture");
    } else {
        QMessageBox::information(this, "Capture Started",
            "Session: " + QString::fromStdString(sessionId));
    }
    onRefresh();
}

void ServerDashboard::onStopCapture() {
    if (!connected_ || !client_) return;

    auto summary = client_->stopCapture("");
    QMessageBox::information(this, "Capture Stopped",
        QString::fromStdString(summary));
    onRefresh();
}

// ── Detection streaming ─────────────────────────────────────────────

void ServerDashboard::onStartStreaming() {
    if (!connected_ || !client_) return;

    streaming_.store(true);
    startStreamBtn_->setEnabled(false);
    stopStreamBtn_->setEnabled(true);
    streamTable_->setRowCount(0);

    // Stop any previous stream thread (jthread auto-joins).
    streaming_.store(false);
    if (streamThread_.joinable()) {
        streamThread_.request_stop();
        streamThread_.join();
    }
    streaming_.store(true);

    // Run streaming in a managed jthread.
    streamThread_ = std::jthread([this](std::stop_token) {
        client_->streamDetections("", FILTER_ALL,
            [this](const DetectionEvent& event) {
                if (!streaming_.load()) return;

                QMetaObject::invokeMethod(this, [this, event]() {
                    int row = streamTable_->rowCount();
                    if (row >= 1000) {
                        streamTable_->removeRow(0);
                        row = streamTable_->rowCount();
                    }
                    streamTable_->insertRow(row);
                    streamTable_->setItem(row, 0,
                        new QTableWidgetItem(QString::number(event.flow_index())));
                    streamTable_->setItem(row, 1,
                        new QTableWidgetItem(event.verdict() == VERDICT_ATTACK
                            ? "ATTACK" : "BENIGN"));
                    streamTable_->setItem(row, 2,
                        new QTableWidgetItem(QString::fromStdString(
                            event.flow().src_ip()) + ":" +
                            QString::number(event.flow().src_port())));
                    streamTable_->setItem(row, 3,
                        new QTableWidgetItem(QString::fromStdString(
                            event.flow().dst_ip()) + ":" +
                            QString::number(event.flow().dst_port())));
                    streamTable_->setItem(row, 4,
                        new QTableWidgetItem(QString::fromStdString(
                            event.flow().protocol())));
                    streamTable_->setItem(row, 5,
                        new QTableWidgetItem(QString::fromStdString(
                            event.ml_classification())));
                    streamTable_->setItem(row, 6,
                        new QTableWidgetItem(QString::number(
                            event.combined_score(), 'f', 3)));
                    streamTable_->scrollToBottom();
                });
            },
            streaming_);
    });
}

void ServerDashboard::onStopStreaming() {
    streaming_.store(false);
    startStreamBtn_->setEnabled(true);
    stopStreamBtn_->setEnabled(false);
}

// ── Threat hunting ──────────────────────────────────────────────────

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

// ── Signature management ────────────────────────────────────────────

void ServerDashboard::onLoadRules() {
    if (!connected_ || !client_) return;

    auto path = rulesPathInput_->text().toStdString();
    if (path.empty()) return;

    auto response = client_->loadRules(path);

    QMessageBox::information(this, "Load Rules",
        response.success()
            ? QString("Loaded %1 rules").arg(response.rules_loaded())
            : QString("Failed: %1").arg(
                  QString::fromStdString(response.message())));
    updateRuleStatsPanel();
}

} // namespace nids::ui
