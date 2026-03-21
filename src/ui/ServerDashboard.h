#pragma once

/// ServerDashboard — full remote management client for nids-server.
///
/// Pure gRPC client. Provides complete server control: connection
/// management, capture start/stop, live detection streaming, threat
/// hunting, signature management, and inline IPS control.
/// The server works standalone — this UI is one of many possible clients.

#include <QWidget>

#include <atomic>
#include <memory>
#include <thread>

class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QTabWidget;
class QTimer;

namespace nids::client {
class NidsClient;
} // namespace nids::client

namespace nids::ui {

class ServerDashboard : public QWidget {
    Q_OBJECT

public:
    explicit ServerDashboard(QWidget* parent = nullptr);
    ~ServerDashboard() override;

private slots:
    // Connection.
    void onConnect();
    void onDisconnect();
    void onRefresh();

    // Capture control.
    void onStartCapture();
    void onStopCapture();
    void onRefreshInterfaces();

    // Threat hunting.
    void onSearchFlows();
    void onIocSearch();

    // Signature management.
    void onLoadRules();

    // Detection streaming.
    void onStartStreaming();
    void onStopStreaming();

private:
    void setupUi();
    QWidget* createConnectionBar();
    QWidget* createHealthTab();
    QWidget* createCaptureTab();
    QWidget* createStreamingTab();
    QWidget* createHuntTab();
    QWidget* createRulesTab();

    void updateHealthPanel();
    void updateStatusPanel();
    void updateRuleStatsPanel();
    void setConnectedState(bool connected);

    // Connection bar.
    QLineEdit* serverAddress_ = nullptr;
    QPushButton* connectBtn_ = nullptr;
    QPushButton* disconnectBtn_ = nullptr;
    QLabel* connectionStatus_ = nullptr;

    QTabWidget* tabs_ = nullptr;

    // Health tab.
    QLabel* healthStatus_ = nullptr;
    QLabel* versionLabel_ = nullptr;
    QLabel* uptimeLabel_ = nullptr;
    QLabel* totalFlowsLabel_ = nullptr;
    QLabel* totalAlertsLabel_ = nullptr;

    // Capture tab.
    QComboBox* interfaceCombo_ = nullptr;
    QPushButton* refreshIfacesBtn_ = nullptr;
    QPushButton* startCaptureBtn_ = nullptr;
    QPushButton* stopCaptureBtn_ = nullptr;
    QLabel* capturingLabel_ = nullptr;
    QLabel* sessionLabel_ = nullptr;
    QLabel* packetsLabel_ = nullptr;
    QLabel* flowsLabel_ = nullptr;
    QLabel* flaggedLabel_ = nullptr;

    // Streaming tab.
    QPushButton* startStreamBtn_ = nullptr;
    QPushButton* stopStreamBtn_ = nullptr;
    QTableWidget* streamTable_ = nullptr;
    std::atomic<bool> streaming_{false};

    // Hunt tab.
    QLineEdit* searchIpInput_ = nullptr;
    QPushButton* searchBtn_ = nullptr;
    QTableWidget* searchResults_ = nullptr;
    QLineEdit* iocInput_ = nullptr;
    QPushButton* iocBtn_ = nullptr;
    QTableWidget* iocResults_ = nullptr;

    // Rules tab.
    QLineEdit* rulesPathInput_ = nullptr;
    QPushButton* loadRulesBtn_ = nullptr;
    QLabel* snortRulesLabel_ = nullptr;
    QLabel* yaraRulesLabel_ = nullptr;

    // Auto-refresh.
    QTimer* refreshTimer_ = nullptr;

    // Streaming thread (RAII — auto-joins on destruction).
    std::jthread streamThread_;

    // gRPC client.
    std::unique_ptr<client::NidsClient> client_;
    bool connected_ = false;
};

} // namespace nids::ui
