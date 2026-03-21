#pragma once

/// ServerDashboard — Qt widget for monitoring a remote nids-server via gRPC.
///
/// Acts as a pure gRPC client. Shows server status, detection stats,
/// hunt results, signature alerts, and inline IPS metrics. Completely
/// independent of local capture/analysis — the server works standalone.

#include <QWidget>

#include <memory>
#include <string>

class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QTabWidget;
class QTimer;

namespace nids::client {
class NidsClient;
struct ClientConfig;
} // namespace nids::client

namespace nids::ui {

class ServerDashboard : public QWidget {
    Q_OBJECT

public:
    explicit ServerDashboard(QWidget* parent = nullptr);
    ~ServerDashboard() override;

private slots:
    void onConnect();
    void onDisconnect();
    void onRefresh();
    void onSearchFlows();
    void onIocSearch();
    void onLoadRules();

private:
    void setupUi();
    void updateHealthPanel();
    void updateStatusPanel();
    void updateRuleStatsPanel();

    // Connection.
    QLineEdit* serverAddress_ = nullptr;
    QPushButton* connectBtn_ = nullptr;
    QPushButton* disconnectBtn_ = nullptr;
    QLabel* connectionStatus_ = nullptr;

    // Tabs.
    QTabWidget* tabs_ = nullptr;

    // Health tab.
    QLabel* healthStatus_ = nullptr;
    QLabel* versionLabel_ = nullptr;
    QLabel* uptimeLabel_ = nullptr;
    QLabel* totalFlowsLabel_ = nullptr;
    QLabel* totalAlertsLabel_ = nullptr;

    // Server status tab.
    QLabel* capturingLabel_ = nullptr;
    QLabel* interfaceLabel_ = nullptr;
    QLabel* sessionLabel_ = nullptr;
    QLabel* packetsLabel_ = nullptr;
    QLabel* flowsLabel_ = nullptr;
    QLabel* flaggedLabel_ = nullptr;

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

    // gRPC client.
    std::unique_ptr<client::NidsClient> client_;
    bool connected_ = false;
};

} // namespace nids::ui
