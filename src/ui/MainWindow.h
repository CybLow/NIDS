#pragma once

#include "app/CaptureController.h"
#include "app/AnalysisService.h"
#include "core/services/ServiceRegistry.h"
#include "ui/PacketTableModel.h"
#include "ui/HexView.h"
#include "ui/FilterPanel.h"

#include <QMainWindow>
#include <QTableView>
#include <QScrollArea>
#include <QSystemTrayIcon>
#include <QAction>

#include <memory>

namespace nids::ui {

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(std::unique_ptr<nids::app::CaptureController> controller,
                        std::unique_ptr<nids::app::AnalysisService> analysisService,
                        QWidget* parent = nullptr);
    ~MainWindow() override;

private slots:
    void toggleCapture();
    void onPacketReceived(const nids::core::PacketInfo& info);
    void displaySelectedPacketRawData();
    void securitySettings();
    void notificationSettings();
    void generateReport();

private:
    void setupUi();
    void connectSignals();

    std::unique_ptr<nids::app::CaptureController> controller_;
    std::unique_ptr<nids::app::AnalysisService> analysisService_;
    nids::core::ServiceRegistry serviceRegistry_;

    FilterPanel* filterPanel_ = nullptr;
    QTableView* packetTable_ = nullptr;
    PacketTableModel* tableModel_ = nullptr;
    HexView* hexView_ = nullptr;
    QScrollArea* scrollArea_ = nullptr;
    QSystemTrayIcon* trayIcon_ = nullptr;

    QAction* securityAction_ = nullptr;
    QAction* notificationAction_ = nullptr;

    bool notificationEnabled_ = true;
    bool securityEnabled_ = false;
};

} // namespace nids::ui
