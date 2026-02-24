#include "ui/MainWindow.h"
#include "app/ReportGenerator.h"

#include <QVBoxLayout>
#include <QGridLayout>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QInputDialog>
#include <QCursor>
#include <QApplication>
#include <QDir>
#include <QHeaderView>

namespace nids::ui {

MainWindow::MainWindow(std::unique_ptr<nids::app::CaptureController> controller,
                       std::unique_ptr<nids::app::AnalysisService> analysisService,
                       QWidget* parent)
    : QMainWindow(parent)
    , controller_(std::move(controller))
    , analysisService_(std::move(analysisService)) {
    setupUi();
    connectSignals();
}

MainWindow::~MainWindow() {
    if (controller_ && controller_->isCapturing()) {
        controller_->stopCapture();
    }
}

void MainWindow::setupUi() {
    filterPanel_ = new FilterPanel(serviceRegistry_, this);
    filterPanel_->setInterfaces(controller_->listInterfaces());

    tableModel_ = new PacketTableModel(this);
    packetTable_ = new QTableView(this);
    packetTable_->setModel(tableModel_);
    packetTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    packetTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    packetTable_->verticalHeader()->setVisible(false);

    hexView_ = new HexView(this);
    hexView_->setMinimumSize(200, 100);

    scrollArea_ = new QScrollArea(this);
    scrollArea_->setWidgetResizable(true);
    scrollArea_->setWidget(hexView_);

    auto* layout = new QVBoxLayout();
    layout->addWidget(filterPanel_);
    layout->addWidget(packetTable_, 1);
    layout->addWidget(scrollArea_);

    auto* central = new QWidget(this);
    central->setLayout(layout);
    setCentralWidget(central);

    securityAction_ = new QAction("Security", this);
    notificationAction_ = new QAction("Notification", this);
    menuBar()->addAction(securityAction_);
    menuBar()->addAction(notificationAction_);

    trayIcon_ = new QSystemTrayIcon(this);
    trayIcon_->setIcon(QIcon("logo.png"));
    trayIcon_->setVisible(true);

    setWindowTitle("NIDS - Network Intrusion Detection System");
    resize(1500, 600);
}

void MainWindow::connectSignals() {
    connect(filterPanel_, &FilterPanel::startStopClicked, this, &MainWindow::toggleCapture);
    connect(securityAction_, &QAction::triggered, this, &MainWindow::securitySettings);
    connect(notificationAction_, &QAction::triggered, this, &MainWindow::notificationSettings);
    connect(packetTable_->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &MainWindow::displaySelectedPacketRawData);

    connect(controller_.get(), &nids::app::CaptureController::packetReceived,
            this, &MainWindow::onPacketReceived, Qt::QueuedConnection);
}

void MainWindow::toggleCapture() {
    if (controller_->isCapturing()) {
        controller_->stopCapture();
        filterPanel_->setButtonText("Start");
        filterPanel_->setInputsReadOnly(false);

        int ret = QMessageBox::question(this, "Analysis Report",
                                        "Do you want to generate a report?",
                                        QMessageBox::Yes | QMessageBox::No);
        if (ret == QMessageBox::Yes) {
            generateReport();
        }

        tableModel_->clear();
    } else {
        auto filter = filterPanel_->gatherFilter();
        controller_->startCapture(filter);
        filterPanel_->setButtonText("Stop");
        filterPanel_->setInputsReadOnly(true);
    }
}

void MainWindow::onPacketReceived(const nids::core::PacketInfo& info) {
    tableModel_->addPacket(info, filterPanel_->selectedInterface());
}

void MainWindow::displaySelectedPacketRawData() {
    auto indexes = packetTable_->selectionModel()->selectedRows();
    if (indexes.isEmpty()) return;

    int row = indexes.first().row();
    const auto* packet = tableModel_->packetAt(row);
    if (!packet) return;

    QByteArray rawData = QByteArray::fromRawData(
        reinterpret_cast<const char*>(packet->rawData.data()),
        static_cast<int>(packet->rawData.size()));
    hexView_->setData(rawData);
}

void MainWindow::securitySettings() {
    QMenu menu(this);
    auto* enableAction = new QAction("Enable", this);
    auto* disableAction = new QAction("Disable", this);

    enableAction->setCheckable(true);
    disableAction->setCheckable(true);
    enableAction->setChecked(securityEnabled_);
    disableAction->setChecked(!securityEnabled_);

    connect(enableAction, &QAction::triggered, this, [this]() { securityEnabled_ = true; });
    connect(disableAction, &QAction::triggered, this, [this]() { securityEnabled_ = false; });

    menu.addAction(enableAction);
    menu.addAction(disableAction);
    menu.exec(QCursor::pos());
}

void MainWindow::notificationSettings() {
    auto* menu = new QMenu(this);
    auto* desktopAction = new QAction("Desktop Notification", this);

    desktopAction->setCheckable(true);
    desktopAction->setChecked(notificationEnabled_);

    connect(desktopAction, &QAction::toggled, this, [this](bool checked) {
        notificationEnabled_ = checked;
    });

    menu->addAction(desktopAction);
    menu->popup(QCursor::pos());
}

void MainWindow::generateReport() {
    auto result = nids::app::ReportGenerator::generate(
        controller_->session(),
        "report.txt",
        filterPanel_->selectedInterface());

    if (!result.success) {
        QMessageBox::critical(this, "Error", "Failed to generate report");
        return;
    }

    int hours = static_cast<int>(result.generationTimeMs / 3600000);
    int minutes = static_cast<int>((result.generationTimeMs % 3600000) / 60000);
    int seconds = static_cast<int>((result.generationTimeMs % 60000) / 1000);

    QString message = QString("Report generated at: %1\nGeneration time: %2h %3min %4s")
        .arg(QString::fromStdString(result.filePath))
        .arg(hours).arg(minutes).arg(seconds);

    if (notificationEnabled_) {
        trayIcon_->showMessage("Report Generation", message, QSystemTrayIcon::Information);
    } else {
        QMessageBox::information(this, "Report", message);
    }
}

} // namespace nids::ui
