#include "ui/MainWindow.h"
#include "app/ReportGenerator.h"
#include "core/services/Configuration.h"

#include <QVBoxLayout>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QHeaderView>
#include <QCursor>

namespace nids::ui {

namespace {
    constexpr int kDefaultWindowWidth = 1500;
    constexpr int kDefaultWindowHeight = 600;
    constexpr int kHexViewMinWidth = 200;
    constexpr int kHexViewMinHeight = 100;
    constexpr int kMsPerSecond = 1000;
    constexpr int kMsPerMinute = 60'000;
    constexpr int kMsPerHour = 3'600'000;
} // namespace

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
    const auto& config = nids::core::Configuration::instance();

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
    hexView_->setMinimumSize(kHexViewMinWidth, kHexViewMinHeight);

    scrollArea_ = new QScrollArea(this);
    scrollArea_->setWidgetResizable(true);
    scrollArea_->setWidget(hexView_);

    analysisProgress_ = new QProgressBar(this);
    analysisProgress_->setVisible(false);
    analysisProgress_->setTextVisible(true);

    auto* layout = new QVBoxLayout();
    layout->addWidget(filterPanel_);
    layout->addWidget(packetTable_, 1);
    layout->addWidget(analysisProgress_);
    layout->addWidget(scrollArea_);

    auto* central = new QWidget(this);
    central->setLayout(layout);
    setCentralWidget(central);

    notificationAction_ = new QAction("Notification", this);
    menuBar()->addAction(notificationAction_);

    trayIcon_ = new QSystemTrayIcon(this);
    trayIcon_->setIcon(QIcon(":/icons/logo.png"));
    trayIcon_->setVisible(true);

    setWindowTitle(QString::fromStdString(config.windowTitle()));
    resize(kDefaultWindowWidth, kDefaultWindowHeight);
}

void MainWindow::connectSignals() {
    connect(filterPanel_, &FilterPanel::startStopClicked, this, &MainWindow::toggleCapture);
    connect(notificationAction_, &QAction::triggered, this, &MainWindow::notificationSettings);
    connect(packetTable_->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &MainWindow::displaySelectedPacketRawData);

    connect(controller_.get(), &nids::app::CaptureController::packetReceived,
            this, &MainWindow::onPacketReceived, Qt::QueuedConnection);

    connect(controller_.get(), &nids::app::CaptureController::captureError,
            this, [this](const QString& message) {
                QMessageBox::warning(this, "Capture Error", message);
            }, Qt::QueuedConnection);

    // Analysis service signals
    connect(analysisService_.get(), &nids::app::AnalysisService::analysisStarted,
            this, [this]() {
                analysisProgress_->setVisible(true);
                analysisProgress_->setValue(0);
            }, Qt::QueuedConnection);

    connect(analysisService_.get(), &nids::app::AnalysisService::analysisProgress,
            this, [this](int current, int total) {
                analysisProgress_->setMaximum(total);
                analysisProgress_->setValue(current);
            }, Qt::QueuedConnection);

    connect(analysisService_.get(), &nids::app::AnalysisService::analysisFinished,
            this, [this]() {
                analysisProgress_->setVisible(false);
            }, Qt::QueuedConnection);

    connect(analysisService_.get(), &nids::app::AnalysisService::analysisError,
            this, [this](const QString& message) {
                QMessageBox::warning(this, "Analysis Error", message);
            }, Qt::QueuedConnection);
}

void MainWindow::toggleCapture() {
    if (controller_->isCapturing()) {
        controller_->stopCapture();
        filterPanel_->setButtonText("Start");
        filterPanel_->setInputsReadOnly(false);

        int ret = QMessageBox::question(this, "Analysis",
                                        "Do you want to run ML analysis on captured traffic?",
                                        QMessageBox::Yes | QMessageBox::No);
        if (ret == QMessageBox::Yes) {
            runAnalysis();
        }

        ret = QMessageBox::question(this, "Report",
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

void MainWindow::runAnalysis() {
    auto dumpFile = nids::core::Configuration::instance().defaultDumpFile();
    analysisService_->analyzeCapture(dumpFile, controller_->session());
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

void MainWindow::notificationSettings() {
    auto* menu = new QMenu(this);
    auto* desktopAction = new QAction("Desktop Notification", menu);

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

    int hours = static_cast<int>(result.generationTimeMs / kMsPerHour);
    int minutes = static_cast<int>((result.generationTimeMs % kMsPerHour) / kMsPerMinute);
    int seconds = static_cast<int>((result.generationTimeMs % kMsPerMinute) / kMsPerSecond);

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
