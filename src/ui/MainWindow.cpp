#include "ui/MainWindow.h"
#include "ui/WeightTuningDialog.h"
#include "app/ReportGenerator.h"
#include "core/services/Configuration.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QHeaderView>
#include <QCursor>
#include <QSplitter>
#include <QMetaObject>
#include <QStatusBar>
#include <QStringList>

namespace nids::ui {

namespace {
    constexpr int kDefaultWindowWidth = 1500;
    constexpr int kDefaultWindowHeight = 700;
    constexpr int kHexViewMinWidth = 200;
    constexpr int kHexViewMinHeight = 100;
    constexpr int kMsPerSecond = 1000;
    constexpr int kMsPerMinute = 60'000;
    constexpr int kMsPerHour = 3'600'000;
    constexpr int kFlowsTabIndex = 1;
    constexpr int kDetailPanelStretchFactor = 1;
    constexpr int kFlowTableStretchFactor = 2;
} // namespace

MainWindow::MainWindow(std::unique_ptr<nids::app::CaptureController> controller,
                       std::unique_ptr<nids::app::AnalysisService> analysisService,
                       nids::app::HybridDetectionService* hybridService,
                       nids::core::IThreatIntelligence* threatIntel,
                       nids::core::IRuleEngine* ruleEngine,
                       QWidget* parent)
    : QMainWindow(parent)
    , controller_(std::move(controller))
    , analysisService_(std::move(analysisService))
    , threatIntel_(threatIntel)
    , ruleEngine_(ruleEngine)
    , hybridService_(hybridService) {
    setupUi();
    connectSignals();

    // Move analysis service to a dedicated worker thread so analyzeCapture()
    // does not block the UI.  Signals from AnalysisService are already
    // connected with Qt::QueuedConnection, so they cross threads safely.
    analysisThread_ = new QThread(this);
    analysisService_->moveToThread(analysisThread_);
    analysisThread_->start();
}

MainWindow::~MainWindow() {
    if (controller_ && controller_->isCapturing()) {
        controller_->stopCapture();
    }
    if (analysisThread_) {
        analysisThread_->quit();
        analysisThread_->wait();
    }
}

void MainWindow::setupUi() {
    const auto& config = nids::core::Configuration::instance();

    filterPanel_ = new FilterPanel(serviceRegistry_, this);
    filterPanel_->setInterfaces(controller_->listInterfaces());

    // -- Packets tab --
    tableModel_ = new PacketTableModel(this);
    packetTable_ = new QTableView();
    packetTable_->setModel(tableModel_);
    packetTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    packetTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    packetTable_->verticalHeader()->setVisible(false);

    hexView_ = new HexView();
    hexView_->setMinimumSize(kHexViewMinWidth, kHexViewMinHeight);

    scrollArea_ = new QScrollArea();
    scrollArea_->setWidgetResizable(true);
    scrollArea_->setWidget(hexView_);

    auto* packetsTab = new QWidget();
    auto* packetsLayout = new QVBoxLayout(packetsTab);
    packetsLayout->addWidget(packetTable_, 1);
    packetsLayout->addWidget(scrollArea_);

    // -- Flows tab --
    flowModel_ = new FlowTableModel(this);
    flowTable_ = new QTableView();
    flowTable_->setModel(flowModel_);
    flowTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    flowTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    flowTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    flowTable_->verticalHeader()->setVisible(false);

    detectionDetail_ = new DetectionDetailWidget();

    auto* detailScroll = new QScrollArea();
    detailScroll->setWidgetResizable(true);
    detailScroll->setWidget(detectionDetail_);

    auto* flowSplitter = new QSplitter(Qt::Horizontal);
    flowSplitter->addWidget(flowTable_);
    flowSplitter->addWidget(detailScroll);
    flowSplitter->setStretchFactor(0, kFlowTableStretchFactor);
    flowSplitter->setStretchFactor(1, kDetailPanelStretchFactor);

    auto* flowsTab = new QWidget();
    auto* flowsLayout = new QVBoxLayout(flowsTab);
    flowsLayout->addWidget(flowSplitter);

    // -- Tab widget --
    tabWidget_ = new QTabWidget(this);
    tabWidget_->addTab(packetsTab, "Packets");
    tabWidget_->addTab(flowsTab, "Flows");

    // -- Progress bar --
    analysisProgress_ = new QProgressBar(this);
    analysisProgress_->setVisible(false);
    analysisProgress_->setTextVisible(true);

    // -- Main layout --
    auto* layout = new QVBoxLayout();
    layout->addWidget(filterPanel_);
    layout->addWidget(tabWidget_, 1);
    layout->addWidget(analysisProgress_);

    auto* central = new QWidget(this);
    central->setLayout(layout);
    setCentralWidget(central);

    // -- Menu & tray --
    auto* settingsMenu = menuBar()->addMenu("Settings");

    auto* weightsAction = new QAction("Detection Weights...", this);
    connect(weightsAction, &QAction::triggered, this, &MainWindow::openWeightTuning);
    settingsMenu->addAction(weightsAction);

    notificationAction_ = new QAction("Notification", this);
    settingsMenu->addAction(notificationAction_);

    trayIcon_ = new QSystemTrayIcon(this);
    trayIcon_->setIcon(QIcon(":/icons/logo.png"));
    trayIcon_->setVisible(true);

    setWindowTitle(QString::fromStdString(config.windowTitle()));
    resize(kDefaultWindowWidth, kDefaultWindowHeight);

    // -- Status bar: TI + rules summary --
    tiStatusLabel_ = new QLabel(this);
    statusBar()->addPermanentWidget(tiStatusLabel_);
    updateTiStatus();
}

void MainWindow::connectSignals() {
    connect(filterPanel_, &FilterPanel::startStopClicked, this, &MainWindow::toggleCapture);
    connect(notificationAction_, &QAction::triggered, this, &MainWindow::notificationSettings);
    connect(packetTable_->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &MainWindow::displaySelectedPacketRawData);

    // Flow table selection -> detail panel
    connect(flowTable_->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &MainWindow::onFlowSelectionChanged);

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
                populateFlowResults();
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
            // Analysis runs on the worker thread. The report prompt is
            // deferred to populateFlowResults() so that detection results
            // are available when the report is generated.
            runAnalysis();
        } else {
            // No analysis requested — offer report with packet data only.
            promptForReport();
        }
    } else {
        auto filter = filterPanel_->gatherFilter();
        controller_->startCapture(filter);
        filterPanel_->setButtonText("Stop");
        filterPanel_->setInputsReadOnly(true);
    }
}

void MainWindow::runAnalysis() {
    auto dumpFile = nids::core::Configuration::instance().defaultDumpFile();
    // Dispatch analysis to the worker thread via queued invocation.
    // CaptureSession is mutex-protected, so the reference is safe to use
    // from the worker thread while the UI thread reads packet data.
    QMetaObject::invokeMethod(analysisService_.get(), [this, dumpFile]() {
        analysisService_->analyzeCapture(dumpFile, controller_->session());
    }, Qt::QueuedConnection);
}

void MainWindow::onPacketReceived(const nids::core::PacketInfo& info) {
    tableModel_->addPacket(info, filterPanel_->selectedInterface());
}

void MainWindow::displaySelectedPacketRawData() {
    auto indexes = packetTable_->selectionModel()->selectedRows();
    if (indexes.isEmpty())
        return;

    int row = indexes.first().row();
    const auto* packet = tableModel_->packetAt(row);
    if (!packet)
        return;

    QByteArray rawData = QByteArray::fromRawData(
        reinterpret_cast<const char*>(packet->rawData.data()),
        static_cast<qsizetype>(packet->rawData.size()));
    hexView_->setData(rawData);
}

void MainWindow::onFlowSelectionChanged() {
    auto indexes = flowTable_->selectionModel()->selectedRows();
    if (indexes.isEmpty()) {
        detectionDetail_->clearResult();
        return;
    }

    int row = indexes.first().row();
    const auto* result = flowModel_->resultAt(row);
    if (result) {
        const auto* metadata = flowModel_->metadataAt(row);
        detectionDetail_->setResult(*result, metadata);
    } else {
        detectionDetail_->clearResult();
    }
}

void MainWindow::populateFlowResults() {
    auto& session = controller_->session();
    auto resultCount = session.analysisResultCount();
    if (resultCount == 0)
        return;

    // Collect all detection results from the session
    std::vector<nids::core::DetectionResult> results;
    results.reserve(resultCount);
    for (std::size_t i = 0; i < resultCount; ++i) {
        results.push_back(session.getDetectionResult(i));
    }

    // Retrieve flow metadata from the analysis service
    const auto& metadata = analysisService_->lastFlowMetadata();

    flowModel_->setFlowResults(results, metadata);

    // Switch to Flows tab to show results
    tabWidget_->setCurrentIndex(kFlowsTabIndex);

    // Now that detection results are available, offer to generate a report.
    promptForReport();
}

void MainWindow::promptForReport() {
    int ret = QMessageBox::question(this, "Report",
                                    "Do you want to generate a report?",
                                    QMessageBox::Yes | QMessageBox::No);
    if (ret == QMessageBox::Yes) {
        generateReport();
    }
}

void MainWindow::updateTiStatus() {
    QString status;

    if (threatIntel_) {
        auto feeds = threatIntel_->feedCount();
        auto entries = threatIntel_->entryCount();
        status += QString("TI: %1 feeds, %2 entries").arg(feeds).arg(entries);

        auto names = threatIntel_->feedNames();
        if (!names.empty()) {
            QStringList feedList;
            for (const auto& name : names) {
                feedList.append(QString::fromStdString(name));
            }
            status += QString(" [%1]").arg(feedList.join(", "));
        }
    } else {
        status += "TI: disabled";
    }

    if (ruleEngine_) {
        status += QString("  |  Rules: %1").arg(ruleEngine_->ruleCount());
    }

    tiStatusLabel_->setText(status);
}

void MainWindow::openWeightTuning() {
    auto* dialog = new WeightTuningDialog(hybridService_, this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->exec();
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
