#include "ui/MainWindow.h"

#include "core/services/Configuration.h"
#include "ui/WeightTuningDialog.h"

#include <QAction>
#include <QCursor>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QMetaObject>
#include <QProgressBar>
#include <QScrollArea>
#include <QSplitter>
#include <QStatusBar>
#include <QStringList>
#include <QSystemTrayIcon>
#include <QTabWidget>
#include <QTableView>
#include <QVBoxLayout>

namespace nids::ui {

namespace {
constexpr int kDefaultWindowWidth = 1500;
constexpr int kDefaultWindowHeight = 700;
constexpr int kHexViewMinWidth = 200;
constexpr int kHexViewMinHeight = 100;

constexpr int kFlowsTabIndex = 1;
constexpr int kDetailPanelStretchFactor = 1;
constexpr int kFlowTableStretchFactor = 2;
} // namespace

MainWindow::MainWindow(
    std::unique_ptr<app::CaptureController> controller,
    std::unique_ptr<app::AnalysisService> analysisService,
    app::HybridDetectionService *hybridService,
    core::IThreatIntelligence *threatIntel,
    core::IRuleEngine *ruleEngine, QWidget *parent)
    : QMainWindow(parent), controller_(std::move(controller)),
      analysisService_(std::move(analysisService)), threatIntel_(threatIntel),
      ruleEngine_(ruleEngine), hybridService_(hybridService) {
  setupUi();
  wireControllerCallbacks();
  wireAnalysisCallbacks();
  connectSignals();
}

MainWindow::~MainWindow() {
  // Join any in-flight analysis thread before destroying the window.
  // std::jthread destructor requests stop + joins, but we need to ensure
  // the analysis service and session are still alive during the join.
  if (analysisThread_.joinable()) {
    analysisThread_.join();
  }
  if (controller_ && controller_->isCapturing()) {
    controller_->stopCapture();
  }
}

void MainWindow::setupUi() {
  const auto &config = core::Configuration::instance();

  filterPanel_ = new FilterPanel(serviceRegistry_, this); // NOSONAR
  filterPanel_->setInterfaces(controller_->listInterfaces());

  // -- Packets tab --
  tableModel_ = new PacketTableModel(&serviceRegistry_, this); // NOSONAR
  packetTable_ = new QTableView();          // NOSONAR
  packetTable_->setModel(tableModel_);
  packetTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
  packetTable_->setSelectionMode(QAbstractItemView::SingleSelection);
  packetTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  packetTable_->verticalHeader()->setVisible(false);

  hexView_ = new HexView(); // NOSONAR
  hexView_->setMinimumSize(kHexViewMinWidth, kHexViewMinHeight);

  scrollArea_ = new QScrollArea(); // NOSONAR
  scrollArea_->setWidgetResizable(true);
  scrollArea_->setWidget(hexView_);

  auto *packetsTab = new QWidget();                  // NOSONAR
  auto *packetsLayout = new QVBoxLayout(packetsTab); // NOSONAR
  packetsLayout->addWidget(packetTable_, 1);
  packetsLayout->addWidget(scrollArea_);

  // -- Flows tab --
  flowModel_ = new FlowTableModel(this); // NOSONAR
  flowTable_ = new QTableView();         // NOSONAR
  flowTable_->setModel(flowModel_);
  flowTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
  flowTable_->setSelectionMode(QAbstractItemView::SingleSelection);
  flowTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  flowTable_->verticalHeader()->setVisible(false);

  detectionDetail_ = new DetectionDetailWidget(); // NOSONAR

  auto *detailScroll = new QScrollArea(); // NOSONAR
  detailScroll->setWidgetResizable(true);
  detailScroll->setWidget(detectionDetail_);

  auto *flowSplitter = new QSplitter(Qt::Horizontal); // NOSONAR
  flowSplitter->addWidget(flowTable_);
  flowSplitter->addWidget(detailScroll);
  flowSplitter->setStretchFactor(0, kFlowTableStretchFactor);
  flowSplitter->setStretchFactor(1, kDetailPanelStretchFactor);

  auto *flowsTab = new QWidget();                // NOSONAR
  auto *flowsLayout = new QVBoxLayout(flowsTab); // NOSONAR
  flowsLayout->addWidget(flowSplitter);

  // -- Tab widget --
  tabWidget_ = new QTabWidget(this); // NOSONAR
  tabWidget_->addTab(packetsTab, "Packets");
  tabWidget_->addTab(flowsTab, "Flows");

  // -- Progress bar --
  analysisProgress_ = new QProgressBar(this); // NOSONAR
  analysisProgress_->setVisible(false);
  analysisProgress_->setTextVisible(true);

  // -- Main layout --
  auto *layout = new QVBoxLayout(); // NOSONAR
  layout->addWidget(filterPanel_);
  layout->addWidget(tabWidget_, 1);
  layout->addWidget(analysisProgress_);

  auto *central = new QWidget(this); // NOSONAR
  central->setLayout(layout);
  setCentralWidget(central);

  // -- Menu & tray --
  auto *settingsMenu = menuBar()->addMenu("Settings");

  auto *weightsAction = new QAction("Detection Weights...", this); // NOSONAR
  connect(weightsAction, &QAction::triggered, this,
          &MainWindow::openWeightTuning);
  settingsMenu->addAction(weightsAction);

  notificationAction_ = new QAction("Notification", this); // NOSONAR
  settingsMenu->addAction(notificationAction_);

  trayIcon_ = new QSystemTrayIcon(this); // NOSONAR
  trayIcon_->setIcon(QIcon(":/icons/logo.png"));
  trayIcon_->setVisible(true);

  setWindowTitle(QString::fromStdString(config.windowTitle()));
  resize(kDefaultWindowWidth, kDefaultWindowHeight);

  // -- Status bar: TI + rules summary --
  tiStatusLabel_ = new QLabel(this); // NOSONAR
  statusBar()->addPermanentWidget(tiStatusLabel_);
  updateTiStatus();
}

void MainWindow::connectSignals() {
  connect(filterPanel_, &FilterPanel::startStopClicked, this,
          &MainWindow::toggleCapture);
  connect(notificationAction_, &QAction::triggered, this,
          &MainWindow::notificationSettings);
  connect(packetTable_->selectionModel(),
          &QItemSelectionModel::selectionChanged, this,
          &MainWindow::displaySelectedPacketRawData);

  // Flow table selection -> detail panel
  connect(flowTable_->selectionModel(), &QItemSelectionModel::selectionChanged,
          this, &MainWindow::onFlowSelectionChanged);

}

void MainWindow::wireControllerCallbacks() {
  // CaptureController callbacks may fire on the capture thread —
  // marshal all UI updates to the main thread via QMetaObject::invokeMethod.

  controller_->setPacketReceivedCallback(
      [this](const core::PacketInfo &info) {
        QMetaObject::invokeMethod(this, [this, info]() {
          onPacketReceived(info);
        }, Qt::QueuedConnection);
      });

  controller_->setLiveFlowCallback(
      [this](core::DetectionResult result,
             core::FlowInfo metadata) {
        QMetaObject::invokeMethod(this, [this, r = std::move(result),
                                         m = std::move(metadata)]() {
          flowModel_->addFlowResult(r, m);
        }, Qt::QueuedConnection);
      });

  controller_->setCaptureErrorCallback(
      [this](const std::string &message) {
        QMetaObject::invokeMethod(this, [this, msg = QString::fromStdString(message)]() {
          QMessageBox::warning(this, "Capture Error", msg);
        }, Qt::QueuedConnection);
      });
}

void MainWindow::wireAnalysisCallbacks() {
  // AnalysisService callbacks fire on the analysis worker thread —
  // marshal all UI updates to the main thread.

  analysisService_->setStartedCallback([this]() {
    QMetaObject::invokeMethod(this, [this]() {
      analysisProgress_->setVisible(true);
      analysisProgress_->setValue(0);
    }, Qt::QueuedConnection);
  });

  analysisService_->setProgressCallback([this](int current, int total) {
    QMetaObject::invokeMethod(this, [this, current, total]() {
      analysisProgress_->setMaximum(total);
      analysisProgress_->setValue(current);
    }, Qt::QueuedConnection);
  });

  analysisService_->setFinishedCallback([this]() {
    QMetaObject::invokeMethod(this, [this]() {
      analysisProgress_->setVisible(false);
      populateFlowResults();
    }, Qt::QueuedConnection);
  });

  analysisService_->setErrorCallback([this](const std::string &message) {
    QMetaObject::invokeMethod(this, [this, msg = QString::fromStdString(message)]() {
      QMessageBox::warning(this, "Analysis Error", msg);
    }, Qt::QueuedConnection);
  });
}

void MainWindow::toggleCapture() {
  if (controller_->isCapturing()) {
    // Capture the live detection state before stopping (stopCapture clears it).
    bool hadLiveDetection = controller_->isLiveDetectionActive();

    controller_->stopCapture();
    filterPanel_->setButtonText("Start");
    filterPanel_->setInputsReadOnly(false);

    if (hadLiveDetection) {
      // Live detection already produced results — switch to Flows tab.
      tabWidget_->setCurrentIndex(kFlowsTabIndex);
    } else {
      int ret = QMessageBox::question(
          this, "Analysis",
          "Do you want to run ML analysis on captured traffic?",
          QMessageBox::Yes | QMessageBox::No);
      if (ret == QMessageBox::Yes) {
        runAnalysis();
      }
    }
  } else {
    // Clear stale data from the previous capture session.
    tableModel_->clear();
    flowModel_->clear();

    auto filter = filterPanel_->gatherFilter();
    controller_->startCapture(filter);
    filterPanel_->setButtonText("Stop");
    filterPanel_->setInputsReadOnly(true);
  }
}

void MainWindow::runAnalysis() {
  // Join any previous analysis thread before launching a new one.
  if (analysisThread_.joinable()) {
    analysisThread_.join();
  }
  auto dumpFile = core::Configuration::instance().defaultDumpFile();
  // Run analysis on a stored std::jthread.  AnalysisService callbacks
  // are already wired to marshal results back to the main thread via
  // QMetaObject::invokeMethod (see wireAnalysisCallbacks()).
  // CaptureSession is mutex-protected, so the reference is safe to use
  // from the worker thread while the UI thread reads packet data.
  analysisThread_ = std::jthread([this, dumpFile]() {
    analysisService_->analyzeCapture(dumpFile, controller_->session());
  });
}

void MainWindow::onPacketReceived(const core::PacketInfo &info) {
  tableModel_->addPacket(info, filterPanel_->selectedInterface());
}

void MainWindow::displaySelectedPacketRawData() {
  auto indexes = packetTable_->selectionModel()->selectedRows();
  if (indexes.isEmpty())
    return;

  int row = indexes.first().row();
  const auto *packet = tableModel_->packetAt(row);
  if (!packet)
    return;

  QByteArray rawData = QByteArray::fromRawData(
      reinterpret_cast<const char *>(packet->rawData.data()),
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
  const auto *result = flowModel_->resultAt(row);
  if (result) {
    const auto *metadata = flowModel_->metadataAt(row);
    detectionDetail_->setResult(*result, metadata);
  } else {
    detectionDetail_->clearResult();
  }
}

void MainWindow::populateFlowResults() {
  const auto &session = controller_->session();
  auto resultCount = session.detectionResultCount();
  if (resultCount == 0)
    return;

  // Collect all detection results from the session
  std::vector<core::DetectionResult> results;
  results.reserve(resultCount);
  for (std::size_t i = 0; i < resultCount; ++i) {
    results.push_back(session.getDetectionResult(i));
  }

  // Retrieve flow metadata from the analysis service
  const auto &metadata = analysisService_->lastFlowMetadata();

  flowModel_->setFlowResults(results, metadata);

  // Switch to Flows tab to show results.
  tabWidget_->setCurrentIndex(kFlowsTabIndex);
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
      for (const auto &name : names) {
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
  auto *dialog = new WeightTuningDialog(hybridService_, this); // NOSONAR
  dialog->setAttribute(Qt::WA_DeleteOnClose);
  dialog->exec();
}

void MainWindow::notificationSettings() {
  auto *menu = new QMenu(this);                                    // NOSONAR
  auto *desktopAction = new QAction("Desktop Notification", menu); // NOSONAR

  desktopAction->setCheckable(true);
  desktopAction->setChecked(notificationEnabled_);

  connect(desktopAction, &QAction::toggled, this,
          [this](bool checked) { notificationEnabled_ = checked; });

  menu->addAction(desktopAction);
  menu->popup(QCursor::pos());
}

} // namespace nids::ui
