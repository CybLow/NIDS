#pragma once

#include "app/AnalysisService.h"
#include "app/CaptureController.h"
#include "app/HybridDetectionService.h"
#include "core/services/IRuleEngine.h"
#include "core/services/IThreatIntelligence.h"
#include "core/services/ServiceRegistry.h"
#include "ui/DetectionDetailWidget.h"
#include "ui/FilterPanel.h"
#include "ui/FlowTableModel.h"
#include "ui/HexView.h"
#include "ui/PacketTableModel.h"

#include <QAction>
#include <QLabel>
#include <QMainWindow>
#include <QProgressBar>
#include <QScrollArea>
#include <QSplitter>
#include <QSystemTrayIcon>
#include <QTabWidget>
#include <QTableView>
#include <QThread>

#include <memory>

namespace nids::ui {

/** Main application window for the NIDS GUI. */
class MainWindow : public QMainWindow { // NOSONAR - Qt widget class requires
                                        // many member pointers
  Q_OBJECT

public:
  /**
   * Construct the main window with injected services.
   * @param controller       Packet capture controller (takes ownership).
   * @param analysisService  ML analysis service (takes ownership).
   * @param hybridService    Optional hybrid detection service (non-owning).
   * @param threatIntel      Optional threat intelligence provider (non-owning).
   * @param ruleEngine       Optional heuristic rule engine (non-owning).
   * @param parent           Parent widget.
   */
  explicit MainWindow(
      std::unique_ptr<nids::app::CaptureController> controller,
      std::unique_ptr<nids::app::AnalysisService> analysisService,
      nids::app::HybridDetectionService *hybridService = nullptr,
      nids::core::IThreatIntelligence *threatIntel = nullptr,
      nids::core::IRuleEngine *ruleEngine = nullptr, QWidget *parent = nullptr);
  ~MainWindow() override;

private slots:
  void toggleCapture();
  void onPacketReceived(const nids::core::PacketInfo &info);
  void displaySelectedPacketRawData();
  void onFlowSelectionChanged();
  void notificationSettings();
  void generateReport();
  void runAnalysis();
  void populateFlowResults();
  void openWeightTuning();

private:
  void setupUi();
  void connectSignals();
  void promptForReport();
  void updateTiStatus();

  std::unique_ptr<nids::app::CaptureController> controller_;
  std::unique_ptr<nids::app::AnalysisService> analysisService_;
  nids::core::ServiceRegistry serviceRegistry_;
  nids::core::IThreatIntelligence *threatIntel_ = nullptr;     // non-owning
  nids::core::IRuleEngine *ruleEngine_ = nullptr;              // non-owning
  nids::app::HybridDetectionService *hybridService_ = nullptr; // non-owning
  QThread *analysisThread_ = nullptr;

  // -- Top-level layout --
  FilterPanel *filterPanel_ = nullptr;
  QTabWidget *tabWidget_ = nullptr;
  QProgressBar *analysisProgress_ = nullptr;

  // -- Packets tab --
  QTableView *packetTable_ = nullptr;
  PacketTableModel *tableModel_ = nullptr;
  HexView *hexView_ = nullptr;
  QScrollArea *scrollArea_ = nullptr;

  // -- Flows tab --
  QTableView *flowTable_ = nullptr;
  FlowTableModel *flowModel_ = nullptr;
  DetectionDetailWidget *detectionDetail_ = nullptr;

  // -- Status bar widgets --
  QLabel *tiStatusLabel_ = nullptr;

  // -- System tray & notifications --
  QSystemTrayIcon *trayIcon_ = nullptr;
  QAction *notificationAction_ = nullptr;
  bool notificationEnabled_ = true;
};

} // namespace nids::ui
