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

#include <QMainWindow>

#include <memory>
#include <thread>

class QAction;
class QLabel;
class QProgressBar;
class QScrollArea;
class QSystemTrayIcon;
class QTabWidget;
class QTableView;

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
  explicit MainWindow(std::unique_ptr<app::CaptureController> controller,
                      std::unique_ptr<app::AnalysisService> analysisService,
                      app::HybridDetectionService *hybridService = nullptr,
                      core::IThreatIntelligence *threatIntel = nullptr,
                      core::IRuleEngine *ruleEngine = nullptr,
                      QWidget *parent = nullptr);
  ~MainWindow() override;

private slots:
  void toggleCapture();
  void onPacketReceived(const core::PacketInfo &info);
  void displaySelectedPacketRawData();
  void onFlowSelectionChanged();
  void notificationSettings();

  void runAnalysis();
  void populateFlowResults();
  void openWeightTuning();

private:
  void setupUi();
  void connectSignals() const;

  void updateTiStatus();

  std::unique_ptr<app::CaptureController> controller_;
  std::unique_ptr<app::AnalysisService> analysisService_;
  core::ServiceRegistry serviceRegistry_;
  core::IThreatIntelligence *threatIntel_ = nullptr;     // non-owning
  core::IRuleEngine *ruleEngine_ = nullptr;              // non-owning
  app::HybridDetectionService *hybridService_ = nullptr; // non-owning

  void wireControllerCallbacks();
  void wireAnalysisCallbacks();

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

  /// Analysis worker thread (stored to avoid detached jthread capturing
  /// `this`).
  std::jthread analysisThread_;
};

} // namespace nids::ui
