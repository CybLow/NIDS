#include "ui/DetectionDetailWidget.h"
#include "core/model/AttackType.h"

#include <QFont>
#include <QHeaderView>
#include <QScrollArea>

namespace nids::ui {

namespace {
constexpr int kProbabilityTableRows = nids::core::kAttackTypeCount;
constexpr int kProbabilityTableCols = 2; // Attack Type, Probability
constexpr int kTiTableCols = 3;          // IP, Feed, Direction
constexpr int kRulesTableCols = 3;       // Rule, Severity, Description
constexpr int kPercentMultiplier = 100;
constexpr int kProbPrecision = 2;
constexpr int kScorePrecision = 3;
} // namespace

DetectionDetailWidget::DetectionDetailWidget(QWidget *parent)
    : QWidget(parent) {
  setupUi();
}

void DetectionDetailWidget::setupUi() {
  auto *mainLayout = new QVBoxLayout(this); // NOSONAR

  // -- Flow metadata section --
  flowGroup_ = new QGroupBox("Flow Information", this); // NOSONAR
  auto *flowLayout = new QVBoxLayout(flowGroup_);       // NOSONAR
  flowSrcLabel_ = new QLabel(flowGroup_);               // NOSONAR
  flowDstLabel_ = new QLabel(flowGroup_);               // NOSONAR
  flowProtocolLabel_ = new QLabel(flowGroup_);          // NOSONAR
  flowDurationLabel_ = new QLabel(flowGroup_);          // NOSONAR
  flowPacketsLabel_ = new QLabel(flowGroup_);           // NOSONAR
  flowLayout->addWidget(flowSrcLabel_);
  flowLayout->addWidget(flowDstLabel_);
  flowLayout->addWidget(flowProtocolLabel_);
  flowLayout->addWidget(flowDurationLabel_);
  flowLayout->addWidget(flowPacketsLabel_);
  mainLayout->addWidget(flowGroup_);

  // -- Combined verdict section --
  verdictGroup_ = new QGroupBox("Detection Verdict", this); // NOSONAR
  auto *verdictLayout = new QVBoxLayout(verdictGroup_);     // NOSONAR
  verdictLabel_ = new QLabel(verdictGroup_);                // NOSONAR
  QFont verdictFont = verdictLabel_->font();
  verdictFont.setBold(true);
  verdictFont.setPointSize(verdictFont.pointSize() + 2);
  verdictLabel_->setFont(verdictFont);
  combinedScoreLabel_ = new QLabel(verdictGroup_);   // NOSONAR
  detectionSourceLabel_ = new QLabel(verdictGroup_); // NOSONAR
  verdictLayout->addWidget(verdictLabel_);
  verdictLayout->addWidget(combinedScoreLabel_);
  verdictLayout->addWidget(detectionSourceLabel_);
  mainLayout->addWidget(verdictGroup_);

  // -- ML section --
  mlGroup_ = new QGroupBox("ML Classifier", this); // NOSONAR
  auto *mlLayout = new QVBoxLayout(mlGroup_);      // NOSONAR
  mlClassLabel_ = new QLabel(mlGroup_);            // NOSONAR
  mlConfidenceLabel_ = new QLabel(mlGroup_);       // NOSONAR
  mlLayout->addWidget(mlClassLabel_);
  mlLayout->addWidget(mlConfidenceLabel_);

  probabilityTable_ = new QTableWidget( // NOSONAR
      kProbabilityTableRows, kProbabilityTableCols, mlGroup_);
  probabilityTable_->setHorizontalHeaderLabels({"Attack Type", "Probability"});
  probabilityTable_->horizontalHeader()->setSectionResizeMode(
      QHeaderView::Stretch);
  probabilityTable_->verticalHeader()->setVisible(false);
  probabilityTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  probabilityTable_->setSelectionMode(QAbstractItemView::NoSelection);
  mlLayout->addWidget(probabilityTable_);
  mainLayout->addWidget(mlGroup_);

  // -- Threat intelligence section --
  tiGroup_ = new QGroupBox("Threat Intelligence Matches", this); // NOSONAR
  auto *tiLayout = new QVBoxLayout(tiGroup_);                    // NOSONAR
  tiTable_ = new QTableWidget(0, kTiTableCols, tiGroup_);        // NOSONAR
  tiTable_->setHorizontalHeaderLabels({"IP Address", "Feed", "Direction"});
  tiTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  tiTable_->verticalHeader()->setVisible(false);
  tiTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  tiTable_->setSelectionMode(QAbstractItemView::NoSelection);
  tiLayout->addWidget(tiTable_);
  mainLayout->addWidget(tiGroup_);

  // -- Heuristic rules section --
  rulesGroup_ = new QGroupBox("Heuristic Rule Matches", this);     // NOSONAR
  auto *rulesLayout = new QVBoxLayout(rulesGroup_);                // NOSONAR
  rulesTable_ = new QTableWidget(0, kRulesTableCols, rulesGroup_); // NOSONAR
  rulesTable_->setHorizontalHeaderLabels({"Rule", "Severity", "Description"});
  rulesTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  rulesTable_->verticalHeader()->setVisible(false);
  rulesTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  rulesTable_->setSelectionMode(QAbstractItemView::NoSelection);
  rulesLayout->addWidget(rulesTable_);
  mainLayout->addWidget(rulesGroup_);

  mainLayout->addStretch();
  clearResult();
}

void DetectionDetailWidget::setResult(const nids::core::DetectionResult &result,
                                      const nids::core::FlowInfo *metadata) {
  // -- Flow metadata --
  if (metadata) {
    flowGroup_->setVisible(true);
    flowSrcLabel_->setText(QString("Source: %1:%2")
                               .arg(QString::fromStdString(metadata->srcIp))
                               .arg(metadata->srcPort));
    flowDstLabel_->setText(QString("Destination: %1:%2")
                               .arg(QString::fromStdString(metadata->dstIp))
                               .arg(metadata->dstPort));

    QString protoStr;
    switch (metadata->protocol) {
    case 6:
      protoStr = "TCP";
      break;
    case 17:
      protoStr = "UDP";
      break;
    case 1:
      protoStr = "ICMP";
      break;
    default:
      protoStr = QString("Other (%1)").arg(metadata->protocol);
      break;
    }
    flowProtocolLabel_->setText(QString("Protocol: %1").arg(protoStr));

    double durationSec = metadata->flowDurationUs / 1'000'000.0;
    flowDurationLabel_->setText(
        QString("Duration: %1 s").arg(durationSec, 0, 'f', 3));
    flowPacketsLabel_->setText(QString("Packets: %1 fwd / %2 bwd")
                                   .arg(metadata->totalFwdPackets)
                                   .arg(metadata->totalBwdPackets));
  } else {
    flowGroup_->setVisible(false);
  }

  // -- Combined verdict --
  auto verdictStr = nids::core::attackTypeToString(result.finalVerdict);
  verdictLabel_->setText(
      QString("Verdict: %1")
          .arg(QString::fromUtf8(verdictStr.data(),
                                 static_cast<int>(verdictStr.size()))));
  combinedScoreLabel_->setText(
      QString("Combined Score: %1")
          .arg(static_cast<double>(result.combinedScore), 0, 'f',
               kScorePrecision));
  auto sourceStr = nids::core::detectionSourceToString(result.detectionSource);
  detectionSourceLabel_->setText(
      QString("Detection Source: %1")
          .arg(QString::fromUtf8(sourceStr.data(),
                                 static_cast<int>(sourceStr.size()))));

  // -- ML classifier --
  auto mlStr = nids::core::attackTypeToString(result.mlResult.classification);
  mlClassLabel_->setText(
      QString("Classification: %1")
          .arg(
              QString::fromUtf8(mlStr.data(), static_cast<int>(mlStr.size()))));
  mlConfidenceLabel_->setText(
      QString("Confidence: %1%")
          .arg(static_cast<double>(result.mlResult.confidence) *
                   kPercentMultiplier,
               0, 'f', 1));

  // Populate probability distribution table
  for (int i = 0; i < nids::core::kAttackTypeCount; ++i) {
    auto typeName =
        nids::core::attackTypeToString(nids::core::attackTypeFromIndex(i));
    auto *nameItem = new QTableWidgetItem( // NOSONAR
        QString::fromUtf8(typeName.data(), static_cast<int>(typeName.size())));
    probabilityTable_->setItem(i, 0, nameItem);

    auto prob = static_cast<double>(
        result.mlResult.probabilities[static_cast<std::size_t>(i)]);
    auto *probItem = new QTableWidgetItem( // NOSONAR
        QString("%1%").arg(prob * kPercentMultiplier, 0, 'f', kProbPrecision));
    probItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    probabilityTable_->setItem(i, 1, probItem);
  }

  // -- Threat intelligence matches --
  auto tiCount = static_cast<int>(result.threatIntelMatches.size());
  tiTable_->setRowCount(tiCount);
  for (int i = 0; i < tiCount; ++i) {
    const auto &match = result.threatIntelMatches[static_cast<std::size_t>(i)];
    tiTable_->setItem(
        i, 0,
        new QTableWidgetItem(QString::fromStdString(match.ip))); // NOSONAR
    tiTable_->setItem(i, 1,
                      new QTableWidgetItem( // NOSONAR
                          QString::fromStdString(match.feedName)));
    tiTable_->setItem(i, 2,
                      new QTableWidgetItem(match.isSource // NOSONAR
                                               ? "Source"
                                               : "Destination"));
  }
  tiGroup_->setVisible(tiCount > 0);

  // -- Heuristic rule matches --
  auto rulesCount = static_cast<int>(result.ruleMatches.size());
  rulesTable_->setRowCount(rulesCount);
  for (int i = 0; i < rulesCount; ++i) {
    const auto &rule = result.ruleMatches[static_cast<std::size_t>(i)];
    rulesTable_->setItem(
        i, 0,
        new QTableWidgetItem(QString::fromStdString(rule.ruleName))); // NOSONAR
    rulesTable_->setItem(
        i, 1,
        new QTableWidgetItem(QString::number( // NOSONAR
            static_cast<double>(rule.severity), 'f', kProbPrecision)));
    rulesTable_->setItem(i, 2,
                         new QTableWidgetItem(QString::fromStdString( // NOSONAR
                             rule.description)));
  }
  rulesGroup_->setVisible(rulesCount > 0);
}

void DetectionDetailWidget::clearResult() {
  flowGroup_->setVisible(false);
  verdictLabel_->setText("Verdict: —");
  combinedScoreLabel_->setText("Combined Score: —");
  detectionSourceLabel_->setText("Detection Source: —");
  mlClassLabel_->setText("Classification: —");
  mlConfidenceLabel_->setText("Confidence: —");

  for (int i = 0; i < nids::core::kAttackTypeCount; ++i) {
    auto typeName =
        nids::core::attackTypeToString(nids::core::attackTypeFromIndex(i));
    probabilityTable_->setItem(
        i, 0,
        new QTableWidgetItem(QString::fromUtf8( // NOSONAR
            typeName.data(), static_cast<int>(typeName.size()))));
    auto *probItem = new QTableWidgetItem("—"); // NOSONAR
    probItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    probabilityTable_->setItem(i, 1, probItem);
  }

  tiTable_->setRowCount(0);
  tiGroup_->setVisible(false);
  rulesTable_->setRowCount(0);
  rulesGroup_->setVisible(false);
}

} // namespace nids::ui
