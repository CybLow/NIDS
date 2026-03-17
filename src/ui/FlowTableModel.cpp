#include "ui/FlowTableModel.h"
#include "ui/QtStringConversions.h"

#include <algorithm>
#include <cmath>
#include <utility>

namespace nids::ui {

namespace {
// Severity thresholds for combined score color-coding.
constexpr float kLowRiskThreshold = 0.3f;
constexpr float kMediumRiskThreshold = 0.6f;
constexpr int kAlphaBackground = 60; // Subtle transparency for row colors

/// Column headers in enum order.
constexpr std::array<const char *, FlowTableModel::kColumnCount>
    kFlowColumnHeaders = {{
        "Flow #",
        "Source IP",
        "Src Port",
        "Destination IP",
        "Dst Port",
        "Protocol",
        "Verdict",
        "ML Confidence",
        "Combined Score",
        "Detection Source",
    }};

/// Columns that should be right-aligned.
constexpr std::array<int, 5> kRightAlignedColumns = {{
    std::to_underlying(FlowTableModel::Column::Number),
    std::to_underlying(FlowTableModel::Column::SrcPort),
    std::to_underlying(FlowTableModel::Column::DstPort),
    std::to_underlying(FlowTableModel::Column::Confidence),
    std::to_underlying(FlowTableModel::Column::CombinedScore),
}};

/// Per-column display formatter.  Signature: (row index, FlowRow) -> QVariant.
using FlowRow = FlowTableModel::FlowRow;
using DisplayFn = QVariant (*)(int, const FlowRow &);

QVariant fmtNumber(int row, const FlowRow & /*r*/) { return row + 1; }
QVariant fmtSrcIp(int /*row*/, const FlowRow &r) {
  return QString::fromStdString(r.metadata.srcIp);
}
QVariant fmtSrcPort(int /*row*/, const FlowRow &r) {
  return r.metadata.srcPort;
}
QVariant fmtDstIp(int /*row*/, const FlowRow &r) {
  return QString::fromStdString(r.metadata.dstIp);
}
QVariant fmtDstPort(int /*row*/, const FlowRow &r) {
  return r.metadata.dstPort;
}

QVariant fmtProtocol(int /*row*/, const FlowRow &r) {
  return protocolQString(r.metadata.protocol);
}
QVariant fmtVerdict(int /*row*/, const FlowRow &r) {
  return attackTypeQString(r.result.finalVerdict);
}
QVariant fmtConfidence(int /*row*/, const FlowRow &r) {
  return QString::number(static_cast<double>(r.result.mlResult.confidence) *
                             100.0,
                         'f', 1) +
         "%";
}
QVariant fmtCombinedScore(int /*row*/, const FlowRow &r) {
  return QString::number(static_cast<double>(r.result.combinedScore), 'f', 3);
}
QVariant fmtSource(int /*row*/, const FlowRow &r) {
  return detectionSourceQString(r.result.detectionSource);
}

/// Table of formatters indexed by Column enum.
constexpr std::array<DisplayFn, FlowTableModel::kColumnCount>
    kDisplayFormatters = {{
        fmtNumber,
        fmtSrcIp,
        fmtSrcPort,
        fmtDstIp,
        fmtDstPort,
        fmtProtocol,
        fmtVerdict,
        fmtConfidence,
        fmtCombinedScore,
        fmtSource,
    }};
} // namespace

FlowTableModel::FlowTableModel(QObject *parent) : QAbstractTableModel(parent) {}

int FlowTableModel::rowCount(const QModelIndex &parent) const {
  if (parent.isValid())
    return 0;
  return static_cast<int>(rows_.size());
}

int FlowTableModel::columnCount(const QModelIndex &parent) const {
  if (parent.isValid())
    return 0;
  return kColumnCount;
}

QVariant FlowTableModel::displayData(const QModelIndex &index,
                                     const FlowRow &row) {
  const auto col = static_cast<std::size_t>(index.column());
  if (col >= kDisplayFormatters.size())
    return {};
  return kDisplayFormatters[col](index.row(), row);
}

QVariant FlowTableModel::alignmentData(int column) {
  bool rightAligned = std::ranges::find(kRightAlignedColumns, column) !=
                      kRightAlignedColumns.end();
  return static_cast<int>(rightAligned ? (Qt::AlignRight | Qt::AlignVCenter)
                                       : (Qt::AlignLeft | Qt::AlignVCenter));
}

QVariant FlowTableModel::data(const QModelIndex &index, int role) const {
  if (!index.isValid())
    return {};
  if (index.row() < 0 || index.row() >= static_cast<int>(rows_.size()))
    return {};

  const auto &row = rows_[static_cast<std::size_t>(index.row())];

  if (role == Qt::DisplayRole) {
    return displayData(index, row);
  }
  if (role == Qt::BackgroundRole) {
    return severityColor(row.result.combinedScore, row.result.isFlagged());
  }
  if (role == Qt::TextAlignmentRole) {
    return alignmentData(index.column());
  }
  return {};
}

QVariant FlowTableModel::headerData(int section, Qt::Orientation orientation,
                                    int role) const {
  if (role != Qt::DisplayRole || orientation != Qt::Horizontal)
    return {};
  if (section < 0 || section >= kColumnCount)
    return {};
  return kFlowColumnHeaders[static_cast<std::size_t>(section)];
}

void FlowTableModel::setFlowResults(
    const std::vector<core::DetectionResult> &results,
    const std::vector<core::FlowInfo> &metadata) {

  beginResetModel();
  rows_.clear();
  rows_.reserve(results.size());

  for (std::size_t i = 0; i < results.size(); ++i) {
    FlowRow row;
    row.result = results[i];
    row.metadata = (i < metadata.size()) ? metadata[i] : core::FlowInfo{};
    rows_.push_back(std::move(row));
  }
  endResetModel();
}

void FlowTableModel::addFlowResult(const core::DetectionResult &result,
                                   const core::FlowInfo &metadata) {
  auto row = static_cast<int>(rows_.size());
  beginInsertRows(QModelIndex(), row, row);
  rows_.emplace_back(result, metadata);
  endInsertRows();
}

void FlowTableModel::clear() {
  if (rows_.empty())
    return;
  beginResetModel();
  rows_.clear();
  endResetModel();
}

const core::DetectionResult *FlowTableModel::resultAt(int row) const {
  if (row < 0 || row >= static_cast<int>(rows_.size()))
    return nullptr;
  return &rows_[static_cast<std::size_t>(row)].result;
}

const core::FlowInfo *FlowTableModel::metadataAt(int row) const {
  if (row < 0 || row >= static_cast<int>(rows_.size()))
    return nullptr;
  return &rows_[static_cast<std::size_t>(row)].metadata;
}

QColor FlowTableModel::severityColor(float combinedScore,
                                     bool isFlagged) noexcept {
  if (!isFlagged && combinedScore < kLowRiskThreshold) {
    // Benign — green
    return {76, 175, 80, kAlphaBackground};
  }
  if (combinedScore < kLowRiskThreshold) {
    // Flagged but low score — light yellow
    return {255, 235, 59, kAlphaBackground};
  }
  if (combinedScore < kMediumRiskThreshold) {
    // Medium risk — orange
    return {255, 152, 0, kAlphaBackground};
  }
  // High risk — red
  return {244, 67, 54, kAlphaBackground};
}

} // namespace nids::ui
