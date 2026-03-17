#pragma once

/**
 * Table model for displaying flow-level hybrid detection results.
 *
 * Each row represents a network flow with its detection verdict, confidence,
 * combined score, detection source, and connection metadata (IPs, ports).
 * Rows are color-coded by severity: green (benign), yellow (low risk),
 * orange (medium risk), red (high risk).
 */

#include "core/model/DetectionResult.h"
#include "core/model/FlowInfo.h"

#include <QAbstractTableModel>
#include <QColor>

#include <array>
#include <utility>
#include <vector>

namespace nids::ui {

/** Table model for displaying flow-level hybrid detection results. */
class FlowTableModel : public QAbstractTableModel {
  Q_OBJECT

public:
  /** Column indices for the flow table. */
  enum class Column {
    Number = 0,    /**< Flow sequence number. */
    SrcIp,         /**< Source IP address. */
    SrcPort,       /**< Source port number. */
    DstIp,         /**< Destination IP address. */
    DstPort,       /**< Destination port number. */
    Protocol,      /**< Transport protocol. */
    Verdict,       /**< Detection verdict (attack type). */
    Confidence,    /**< ML confidence score. */
    CombinedScore, /**< Hybrid combined threat score. */
    Source,        /**< Detection source (ML, TI, Heuristic, or combination). */
    ColumnCount    /**< Sentinel value: total number of columns. */
  };

  /// Total number of columns (integral constant for use in array sizes).
  static constexpr int kColumnCount = std::to_underlying(Column::ColumnCount);

  /// Per-flow data: detection result + connection metadata.
  struct FlowRow {
    /** Hybrid detection result for this flow. */
    core::DetectionResult result;
    /** Connection metadata (IPs, ports, protocol, packet counts). */
    core::FlowInfo metadata;
  };

  /** Construct an empty flow table model. */
  explicit FlowTableModel(QObject *parent = nullptr);

  [[nodiscard]] int
  rowCount(const QModelIndex &parent = QModelIndex()) const override;
  [[nodiscard]] int
  columnCount(const QModelIndex &parent = QModelIndex()) const override;
  [[nodiscard]] QVariant data(const QModelIndex &index,
                              int role = Qt::DisplayRole) const override;
  [[nodiscard]] QVariant headerData(int section, Qt::Orientation orientation,
                                    int role = Qt::DisplayRole) const override;

  /// Populate the model with flow results from a completed analysis.
  void setFlowResults(const std::vector<core::DetectionResult> &results,
                      const std::vector<core::FlowInfo> &metadata);

  /// Add a single flow result (for incremental updates during live analysis).
  void addFlowResult(const core::DetectionResult &result,
                     const core::FlowInfo &metadata);

  /** Remove all rows from the model. */
  void clear();

  /// Retrieve the detection result for a specific row.
  [[nodiscard]] const core::DetectionResult *resultAt(int row) const;

  /// Retrieve the flow metadata for a specific row.
  [[nodiscard]] const core::FlowInfo *metadataAt(int row) const;

private:
  /// Return display data for a single cell (delegates to kDisplayFormatters
  /// table).
  [[nodiscard]] static QVariant displayData(const QModelIndex &index,
                                            const FlowRow &row);

  /// Return alignment data for a column.
  [[nodiscard]] static QVariant alignmentData(int column);

  /// Map combined score to a background color for severity indication.
  [[nodiscard]] static QColor severityColor(float combinedScore,
                                            bool isFlagged) noexcept;

  std::vector<FlowRow> rows_;
};

} // namespace nids::ui
