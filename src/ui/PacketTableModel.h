#pragma once

#include "core/model/PacketInfo.h"

#include <QAbstractTableModel>

#include <string>
#include <utility>
#include <vector>

namespace nids::ui {

/** Table model for displaying captured packets in a QTableView. */
class PacketTableModel : public QAbstractTableModel {
  Q_OBJECT

public:
  /** Column indices for the packet table. */
  enum class Column {
    Number = 0,      /**< Packet sequence number. */
    Interface,       /**< Network interface that captured the packet. */
    Protocol,        /**< Transport protocol (TCP, UDP, ICMP, etc.). */
    Application,     /**< Application-layer protocol or service name. */
    IpSource,        /**< Source IP address. */
    PortSource,      /**< Source port number. */
    IpDestination,   /**< Destination IP address. */
    PortDestination, /**< Destination port number. */
    ColumnCount      /**< Sentinel value: total number of columns. */
  };

  /// Total number of columns (integral constant for use in array sizes).
  static constexpr int kColumnCount = std::to_underlying(Column::ColumnCount);

  /** Construct an empty packet table model. */
  explicit PacketTableModel(QObject *parent = nullptr);

  [[nodiscard]] int
  rowCount(const QModelIndex &parent = QModelIndex()) const override;
  [[nodiscard]] int
  columnCount(const QModelIndex &parent = QModelIndex()) const override;
  [[nodiscard]] QVariant data(const QModelIndex &index,
                              int role = Qt::DisplayRole) const override;
  [[nodiscard]] QVariant headerData(int section, Qt::Orientation orientation,
                                    int role = Qt::DisplayRole) const override;

  /** Append a captured packet to the model and notify the view. */
  void addPacket(const nids::core::PacketInfo &info,
                 const std::string &interfaceName);
  /** Remove all rows from the model. */
  void clear();

  /** Retrieve the packet at the given row, or nullptr if out of range. */
  [[nodiscard]] const nids::core::PacketInfo *packetAt(int row) const;

private:
  struct Row {
    nids::core::PacketInfo packet;
    std::string interfaceName;
  };

  /// Return display data for a single cell.
  [[nodiscard]] static QVariant displayData(const QModelIndex &index,
                                            const Row &row);

  std::vector<Row> rows_;
};

} // namespace nids::ui
