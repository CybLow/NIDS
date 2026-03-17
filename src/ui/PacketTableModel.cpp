#include "ui/PacketTableModel.h"
#include "ui/QtStringConversions.h"

#include <array>

namespace nids::ui {

namespace {

/// Column headers in enum order.
constexpr std::array<const char *, PacketTableModel::kColumnCount>
    kPacketColumnHeaders = {{
        "Number",
        "Network Card",
        "Protocol",
        "Application",
        "IP Source",
        "Port Source",
        "IP Destination",
        "Port Destination",
    }};

} // namespace

PacketTableModel::PacketTableModel(const core::ServiceRegistry *registry,
                                   QObject *parent)
    : QAbstractTableModel(parent), serviceRegistry_(registry) {}

int PacketTableModel::rowCount(const QModelIndex &parent) const {
  if (parent.isValid())
    return 0;
  return static_cast<int>(rows_.size());
}

int PacketTableModel::columnCount(const QModelIndex &parent) const {
  if (parent.isValid())
    return 0;
  return kColumnCount;
}

QVariant PacketTableModel::data(const QModelIndex &index, int role) const {
  if (!index.isValid() || role != Qt::DisplayRole)
    return {};
  if (index.row() < 0 || index.row() >= static_cast<int>(rows_.size()))
    return {};

  const auto &row = rows_[static_cast<std::size_t>(index.row())];
  return displayData(index, row);
}

QVariant PacketTableModel::displayData(const QModelIndex &index,
                                       const Row &row) const {
  const auto &pkt = row.packet;

  using enum Column;
  switch (static_cast<Column>(index.column())) {
  case Number:
    return index.row() + 1;
  case Interface:
    return QString::fromStdString(row.interfaceName);
  case Protocol:
    return protocolQString(pkt.protocol);
  case Application:
    // Resolve application from ServiceRegistry at display time.
    // Application resolution is a UI/display concern (service name from
    // well-known port), not part of the capture layer.
    if (serviceRegistry_) {
      return QString::fromStdString(
          serviceRegistry_->resolveApplication(0, 0, pkt.portDestination));
    }
    return QStringLiteral("Unknown");
  case IpSource:
    return QString::fromStdString(pkt.ipSource);
  case PortSource:
    return pkt.portSource != 0 ? QString::number(pkt.portSource)
                               : QStringLiteral("-");
  case IpDestination:
    return QString::fromStdString(pkt.ipDestination);
  case PortDestination:
    return pkt.portDestination != 0 ? QString::number(pkt.portDestination)
                                    : QStringLiteral("-");
  case ColumnCount:
    return {};
  }
  return {};
}

QVariant PacketTableModel::headerData(int section, Qt::Orientation orientation,
                                      int role) const {
  if (role != Qt::DisplayRole || orientation != Qt::Horizontal)
    return {};
  if (section < 0 || section >= kColumnCount)
    return {};
  return kPacketColumnHeaders[static_cast<std::size_t>(section)];
}

void PacketTableModel::addPacket(const core::PacketInfo &info,
                                 const std::string &interfaceName) {
  auto row = static_cast<int>(rows_.size());
  beginInsertRows(QModelIndex(), row, row);
  rows_.emplace_back(info, interfaceName);
  endInsertRows();
}

void PacketTableModel::clear() {
  if (rows_.empty())
    return;
  beginResetModel();
  rows_.clear();
  endResetModel();
}

const core::PacketInfo *PacketTableModel::packetAt(int row) const {
  if (row < 0 || row >= static_cast<int>(rows_.size()))
    return nullptr;
  return &rows_[static_cast<std::size_t>(row)].packet;
}

} // namespace nids::ui
