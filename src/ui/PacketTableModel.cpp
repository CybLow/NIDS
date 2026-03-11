#include "ui/PacketTableModel.h"

#include <array>

namespace nids::ui {

namespace {

/// Column headers in enum order.
constexpr std::array<const char*, PacketTableModel::ColumnCount> kPacketColumnHeaders = {{
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

PacketTableModel::PacketTableModel(QObject* parent)
    : QAbstractTableModel(parent) {}

int PacketTableModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid())
        return 0;
    return static_cast<int>(rows_.size());
}

int PacketTableModel::columnCount(const QModelIndex& parent) const {
    if (parent.isValid())
        return 0;
    return ColumnCount;
}

QVariant PacketTableModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || role != Qt::DisplayRole)
        return {};
    if (index.row() < 0 || index.row() >= static_cast<int>(rows_.size()))
        return {};

    const auto& row = rows_[static_cast<std::size_t>(index.row())];
    return displayData(index, row);
}

QVariant PacketTableModel::displayData(const QModelIndex& index,
                                        const Row& row) {
    const auto& pkt = row.packet;

    switch (index.column()) {
        case Number:          return index.row() + 1;
        case Interface:       return QString::fromStdString(row.interfaceName);
        case Protocol:        return QString::fromStdString(pkt.protocol);
        case Application:     return QString::fromStdString(pkt.application);
        case IpSource:        return QString::fromStdString(pkt.ipSource);
        case PortSource:      return QString::fromStdString(pkt.portSource);
        case IpDestination:   return QString::fromStdString(pkt.ipDestination);
        case PortDestination: return QString::fromStdString(pkt.portDestination);
        default: return {};
    }
}

QVariant PacketTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal)
        return {};
    if (section < 0 || section >= ColumnCount)
        return {};
    return kPacketColumnHeaders[static_cast<std::size_t>(section)];
}

void PacketTableModel::addPacket(const nids::core::PacketInfo& info,
                                  const std::string& interfaceName) {
    int row = static_cast<int>(rows_.size());
    beginInsertRows(QModelIndex(), row, row);
    rows_.push_back({info, interfaceName});
    endInsertRows();
}

void PacketTableModel::clear() {
    if (rows_.empty())
        return;
    beginResetModel();
    rows_.clear();
    endResetModel();
}

const nids::core::PacketInfo* PacketTableModel::packetAt(int row) const {
    if (row < 0 || row >= static_cast<int>(rows_.size()))
        return nullptr;
    return &rows_[static_cast<std::size_t>(row)].packet;
}

} // namespace nids::ui
