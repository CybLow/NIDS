#include "ui/PacketTableModel.h"

namespace nids::ui {

PacketTableModel::PacketTableModel(QObject* parent)
    : QAbstractTableModel(parent) {}

int PacketTableModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) return 0;
    return static_cast<int>(rows_.size());
}

int PacketTableModel::columnCount(const QModelIndex& parent) const {
    if (parent.isValid()) return 0;
    return ColumnCount;
}

QVariant PacketTableModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || role != Qt::DisplayRole) return {};
    if (index.row() < 0 || index.row() >= static_cast<int>(rows_.size())) return {};

    const auto& row = rows_[static_cast<std::size_t>(index.row())];
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
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal) return {};

    switch (section) {
        case Number:          return "Number";
        case Interface:       return "Network Card";
        case Protocol:        return "Protocol";
        case Application:     return "Application";
        case IpSource:        return "IP Source";
        case PortSource:      return "Port Source";
        case IpDestination:   return "IP Destination";
        case PortDestination: return "Port Destination";
        default: return {};
    }
}

void PacketTableModel::addPacket(const nids::core::PacketInfo& info,
                                  const std::string& interfaceName) {
    int row = static_cast<int>(rows_.size());
    beginInsertRows(QModelIndex(), row, row);
    rows_.push_back({info, interfaceName});
    endInsertRows();
}

void PacketTableModel::clear() {
    if (rows_.empty()) return;
    beginResetModel();
    rows_.clear();
    endResetModel();
}

const nids::core::PacketInfo* PacketTableModel::packetAt(int row) const {
    if (row < 0 || row >= static_cast<int>(rows_.size())) return nullptr;
    return &rows_[static_cast<std::size_t>(row)].packet;
}

} // namespace nids::ui
