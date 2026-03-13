#include "ui/PacketTableModel.h"

#include <array>

namespace nids::ui {

namespace {

/// Column headers in enum order.
constexpr std::array<const char*, PacketTableModel::kColumnCount> kPacketColumnHeaders = {{
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
    return kColumnCount;
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

    switch (static_cast<Column>(index.column())) {
        case Column::Number:          return index.row() + 1;
        case Column::Interface:       return QString::fromStdString(row.interfaceName);
        case Column::Protocol:        return QString::fromStdString(pkt.protocol);
        case Column::Application:     return QString::fromStdString(pkt.application);
        case Column::IpSource:        return QString::fromStdString(pkt.ipSource);
        case Column::PortSource:      return QString::fromStdString(pkt.portSource);
        case Column::IpDestination:   return QString::fromStdString(pkt.ipDestination);
        case Column::PortDestination: return QString::fromStdString(pkt.portDestination);
        case Column::ColumnCount:     return {};
    }
    return {};
}

QVariant PacketTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal)
        return {};
    if (section < 0 || section >= kColumnCount)
        return {};
    return kPacketColumnHeaders[static_cast<std::size_t>(section)];
}

void PacketTableModel::addPacket(const nids::core::PacketInfo& info,
                                  const std::string& interfaceName) {
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

const nids::core::PacketInfo* PacketTableModel::packetAt(int row) const {
    if (row < 0 || row >= static_cast<int>(rows_.size()))
        return nullptr;
    return &rows_[static_cast<std::size_t>(row)].packet;
}

} // namespace nids::ui
