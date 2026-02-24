#pragma once

#include "core/model/PacketInfo.h"

#include <QAbstractTableModel>

#include <vector>
#include <string>

namespace nids::ui {

class PacketTableModel : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column {
        Number = 0,
        Interface,
        Protocol,
        Application,
        IpSource,
        PortSource,
        IpDestination,
        PortDestination,
        ColumnCount
    };

    explicit PacketTableModel(QObject* parent = nullptr);

    [[nodiscard]] int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    [[nodiscard]] int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QVariant headerData(int section, Qt::Orientation orientation,
                                      int role = Qt::DisplayRole) const override;

    void addPacket(const nids::core::PacketInfo& info, const std::string& interfaceName);
    void clear();

    [[nodiscard]] const nids::core::PacketInfo* packetAt(int row) const;

private:
    struct Row {
        nids::core::PacketInfo packet;
        std::string interfaceName;
    };
    std::vector<Row> rows_;
};

} // namespace nids::ui
