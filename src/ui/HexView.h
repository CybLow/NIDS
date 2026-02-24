#pragma once

#include <QTextEdit>
#include <QByteArray>

namespace nids::ui {

class HexView : public QTextEdit {
    Q_OBJECT

public:
    explicit HexView(QWidget* parent = nullptr);

    void setData(const QByteArray& data);
    void clearData();
};

} // namespace nids::ui
