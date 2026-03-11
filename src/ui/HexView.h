#pragma once

#include <QTextEdit>
#include <QByteArray>

namespace nids::ui {

/** Read-only text widget that displays binary data in hex dump format. */
class HexView : public QTextEdit {
    Q_OBJECT

public:
    /** Construct an empty hex view. */
    explicit HexView(QWidget* parent = nullptr);

    /** Format and display the given binary data as a hex dump. */
    void setData(const QByteArray& data);
    /** Clear the hex dump display. */
    void clearData();
};

} // namespace nids::ui
