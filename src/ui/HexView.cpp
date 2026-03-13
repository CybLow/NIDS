#include "ui/HexView.h"

#include <QFont>

namespace nids::ui {

HexView::HexView(QWidget* parent)
    : QTextEdit(parent) {
    setReadOnly(true);
    setWordWrapMode(QTextOption::NoWrap);
    setFont(QFont("Courier", 10));
}

void HexView::setData(const QByteArray& data) {
    QString display;
    QString hexPart;
    QString asciiPart;
    QString offset;

    for (int i = 0; i < data.size(); ++i) {
        if (i % 16 == 0) {
            if (i != 0) {
                display += offset + " " + hexPart.leftJustified(16 * 3, ' ')
                           + "    " + asciiPart + "\n";
            }
            offset = QString("%1").arg(i, 4, 16, QLatin1Char('0')).toUpper();
            hexPart.clear();
            asciiPart.clear();
        }

        auto byte = static_cast<unsigned char>(data[i]);
        hexPart += QString("%1 ").arg(byte, 2, 16, QLatin1Char('0')).toUpper();
        asciiPart += (byte >= 32 && byte < 127) ? QChar(byte) : QChar('.');
    }

    if (!hexPart.isEmpty()) {
        display += offset + " " + hexPart.leftJustified(16 * 3, ' ')
                   + "    " + asciiPart;
    }

    setPlainText(display.trimmed());
    setMinimumHeight(static_cast<int>(document()->size().height()));
}

void HexView::clearData() {
    clear();
}

} // namespace nids::ui
