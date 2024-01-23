#include "include/ui/HexAsciiDisplay.h"

#include <QVBoxLayout>
#include <QDebug>

HexAsciiDisplay::HexAsciiDisplay(QWidget *parent) : QTextEdit(parent) {
    this->setReadOnly(true);
    this->setWordWrapMode(QTextOption::NoWrap);  // Disable word wrapping

}

void HexAsciiDisplay::setData(const QByteArray& data) {
    QFont font("Courier");  // Using a monospaced font
    this->setFont(font);

    QString displayString;
    QString hexString;
    QString asciiString;
    QString offsetString;

    for (int i = 0; i < data.size(); ++i) {
        if (i % 16 == 0) {
            if (i != 0) {
                // Append completed lines with offset
                displayString += offsetString + " " + hexString.leftJustified(16 * 3, ' ') + "    " + asciiString + "\n";
            }
            // Calculate the new offset string for the next line
            offsetString = QString("%1").arg(i, 4, 16, QLatin1Char('0')).toUpper();
            hexString.clear();
            asciiString.clear();
        }

        unsigned char byte = static_cast<unsigned char>(data[i]);
        hexString += QString("%1 ").arg(byte, 2, 16, QLatin1Char('0')).toUpper();
        asciiString += (byte >= 32 && byte < 127) ? QChar(byte) : '.';
    }

    // Append the last line if it's not complete
    if (!hexString.isEmpty()) {
        displayString += offsetString + " " + hexString.leftJustified(16 * 3, ' ') + "    " + asciiString;
    }

    this->setPlainText(displayString.trimmed());  // Remove any trailing whitespace
    // Suggest a minimum size based on content
    this->setMinimumHeight(this->document()->size().height());
}

#include "include/ui/HexAsciiDisplay.moc" // Include if using Q_OBJECT macro in class
