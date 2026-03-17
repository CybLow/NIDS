#include "ui/HexView.h"

#include <QFont>

namespace nids::ui {

namespace {
constexpr int kBytesPerRow = 16;
constexpr int kFontSize = 10;
constexpr int kOffsetWidth = 4;      ///< Hex digits for the offset column.
constexpr int kHexFieldWidth = 2;    ///< Hex digits per byte.
constexpr unsigned char kPrintableMin = 32;
constexpr unsigned char kPrintableMax = 127;
} // namespace

HexView::HexView(QWidget *parent) : QTextEdit(parent) {
  setReadOnly(true);
  setWordWrapMode(QTextOption::NoWrap);
  setFont(QFont("Courier", kFontSize));
}

void HexView::setData(const QByteArray &bytes) {
  QString display;
  QString hexPart;
  QString asciiPart;
  QString offset;

  for (int i = 0; i < bytes.size(); ++i) {
    if (i % kBytesPerRow == 0) {
      if (i != 0) {
        display += offset + " " +
                   hexPart.leftJustified(kBytesPerRow * 3, ' ') + "    " +
                   asciiPart + "\n";
      }
      offset = QString("%1").arg(i, kOffsetWidth, 16, QLatin1Char('0')).toUpper();
      hexPart.clear();
      asciiPart.clear();
    }

    auto byte = static_cast<unsigned char>(bytes[i]);
    hexPart += QString("%1 ").arg(byte, kHexFieldWidth, 16, QLatin1Char('0')).toUpper();
    asciiPart += (byte >= kPrintableMin && byte < kPrintableMax)
                     ? QChar(byte)
                     : QChar('.');
  }

  if (!hexPart.isEmpty()) {
    display += offset + " " +
               hexPart.leftJustified(kBytesPerRow * 3, ' ') + "    " +
               asciiPart;
  }

  setPlainText(display.trimmed());
  setMinimumHeight(static_cast<int>(document()->size().height()));
}

void HexView::clearData() { clear(); }

} // namespace nids::ui
