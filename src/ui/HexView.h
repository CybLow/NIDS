#pragma once

#include <QByteArray>
#include <QTextEdit>

namespace nids::ui {

/** Read-only text widget that displays binary data in hex dump format. */
class HexView : public QTextEdit {
  Q_OBJECT

public:
  /** Construct an empty hex view. */
  explicit HexView(QWidget *parent = nullptr);

  /** Format and display the given binary data as a hex dump. */
  void setData(const QByteArray &bytes);
  /** Clear the hex dump display. */
  void clearData();
};

} // namespace nids::ui
