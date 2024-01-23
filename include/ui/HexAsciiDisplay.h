#ifndef HEXASCIIDISPLAY_H
#define HEXASCIIDISPLAY_H

#include <QWidget>
#include <QTextEdit>
#include <vector>

using namespace std;

class HexAsciiDisplay : public QTextEdit {
Q_OBJECT

public:
    explicit HexAsciiDisplay(QWidget *parent = nullptr);

    // Method to set data
    void setData(const QByteArray &data);
};

#endif // HEXASCIIDISPLAY_H
